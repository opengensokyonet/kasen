//! Collecting a handshake message from the CRYPTO bytes of a level: what a
//! header alone makes the reader accept and allocate.
//!
//! The binary counts the largest allocation of each thread, so that a test
//! sees what a read allocated before its body arrived.
#![feature(impl_trait_in_assoc_type, yield_expr)]

mod common;

use common::streams::{Incoming, Outgoing, ServerParameters, ServerSide};
use core::{
    cell::Cell,
    ops::ControlFlow,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use kasen_handshake::{
    alert::AlertDescription,
    engine::HandshakeError,
    message::{HandshakeType, MessageLimits, codec::ReadHandshakeMessageError},
    server::engine::{ReadFirstClientHello, ReadFirstClientHelloError},
};
use nitori_call::{LentCall, Receiver as _};
use std::alloc::{GlobalAlloc, Layout, System};

/// The system allocator, counting the largest allocation of each thread.
struct Largest;

thread_local! {
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    // A thread that is going away no longer counts.
    let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
}

// SAFETY: every call goes to `System` as it came.
unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract, passed on.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's contract, passed on.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller's contract, passed on.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: Largest = Largest;

/// A server's receiver with `bytes` at Initial.
fn server_side(bytes: &[u8]) -> ServerSide {
    let mut input = Incoming::default();
    input.levels[0].extend(bytes);
    ServerSide {
        input,
        output: Outgoing::default(),
        parameters: ServerParameters {
            local: bytes::Bytes::new(),
            peer: None,
            early_data: false,
            refuse: false,
        },
    }
}

type FirstClientHelloEnd = ControlFlow<
    Result<
        kasen_handshake::server::engine::FirstClientHello,
        HandshakeError<ReadFirstClientHelloError, common::streams::Fault>,
    >,
    core::convert::Infallible,
>;

/// Polls a read of the first ClientHello once on `side`; the largest
/// allocation of the poll with it.
fn poll_first_client_hello(side: &mut ServerSide) -> (Poll<FirstClientHelloEnd>, usize) {
    let mut read = pin!(LentCall::<ServerSide, _>::new(ReadFirstClientHello::new(
        MessageLimits::default()
    )));
    let mut view = pin!(Pin::new(side).view());
    LARGEST.set(0);
    let poll = read
        .as_mut()
        .poll_with_views(view.as_mut(), &mut Context::from_waker(Waker::noop()));
    (poll, LARGEST.get())
}

/// A server waiting for the first ClientHello refuses the header of a
/// Certificate at once, without waiting for its body or making room for
/// it, though the length is within the limit of a Certificate.
#[test]
fn a_header_of_another_type_fails_before_its_body() {
    let mut side = server_side(&[11, 0, 0xff, 0xff]);
    let (poll, largest) = poll_first_client_hello(&mut side);
    let Poll::Ready(ControlFlow::Break(Err(error))) = poll else {
        panic!("the read did not fail: {poll:?}")
    };
    assert!(
        matches!(
            &error,
            HandshakeError::Alert {
                source: ReadFirstClientHelloError::Message {
                    source: ReadHandshakeMessageError::Unexpected { source }
                }
            } if source.message_type() == HandshakeType::CERTIFICATE
        ),
        "{error:?}"
    );
    assert_eq!(error.alert(), Some(AlertDescription::UNEXPECTED_MESSAGE));
    assert!(largest < 4096, "{largest} bytes allocated");
}

/// The header of a ClientHello of the largest length the limit allows does
/// not make room for that length before the body arrives; the buffer grows
/// with the body.
#[test]
fn a_header_alone_does_not_allocate_its_length() {
    let mut side = server_side(&[1, 0, 0x3f, 0xff]);
    let (poll, largest) = poll_first_client_hello(&mut side);
    assert!(poll.is_pending(), "{poll:?}");
    assert!(largest <= 4096, "{largest} bytes allocated");
}
