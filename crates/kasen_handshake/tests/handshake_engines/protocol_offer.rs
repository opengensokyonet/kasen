//! The application protocol a target selection hands the server engine,
//! which must be one the client offers (RFC 7301 §3.2).

use super::*;
use kasen_handshake::server::targets::SelectedTarget;

#[test]
fn a_preselected_protocol_the_client_did_not_offer_fails_with_internal_error() {
    let endpoints = Endpoints::new();
    let mut wire = Wire::new();
    let selected = SelectedTarget {
        target: "web",
        application_protocol: Some(ProtocolName::new(Bytes::from_static(b"h2")).unwrap()),
    };
    let mut server = pin!(LentCall::<ServerSide, _>::new(ServerSteps::new(
        server_handshake!(
            &endpoints,
            PassThroughLayers,
            PreselectedTarget::new(selected)
        ),
        MessageLimits::default()
    )));
    let mut client = pin!(LentCall::<ClientSide, _>::new(ClientSteps::new(
        client_handshake!(&endpoints, "example.com")
    )));
    let run = run(
        &mut wire,
        |wire| poll_server!(server, wire),
        |wire| {
            let mut side = pin!(Pin::new(&mut wire.client).view());
            client
                .as_mut()
                .poll_with_views(side.as_mut(), &mut Context::from_waker(Waker::noop()))
        },
        unchanged,
    );
    let end = run.server_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ServerAlertError::ProtocolNotOffered)
    ));
    assert_eq!(alert_of(end), AlertDescription::INTERNAL_ERROR);
}

#[test]
fn a_second_client_hello_that_withdraws_the_protocol_fails_with_internal_error() {
    let mut endpoints = Endpoints::new();
    endpoints.offering = offering(&[NamedGroup::SECP256R1]);
    endpoints.group_preference = GroupPreference::TableOrder;
    let mut hellos = 0;
    let connection = connect!(&endpoints, Wire::new(), "example.com", |from,
                                                                       _,
                                                                       bytes: &mut Vec<
        u8,
    >| {
        if from == Sender::Client
            && messages(bytes).first().map(|m| m.0) == Some(HandshakeType::CLIENT_HELLO)
        {
            hellos += 1;
            if hellos == 2 {
                // The protocol name list of h3 alone offers h4 instead.
                replace(
                    bytes,
                    &[0x00, 0x03, 0x02, b'h', b'3'],
                    &[0x00, 0x03, 0x02, b'h', b'4'],
                );
            }
        }
    });
    assert_eq!(hellos, 2);
    let end = connection.server_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ServerAlertError::ProtocolNotOffered)
    ));
    assert_eq!(alert_of(end), AlertDescription::INTERNAL_ERROR);
}
