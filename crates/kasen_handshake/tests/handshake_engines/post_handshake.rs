//! Messages after the handshake that QUIC forbids.

use super::*;

#[test]
fn a_certificate_request_after_the_handshake_is_a_protocol_violation() {
    let connection = connect!(
        &Endpoints::new(),
        Wire::new(),
        "example.com",
        |from, level, bytes: &mut Vec<u8>| {
            if from == Sender::Server && level == CryptoLevel::OneRtt {
                // A CertificateRequest with an empty context and no extensions
                // before the tickets (RFC 9001 §4.4).
                let request = [HandshakeType::CERTIFICATE_REQUEST.get(), 0, 0, 3, 0, 0, 0];
                bytes.splice(0..0, request);
            }
        }
    );
    assert!(matches!(connection.server_end, Some(Ok(()))));
    match connection.client_end {
        Some(Err(error)) => {
            assert_eq!(
                error.protocol_violation(),
                Some(&ProtocolViolationError::PostHandshakeCertificateRequest)
            );
            assert!(error.alert().is_none());
        }
        _ => panic!("the client did not fail"),
    }
}
