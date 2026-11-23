//! certificate_request_context during the handshake, which the client
//! requires to be empty.

use super::*;

/// The range of the first message of `message_type` in `bytes`.
fn first(bytes: &[u8], message_type: HandshakeType) -> Option<core::ops::Range<usize>> {
    messages(bytes)
        .into_iter()
        .find_map(|(found, range)| (found == message_type).then_some(range))
}

/// A CertificateRequest with a one-byte context and signature_algorithms.
const REQUEST: [u8; 16] = [
    13, 0, 0, 12, // header
    1, 0x42, // certificate_request_context
    0, 8, 0, 13, 0, 4, 0, 2, 0x08, 0x07, // signature_algorithms: Ed25519
];

#[test]
fn a_certificate_request_with_a_context_fails_with_illegal_parameter() {
    let connection = connect!(
        &Endpoints::new(),
        Wire::new(),
        "example.com",
        |from, level, bytes: &mut Vec<u8>| {
            if from == Sender::Server
                && level == CryptoLevel::Handshake
                && let Some(certificate) = first(bytes, HandshakeType::CERTIFICATE)
            {
                bytes.splice(certificate.start..certificate.start, REQUEST);
            }
        }
    );
    let end = connection.client_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ClientAlertError::CertificateRequestContext)
    ));
    assert_eq!(alert_of(end), AlertDescription::ILLEGAL_PARAMETER);
}

#[test]
fn a_server_certificate_with_a_context_fails_with_illegal_parameter() {
    let connection = connect!(
        &Endpoints::new(),
        Wire::new(),
        "example.com",
        |from, level, bytes: &mut Vec<u8>| {
            if from == Sender::Server
                && level == CryptoLevel::Handshake
                && let Some(certificate) = first(bytes, HandshakeType::CERTIFICATE)
            {
                // A one-byte context instead of the empty one; the body
                // grows by the byte.
                let at = certificate.start;
                assert_eq!(bytes[at + 4], 0);
                let len = u32::from_be_bytes([0, bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
                bytes[at + 1..at + 4].copy_from_slice(&(len + 1).to_be_bytes()[1..]);
                bytes[at + 4] = 1;
                bytes.insert(at + 5, 0x42);
            }
        }
    );
    let end = connection.client_end;
    assert!(matches!(
        end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
        Some(ClientAlertError::CertificateContext)
    ));
    assert_eq!(alert_of(end), AlertDescription::ILLEGAL_PARAMETER);
}

/// A CertificateRequest with an empty context, server_name and
/// signature_algorithms.
const REQUEST_WITH_NAME: [u8; 25] = [
    13, 0, 0, 21, // header
    0,  // certificate_request_context
    0, 18, // extensions
    0, 0, 0, 6, 0, 4, 0, 0, 1, b'a', // server_name: "a"
    0, 13, 0, 4, 0, 2, 0x08, 0x07, // signature_algorithms: Ed25519
];

#[test]
fn a_certificate_request_may_carry_server_name() {
    // RFC 9846 Table 1 lists server_name for a CertificateRequest. The
    // inserted message changes the transcript, so the client goes on past
    // the request and fails on the server's CertificateVerify instead.
    let connection = connect!(
        &Endpoints::new(),
        Wire::new(),
        "example.com",
        |from, level, bytes: &mut Vec<u8>| {
            if from == Sender::Server
                && level == CryptoLevel::Handshake
                && let Some(certificate) = first(bytes, HandshakeType::CERTIFICATE)
            {
                bytes.splice(certificate.start..certificate.start, REQUEST_WITH_NAME);
            }
        }
    );
    assert_eq!(
        alert_of(connection.client_end),
        AlertDescription::DECRYPT_ERROR
    );
}
