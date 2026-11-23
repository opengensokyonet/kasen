//! 0-RTT across a HelloRetryRequest, against a server that claims to accept
//! it anyway.

use super::*;
use kasen_handshake::{
    client::engine::UnsolicitedExtension,
    key_log::{KeyLog, KeyLogLabel},
};
use nitori_crypto::{Hkdf as _, Hmac as _, RunningHash as _, Secret};

/// The server's handshake traffic secret, as its key log receives it.
#[derive(Default)]
struct ServerHandshakeSecret(Mutex<Option<Vec<u8>>>);

impl KeyLog for ServerHandshakeSecret {
    fn log(&self, label: KeyLogLabel, _client_random: &HelloRandom, secret: &[u8]) {
        if label == KeyLogLabel::ServerHandshakeTrafficSecret {
            *self.0.lock().unwrap() = Some(secret.to_vec());
        }
    }
}

/// The SHA-256 of `parts`, concatenated.
fn sha256(parts: &[&[u8]]) -> Vec<u8> {
    let mut running = nitori_crypto::Hash::start(&AwsLcBackend, sha256_algorithm());
    for part in parts {
        running.update(part);
    }
    running.finish().as_bytes().to_vec()
}

fn sha256_algorithm() -> nitori_crypto::Supported<AwsLcBackend, HashAlgorithm> {
    nitori_crypto::Hash::hash_algorithm(&AwsLcBackend, HashAlgorithm::Sha256).unwrap()
}

/// The verify_data of a Finished under the traffic secret `base` over a
/// transcript whose hash is `transcript_hash` (RFC 8446 §4.4.4).
fn verify_data(base: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let label: &[u8] = b"tls13 finished";
    let key = AwsLcBackend.expand(
        sha256_algorithm(),
        &Secret::new(base).unwrap(),
        &[&32u16.to_be_bytes(), &[label.len() as u8], label, &[0]],
        ExpandLength::new(32).unwrap(),
    );
    AwsLcBackend
        .sign(sha256_algorithm(), key.as_bytes(), transcript_hash)
        .as_bytes()
        .to_vec()
}

/// Appends an empty `early_data` extension to the EncryptedExtensions in
/// `bytes`, and recomputes the server's Finished after it over `before`,
/// the transcript up to it. The CertificateVerify keeps its old signature:
/// a fixed client fails at the EncryptedExtensions before it reads it, and
/// an unfixed one fails there instead.
fn add_early_data(bytes: &mut Vec<u8>, before: &[Vec<u8>], secret: &[u8]) {
    let found = messages(bytes);
    let mut changed = Vec::new();
    let mut transcript: Vec<u8> = Vec::new();
    // The transcript starts with the message_hash of the first ClientHello
    // (RFC 8446 §4.4.1).
    let first = sha256(&[&before[0]]);
    transcript.extend([254, 0, 0, first.len() as u8]);
    transcript.extend(&first);
    for message in &before[1..] {
        transcript.extend(message);
    }
    for (message_type, range) in found {
        let mut message = bytes[range].to_vec();
        if message_type == HandshakeType::ENCRYPTED_EXTENSIONS {
            message.extend([0, 42, 0, 0]);
            let len = u32::from_be_bytes([0, message[1], message[2], message[3]]) + 4;
            message[1..4].copy_from_slice(&len.to_be_bytes()[1..]);
            let block = u16::from_be_bytes([message[4], message[5]]) + 4;
            message[4..6].copy_from_slice(&block.to_be_bytes());
        } else if message_type == HandshakeType::FINISHED {
            let data = verify_data(secret, &sha256(&[&transcript]));
            message.truncate(4);
            message.extend(data);
        }
        transcript.extend(&message);
        changed.extend(message);
    }
    *bytes = changed;
}

/// A server that sent a HelloRetryRequest and still puts `early_data` in
/// its EncryptedExtensions answers a ClientHello that did not offer it: the
/// client fails with unsupported_extension, instead of taking the 0-RTT it
/// sent before the retry as accepted.
#[test]
fn early_data_accepted_after_a_retry_fails_with_unsupported_extension() {
    let mut endpoints = Endpoints::new();
    connect!(&endpoints, Wire::new(), "example.com", unchanged);
    // The server now wants a group the client does not share.
    endpoints.server_groups = vec![NamedGroup::SECP256R1, NamedGroup::X25519];
    endpoints.group_preference = GroupPreference::TableOrder;

    let secret = Arc::new(ServerHandshakeSecret::default());
    let identity = CertifiedKey::new(vec![Bytes::from(pki::leaf())], pki::key(2)).unwrap();
    let server = ServerHandshake::new(
        AwsLcBackend,
        PreferenceTable::new(
            vec![CipherSuite::TLS_AES_128_GCM_SHA256],
            endpoints.server_groups.clone(),
            endpoints.group_preference,
        ),
        endpoints.server_tickets.clone(),
        PassThroughLayers,
        sni_targets(&endpoints),
        identity,
        NoCertificateRequest,
        Arc::clone(&endpoints.clock),
        Arc::clone(&secret),
        ServerHandshakeSettings::default(),
    );
    let client = client_handshake!(&endpoints, "example.com");
    let mut server = pin!(LentCall::<ServerSide, _>::new(ServerSteps::new(
        server,
        MessageLimits::default()
    )));
    let mut client = pin!(LentCall::<ClientSide, _>::new(ClientSteps::new(client)));
    let mut wire = Wire::new();
    // The Initial messages, in order: ClientHello, HelloRetryRequest,
    // ClientHello, ServerHello.
    let mut initial: Vec<Vec<u8>> = Vec::new();
    let run = run(
        &mut wire,
        |wire| poll_server!(server, wire),
        |wire| {
            let mut side = pin!(Pin::new(&mut wire.client).view());
            client
                .as_mut()
                .poll_with_views(side.as_mut(), &mut Context::from_waker(Waker::noop()))
        },
        |from, level, bytes: &mut Vec<u8>| match (from, level) {
            (_, CryptoLevel::Initial) => {
                for (_, range) in messages(bytes) {
                    initial.push(bytes[range].to_vec());
                }
            }
            (Sender::Server, CryptoLevel::Handshake) => {
                let secret = secret
                    .0
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("a handshake secret");
                add_early_data(bytes, &initial, &secret);
            }
            _ => {}
        },
    );
    assert_eq!(initial.len(), 4, "a retry took place");
    assert!(matches!(
        run.client_events.first(),
        Some(ClientEvent::EarlyDataOffered(_))
    ));
    let end = run.client_end;
    assert!(
        matches!(
            end.as_ref().and_then(|end| end.as_ref().err()?.failure()),
            Some(ClientAlertError::Unsolicited {
                extension: UnsolicitedExtension::EarlyData
            })
        ),
        "{end:?}"
    );
    assert_eq!(alert_of(end), AlertDescription::UNSUPPORTED_EXTENSION);
}
