use adln_networking::{
    ConnectionId, Endpoint, Event, GameId, ServerConfig,
    auth::{
        self, Credential, CredentialStore, DeviceId, Identity, Keys, Lookup, LookupError, Secret,
    },
    protocol::{ConnectionToken, Hello, Kind, Packet},
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

const GAME: GameId = GameId(u32::from_le_bytes(*b"MKDS"));
fn device() -> DeviceId {
    DeviceId::parse("device000000001").unwrap()
}
fn secret() -> Secret {
    Secret::new([42; 32])
}
fn config() -> ServerConfig {
    ServerConfig::new("127.0.0.1:0".parse().unwrap(), GAME, vec![3])
}
struct Store {
    calls: AtomicUsize,
    delay: Duration,
    denied: bool,
}
impl CredentialStore for Store {
    fn lookup(&self, device: DeviceId, _: GameId) -> Lookup {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let delay = self.delay;
        let denied = self.denied;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            if denied {
                return Err(LookupError::Denied);
            }
            Ok(Credential {
                secret: secret(),
                identity: Identity {
                    device,
                    player: "player000000001".into(),
                    account_id: "preexisting-account-id".into(),
                },
            })
        })
    }
}
fn store() -> Arc<Store> {
    Arc::new(Store {
        calls: AtomicUsize::new(0),
        delay: Duration::ZERO,
        denied: false,
    })
}
fn hello(linked: bool, nonce: u64) -> Packet {
    let hello = Hello {
        game: GAME,
        application_version: 3,
        nonce,
        required_features: 0,
    };
    Packet {
        kind: if linked { Kind::AuthHello } else { Kind::Hello },
        connection: ConnectionId(0),
        token: ConnectionToken::ZERO,
        sequence: 0,
        channel: 0,
        payload: if linked {
            auth::hello_payload(hello, &device())
        } else {
            hello.encode()
        },
    }
}
async fn receive(socket: &UdpSocket) -> Vec<u8> {
    let mut bytes = [0; 2048];
    let length = timeout(Duration::from_secs(2), socket.recv(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes[..length].to_vec()
}
// Poll the endpoint while a client is waiting for a control response that emits no event.
async fn control(endpoint: &mut Endpoint, socket: &UdpSocket) -> Vec<u8> {
    tokio::select! {
        bytes = receive(socket) => bytes,
        event = endpoint.next_event() => panic!("Unexpected event: {event:?}"),
    }
}
async fn connect(endpoint: &mut Endpoint, socket: &UdpSocket) -> (Packet, Keys, Vec<u8>) {
    socket
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    let challenge_bytes = control(endpoint, socket).await;
    assert!(auth::verify(&challenge_bytes, &secret()));
    let challenge = auth::decode(&challenge_bytes).unwrap();
    assert_eq!(challenge.kind, Kind::AuthChallenge);
    assert_eq!(challenge.payload.len(), auth::CHALLENGE_SIZE);
    let keys = Keys::derive(&secret(), &challenge).unwrap();
    let proof = Packet {
        kind: Kind::AuthProof,
        connection: challenge.connection,
        token: challenge.token,
        sequence: 0,
        channel: 0,
        payload: vec![],
    };
    let proof_bytes = auth::encode(&proof, Some(&keys.client)).unwrap();
    socket.send(&proof_bytes).await.unwrap();
    let event = timeout(Duration::from_secs(2), endpoint.next_event())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(event, Event::Connected(_)));
    let accepted = receive(socket).await;
    assert!(auth::verify(&accepted, &keys.server));
    assert_eq!(auth::decode(&accepted).unwrap().kind, Kind::AuthAccepted);
    (challenge, keys, proof_bytes)
}

#[tokio::test]
async fn linked_login_integrity_replay_downgrade_and_retry() {
    let store = store();
    let mut endpoint = Endpoint::bind_with_auth(config(), store.clone())
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint.local_addr()).await.unwrap();
    let (challenge, keys, proof) = connect(&mut endpoint, &socket).await;
    assert_eq!(
        endpoint.identity(challenge.connection).unwrap().account_id,
        "preexisting-account-id"
    );
    assert_eq!(store.calls.load(Ordering::Relaxed), 1);
    let data = Packet {
        kind: Kind::Data,
        connection: challenge.connection,
        token: challenge.token,
        sequence: 0,
        channel: 0,
        payload: b"race state".to_vec(),
    };
    let signed = auth::encode(&data, Some(&keys.client)).unwrap();
    // Tampering and an unsigned downgrade must not consume sequence 0.
    let mut corrupt = signed.clone();
    corrupt[40] ^= 1;
    socket.send(&corrupt).await.unwrap();
    socket.send(&data.encode().unwrap()).await.unwrap();
    socket.send(&signed).await.unwrap();
    let event = timeout(Duration::from_secs(2), endpoint.next_event())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(event, Event::Message { sequence: 0, .. }));
    assert_eq!(endpoint.statistics().auth_failed, 2);
    // Duplicate proof acknowledges without a second Connected; HELLO reuses the challenge.
    socket.send(&proof).await.unwrap();
    assert_eq!(
        auth::decode(&control(&mut endpoint, &socket).await)
            .unwrap()
            .kind,
        Kind::AuthAccepted
    );
    socket
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    assert_eq!(
        auth::decode(&control(&mut endpoint, &socket).await).unwrap(),
        challenge
    );
    assert_eq!(endpoint.statistics().connected, 1);
    assert_eq!(store.calls.load(Ordering::Relaxed), 1);
    socket.send(&signed).await.unwrap();
    let mut next = data.clone();
    next.sequence = 1;
    socket
        .send(&auth::encode(&next, Some(&keys.client)).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        endpoint.next_event().await.unwrap().unwrap(),
        Event::Message { sequence: 1, .. }
    ));
    assert_eq!(endpoint.statistics().replay_dropped, 1);
    endpoint.send(challenge.connection, 0, b"reply").unwrap();
    let reply = receive(&socket).await;
    assert!(auth::verify(&reply, &keys.server));
    assert!(!auth::verify(&reply, &keys.client));
}

#[tokio::test]
async fn slow_or_denied_login_does_not_block_anonymous_or_established_clients() {
    let store = Arc::new(Store {
        calls: AtomicUsize::new(0),
        delay: Duration::from_millis(300),
        denied: true,
    });
    let mut endpoint = Endpoint::bind_with_auth(config(), store).await.unwrap();
    let linked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    linked.connect(endpoint.local_addr()).await.unwrap();
    linked
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    let anonymous = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    anonymous.connect(endpoint.local_addr()).await.unwrap();
    anonymous
        .send(&hello(false, 2).encode().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        timeout(Duration::from_millis(200), endpoint.next_event())
            .await
            .unwrap()
            .unwrap(),
        Some(Event::Connected(_))
    ));
    let welcome = Packet::decode(&receive(&anonymous).await).unwrap();
    let ping = Packet {
        kind: Kind::Ping,
        connection: welcome.connection,
        token: welcome.token,
        sequence: 0,
        channel: 0,
        payload: vec![],
    };
    tokio::time::sleep(Duration::from_millis(350)).await;
    anonymous.send(&ping.encode().unwrap()).await.unwrap();
    assert_eq!(
        Packet::decode(&control(&mut endpoint, &anonymous).await)
            .unwrap()
            .kind,
        Kind::Pong
    );
    assert_eq!(endpoint.statistics().auth_failed, 1);
    assert_eq!(endpoint.connections().count(), 1);
    assert!(endpoint.identity(welcome.connection).is_none());
}

#[tokio::test]
async fn old_session_proof_cannot_log_in_to_a_new_server() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut old = Endpoint::bind_with_auth(config(), store()).await.unwrap();
    socket.connect(old.local_addr()).await.unwrap();
    let (_, _, proof) = connect(&mut old, &socket).await;
    drop(old);
    let mut endpoint = Endpoint::bind_with_auth(config(), store()).await.unwrap();
    socket.connect(endpoint.local_addr()).await.unwrap();
    socket
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    control(&mut endpoint, &socket).await;
    socket.send(&proof).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), endpoint.next_event())
            .await
            .is_err()
    );
    assert_eq!(endpoint.connections().count(), 0);
    assert_eq!(endpoint.statistics().auth_failed, 1);
}

#[test]
fn keys_bind_every_challenge_field_and_all_datagram_fields_are_authenticated() {
    let mut packet = Packet {
        kind: Kind::AuthChallenge,
        connection: ConnectionId(4),
        token: ConnectionToken::from_bytes([5; 16]),
        sequence: 0,
        channel: 0,
        payload: vec![6; auth::CHALLENGE_SIZE],
    };
    let keys = Keys::derive(&secret(), &packet).unwrap();
    // Fixed vectors independently calculated with Python's hashlib/hmac, for
    // the complete ADLN/2 wire contract rather than a round trip of this codec.
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    assert_eq!(
        hex(keys.client.as_bytes()),
        "d97a3179050ad633cd5bb5d5d2940bdfb0e520065600fe31b87fde23702c4444"
    );
    assert_eq!(
        hex(keys.server.as_bytes()),
        "1d36e5ce54b7cff382f2c93c62be2027ad73d368619902cb2f2b9d22f317f54b"
    );
    let challenge = auth::encode(&packet, Some(&secret())).unwrap();
    assert_eq!(
        hex(&challenge[challenge.len() - auth::TAG_SIZE..]),
        "2c3786ac22a4d68db54102a6ab2bd1a64a5936854d3366d0fe3fd9e0b51d13b4"
    );
    let signed = auth::encode(&packet, Some(&keys.server)).unwrap();
    for index in 0..signed.len() {
        let mut corrupted = signed.clone();
        corrupted[index] ^= 1;
        assert!(!auth::verify(&corrupted, &keys.server), "byte {index}");
    }
    packet.payload[auth::HELLO_SIZE] ^= 1;
    let other = Keys::derive(&secret(), &packet).unwrap();
    assert_ne!(keys.client.as_bytes(), other.client.as_bytes());
    assert_ne!(keys.client.as_bytes(), keys.server.as_bytes());
    assert!(DeviceId::parse("../bad/path").is_none());
    assert!(!format!("{:?}", secret()).contains("42"));
}

#[tokio::test]
async fn pending_logins_reserve_capacity_and_bad_proofs_cannot_create_players() {
    let mut config = config();
    config.max_connections = 1;
    let mut endpoint = Endpoint::bind_with_auth(config, store()).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint.local_addr()).await.unwrap();
    socket
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    let challenge = auth::decode(&control(&mut endpoint, &socket).await).unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other.connect(endpoint.local_addr()).await.unwrap();
    other
        .send(&hello(false, 2).encode().unwrap())
        .await
        .unwrap();
    let rejection = Packet::decode(&control(&mut endpoint, &other).await).unwrap();
    assert_eq!(
        adln_networking::protocol::Reject::decode(&rejection.payload)
            .unwrap()
            .code,
        adln_networking::protocol::RejectCode::Capacity
    );
    let proof = Packet {
        kind: Kind::AuthProof,
        connection: challenge.connection,
        token: challenge.token,
        sequence: 0,
        channel: 0,
        payload: vec![],
    };
    socket
        .send(&auth::encode(&proof, Some(&Secret::new([0; 32]))).unwrap())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(100), endpoint.next_event())
            .await
            .is_err()
    );
    assert_eq!(endpoint.connections().count(), 0);
    let keys = Keys::derive(&secret(), &challenge).unwrap();
    socket
        .send(&auth::encode(&proof, Some(&keys.client)).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        endpoint.next_event().await.unwrap(),
        Some(Event::Connected(_))
    ));
    assert_eq!(endpoint.connections().count(), 1);
}

#[tokio::test]
async fn linked_sessions_keep_playing_when_new_account_lookups_fail() {
    struct Switching(Arc<std::sync::atomic::AtomicBool>);
    impl CredentialStore for Switching {
        fn lookup(&self, device: DeviceId, game: GameId) -> Lookup {
            if self.0.load(Ordering::Relaxed) {
                Box::pin(async { Err(LookupError::Unavailable) })
            } else {
                store().lookup(device, game)
            }
        }
    }
    let unavailable = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut endpoint = Endpoint::bind_with_auth(config(), Arc::new(Switching(unavailable.clone())))
        .await
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint.local_addr()).await.unwrap();
    let (challenge, keys, _) = connect(&mut endpoint, &socket).await;
    unavailable.store(true, Ordering::Relaxed);
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    other.connect(endpoint.local_addr()).await.unwrap();
    other
        .send(&auth::encode(&hello(true, 2), None).unwrap())
        .await
        .unwrap();
    // Drain the failed lookup without receiving a Connected event.
    assert!(
        timeout(Duration::from_millis(100), endpoint.next_event())
            .await
            .is_err()
    );
    let data = Packet {
        kind: Kind::Data,
        connection: challenge.connection,
        token: challenge.token,
        sequence: 0,
        channel: 0,
        payload: b"still racing".to_vec(),
    };
    socket
        .send(&auth::encode(&data, Some(&keys.client)).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        endpoint.next_event().await.unwrap(),
        Some(Event::Message { .. })
    ));
    assert_eq!(endpoint.statistics().auth_backend_errors, 1);
    assert_eq!(endpoint.connections().count(), 1);
}

#[tokio::test]
async fn stalled_backends_time_out_and_release_pending_capacity() {
    let mut config = config();
    config.max_connections = 1;
    let slow = Arc::new(Store {
        calls: AtomicUsize::new(0),
        delay: Duration::from_secs(60),
        denied: false,
    });
    let mut endpoint = Endpoint::bind_with_auth(config, slow).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(endpoint.local_addr()).await.unwrap();
    socket
        .send(&auth::encode(&hello(true, 1), None).unwrap())
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_millis(3200), endpoint.next_event())
            .await
            .is_err()
    );
    assert_eq!(endpoint.statistics().auth_backend_errors, 1);
    socket
        .send(&hello(false, 2).encode().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        timeout(Duration::from_secs(1), endpoint.next_event())
            .await
            .unwrap()
            .unwrap(),
        Some(Event::Connected(_))
    ));
}
