use std::io;
use std::net::SocketAddrV4;
use std::time::Duration;

use adln_networking::protocol::{
    self, ConnectionToken, Hello, Kind, Packet, Reject, RejectCode, Welcome,
};
use adln_networking::{
    ConnectionId, DisconnectReason, Endpoint, Event, GameId, SendError, ServerConfig, Statistics,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, timeout};

enum Command {
    Send(
        ConnectionId,
        u16,
        Vec<u8>,
        oneshot::Sender<Result<(), SendError>>,
    ),
    Statistics(oneshot::Sender<Statistics>),
    Shutdown,
}

struct Service {
    address: SocketAddrV4,
    events: mpsc::Receiver<Event>,
    commands: mpsc::Sender<Command>,
    task: tokio::task::JoinHandle<io::Result<Statistics>>,
}

fn config(game: u32) -> ServerConfig {
    ServerConfig::new("127.0.0.1:0".parse().unwrap(), GameId(game), vec![1, 2])
}

impl Service {
    async fn start(config: ServerConfig) -> Self {
        let mut endpoint = Endpoint::bind(config).await.unwrap();
        let address = endpoint.local_addr();
        let (events, received) = mpsc::channel(256);
        let (commands, mut requested) = mpsc::channel(32);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = requested.recv() => match command {
                        Some(Command::Send(id, channel, bytes, response)) => { let _ = response.send(endpoint.send(id, channel, &bytes)); }
                        Some(Command::Statistics(response)) => { let _ = response.send(endpoint.statistics().clone()); }
                        Some(Command::Shutdown) | None => endpoint.shutdown(),
                    },
                    event = endpoint.next_event() => match event? {
                        Some(event) => { let _ = events.send(event).await; }
                        None => return Ok(endpoint.statistics().clone()),
                    },
                }
            }
        });
        Self {
            address,
            events: received,
            commands,
            task,
        }
    }
    async fn event(&mut self) -> Event {
        timeout(Duration::from_secs(3), self.events.recv())
            .await
            .unwrap()
            .unwrap()
    }
    async fn send(&self, id: ConnectionId, channel: u16, bytes: &[u8]) -> Result<(), SendError> {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::Send(id, channel, bytes.to_vec(), send))
            .await
            .unwrap();
        receive.await.unwrap()
    }
    async fn statistics(&self) -> Statistics {
        let (send, receive) = oneshot::channel();
        self.commands.send(Command::Statistics(send)).await.unwrap();
        receive.await.unwrap()
    }
    async fn stop(self) -> Statistics {
        self.commands.send(Command::Shutdown).await.unwrap();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }
}

async fn client() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.unwrap()
}

async fn wire(socket: &UdpSocket, server: SocketAddrV4, packet: Packet) {
    socket
        .send_to(&packet.encode().unwrap(), server)
        .await
        .unwrap();
}

async fn receive(socket: &UdpSocket, server: SocketAddrV4, kind: Kind) -> Packet {
    let mut bytes = [0; 2048];
    timeout(Duration::from_secs(3), async {
        loop {
            let (length, source) = socket.recv_from(&mut bytes).await.unwrap();
            assert_eq!(
                source,
                server.into(),
                "Replies must use the contacted endpoint"
            );
            let packet = Packet::decode(&bytes[..length]).unwrap();
            if packet.kind == kind {
                return packet;
            }
        }
    })
    .await
    .expect("Expected ADLN response")
}

fn hello(game: u32, version: u32, nonce: u64, features: u32) -> Packet {
    Packet {
        kind: Kind::Hello,
        connection: ConnectionId(0),
        token: ConnectionToken::ZERO,
        sequence: 0,
        channel: 0,
        payload: Hello {
            game: GameId(game),
            application_version: version,
            nonce,
            required_features: features,
        }
        .encode(),
    }
}

fn data(welcome: &Packet, sequence: u32, channel: u16, bytes: &[u8]) -> Packet {
    Packet {
        kind: Kind::Data,
        connection: welcome.connection,
        token: welcome.token,
        sequence,
        channel,
        payload: bytes.to_vec(),
    }
}

async fn join(
    service: &mut Service,
    socket: &UdpSocket,
    game: u32,
    version: u32,
    nonce: u64,
) -> Packet {
    wire(socket, service.address, hello(game, version, nonce, 0)).await;
    let welcome = receive(socket, service.address, Kind::Welcome).await;
    let details = Welcome::decode(&welcome.payload).unwrap();
    assert_eq!(
        (details.game, details.application_version, details.nonce),
        (GameId(game), version, nonce)
    );
    assert_eq!(details.features, 0);
    assert_ne!(welcome.connection.0, 0);
    assert_ne!(welcome.token, ConnectionToken::ZERO);
    match service.event().await {
        Event::Connected(connection) => {
            assert_eq!(connection.id, welcome.connection);
            assert_eq!(connection.application_version, version);
        }
        other => panic!("Unexpected event: {other:?}"),
    }
    welcome
}

#[tokio::test]
async fn retries_are_idempotent_and_shared_ip_connections_remain_distinct() {
    let mut service = Service::start(config(17)).await;
    let a = client().await;
    let b = client().await;
    let first = join(&mut service, &a, 17, 1, 123).await;
    let second = join(&mut service, &b, 17, 2, 456).await;
    assert_ne!(first.connection, second.connection);
    wire(&a, service.address, hello(17, 1, 123, 0)).await;
    let retry = receive(&a, service.address, Kind::Welcome).await;
    assert_eq!(
        (retry.connection, retry.token),
        (first.connection, first.token)
    );
    assert!(
        timeout(Duration::from_millis(30), service.events.recv())
            .await
            .is_err()
    );
    let stats = service.stop().await;
    assert_eq!(stats.connected, 2);
    assert_eq!(stats.disconnected, 2);
}

#[tokio::test]
async fn refuses_wrong_games_versions_features_capacity_and_endpoint_replacement() {
    let mut configuration = config(23);
    configuration.max_connections = 1;
    let mut service = Service::start(configuration).await;
    let a = client().await;
    for (packet, expected) in [
        (hello(99, 1, 1, 0), RejectCode::Game),
        (hello(23, 3, 2, 0), RejectCode::ApplicationVersion),
        (
            hello(23, 1, 3, protocol::FEATURE_RELIABLE),
            RejectCode::Features,
        ),
        (
            hello(23, 1, 4, protocol::FEATURE_ENCRYPTED),
            RejectCode::Features,
        ),
    ] {
        wire(&a, service.address, packet).await;
        assert_eq!(
            Reject::decode(&receive(&a, service.address, Kind::Reject).await.payload)
                .unwrap()
                .code,
            expected
        );
    }
    let welcome = join(&mut service, &a, 23, 1, 5).await;
    wire(&a, service.address, hello(23, 1, 6, 0)).await;
    assert_eq!(
        Reject::decode(&receive(&a, service.address, Kind::Reject).await.payload)
            .unwrap()
            .code,
        RejectCode::EndpointInUse
    );
    let b = client().await;
    wire(&b, service.address, hello(23, 1, 7, 0)).await;
    assert_eq!(
        Reject::decode(&receive(&b, service.address, Kind::Reject).await.payload)
            .unwrap()
            .code,
        RejectCode::Capacity
    );
    wire(
        &a,
        service.address,
        data(&welcome, 1, 0, b"still connected"),
    )
    .await;
    assert!(matches!(service.event().await, Event::Message { .. }));
    assert_eq!(service.stop().await.connected, 1);
}

#[tokio::test]
async fn application_receives_opaque_messages_and_explicitly_chooses_recipients() {
    let mut service = Service::start(config(31)).await;
    let a = client().await;
    let b = client().await;
    let first = join(&mut service, &a, 31, 1, 1).await;
    let second = join(&mut service, &b, 31, 1, 2).await;
    wire(
        &a,
        service.address,
        data(&first, 17, 3, b"\0\xffopaque application bytes"),
    )
    .await;
    assert_eq!(
        service.event().await,
        Event::Message {
            connection: first.connection,
            channel: 3,
            sequence: 17,
            payload: b"\0\xffopaque application bytes".to_vec()
        }
    );
    assert!(
        timeout(Duration::from_millis(30), b.recv(&mut [0; 2048]))
            .await
            .is_err(),
        "No automatic forwarding"
    );
    service
        .send(second.connection, 5, b"server-generated update")
        .await
        .unwrap();
    let response = receive(&b, service.address, Kind::Data).await;
    assert_eq!(
        (
            response.connection,
            response.token,
            response.channel,
            response.payload.as_slice()
        ),
        (
            second.connection,
            second.token,
            5,
            b"server-generated update".as_slice()
        )
    );
    service
        .send(first.connection, 0, b"private reply")
        .await
        .unwrap();
    assert_eq!(
        receive(&a, service.address, Kind::Data).await.payload,
        b"private reply"
    );
    assert!(matches!(
        service.send(ConnectionId(0), 0, b"bad recipient").await,
        Err(SendError::UnknownConnection)
    ));
    assert!(matches!(
        service.send(first.connection, 16, b"bad channel").await,
        Err(SendError::Channel)
    ));
    assert!(matches!(
        service.send(first.connection, 0, &[0; 1025]).await,
        Err(SendError::Payload)
    ));
    service.stop().await;
}

#[tokio::test]
async fn source_binding_and_per_channel_replay_windows_preserve_reordered_events() {
    let mut service = Service::start(config(37)).await;
    let a = client().await;
    let stranger = client().await;
    let welcome = join(&mut service, &a, 37, 1, 1).await;
    wire(
        &stranger,
        service.address,
        data(&welcome, 99, 0, b"spoofed endpoint"),
    )
    .await;
    let mut bad = data(&welcome, 99, 0, b"wrong token");
    bad.token = ConnectionToken::from_bytes([1; 16]);
    wire(&a, service.address, bad).await;
    for (sequence, channel) in [(100, 0), (99, 0), (0, 1)] {
        wire(
            &a,
            service.address,
            data(&welcome, sequence, channel, b"event"),
        )
        .await;
        assert!(
            matches!(service.event().await, Event::Message { sequence: received, channel: stream, .. } if received == sequence && stream == channel)
        );
    }
    for sequence in [100, 1] {
        wire(
            &a,
            service.address,
            data(&welcome, sequence, 0, b"duplicate or too old"),
        )
        .await;
    }
    let mut ping = data(&welcome, 0, 0, &[]);
    ping.kind = Kind::Ping;
    wire(&a, service.address, ping).await;
    receive(&a, service.address, Kind::Pong).await;
    let statistics = service.statistics().await;
    assert_eq!(statistics.rejected, 2);
    assert_eq!(statistics.replay_dropped, 2);
    assert!(
        timeout(Duration::from_millis(30), service.events.recv())
            .await
            .is_err()
    );
    service.stop().await;
}

#[tokio::test]
async fn heartbeat_keeps_connection_alive_and_idle_expiry_emits_one_disconnect() {
    let mut configuration = config(41);
    configuration.heartbeat_interval = Duration::from_millis(50);
    configuration.idle_timeout = Duration::from_millis(500);
    let mut service = Service::start(configuration).await;
    let a = client().await;
    let welcome = join(&mut service, &a, 41, 1, 1).await;
    for sequence in 0..7 {
        sleep(Duration::from_millis(100)).await;
        let mut ping = data(&welcome, sequence, 0, &[]);
        ping.kind = Kind::Ping;
        wire(&a, service.address, ping).await;
        receive(&a, service.address, Kind::Pong).await;
    }
    assert!(
        matches!(service.event().await, Event::Disconnected { connection, reason: DisconnectReason::IdleTimeout } if connection.id == welcome.connection)
    );
    let statistics = service.stop().await;
    assert_eq!((statistics.connected, statistics.disconnected), (1, 1));
}

#[tokio::test]
async fn malformed_and_oversize_datagrams_and_closed_clients_do_not_stop_the_endpoint() {
    let mut service = Service::start(config(43)).await;
    let a = client().await;
    let welcome = join(&mut service, &a, 43, 1, 1).await;
    a.send_to(&vec![0u8; 4096], service.address).await.unwrap();
    a.send_to(b"invalid", service.address).await.unwrap();
    let mut illegal = data(&welcome, 0, 0, &[]);
    illegal.kind = Kind::Welcome;
    wire(&a, service.address, illegal).await;
    wire(&a, service.address, data(&welcome, 0, 0, b"alive")).await;
    assert!(matches!(service.event().await, Event::Message { .. }));
    drop(a);
    let _ = service.send(welcome.connection, 0, b"closed client").await;
    let b = client().await;
    join(&mut service, &b, 43, 1, 2).await;
    assert!(service.stop().await.invalid >= 3);
}

#[tokio::test]
async fn independent_services_reject_each_others_connections_and_stop_independently() {
    let mut first = Service::start(config(47)).await;
    let mut second = Service::start(config(53)).await;
    let a = client().await;
    let b = client().await;
    let first_connection = join(&mut first, &a, 47, 1, 1).await;
    let second_connection = join(&mut second, &b, 53, 1, 2).await;
    assert!(matches!(
        second
            .send(first_connection.connection, 0, b"cross-service")
            .await,
        Err(SendError::UnknownConnection)
    ));
    wire(
        &a,
        second.address,
        data(&first_connection, 1, 0, b"cross-service"),
    )
    .await;
    first.stop().await;
    wire(
        &b,
        second.address,
        data(&second_connection, 1, 0, b"still running"),
    )
    .await;
    assert!(
        matches!(second.event().await, Event::Message { payload, .. } if payload == b"still running")
    );
    second.stop().await;
}

#[tokio::test]
async fn application_timers_and_state_live_independently_of_connection_population() {
    let mut endpoint = Endpoint::bind(config(59)).await.unwrap();
    let mut timer = tokio::time::interval(Duration::from_millis(10));
    let mut world_updates = 0;
    while world_updates < 5 {
        tokio::select! {
            _ = timer.tick() => world_updates += 1,
            event = endpoint.next_event() => panic!("An empty service must remain waiting: {event:?}"),
        }
    }
    let a = client().await;
    wire(&a, endpoint.local_addr(), hello(59, 1, 1, 0)).await;
    let event = timeout(Duration::from_secs(3), endpoint.next_event())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let Event::Connected(connection) = event else {
        panic!("Expected connection");
    };
    receive(&a, endpoint.local_addr(), Kind::Welcome).await;
    endpoint
        .disconnect(connection.id, DisconnectReason::Application)
        .unwrap();
    assert!(matches!(
        endpoint.next_event().await.unwrap(),
        Some(Event::Disconnected { .. })
    ));
    while world_updates < 10 {
        tokio::select! {
            _ = timer.tick() => world_updates += 1,
            event = endpoint.next_event() => panic!("Last departure must not stop the service: {event:?}"),
        }
    }
    let address = endpoint.local_addr();
    endpoint.shutdown();
    assert_eq!(endpoint.next_event().await.unwrap(), None);
    assert!(matches!(
        endpoint.send(connection.id, 0, b"closed"),
        Err(SendError::Closed)
    ));
    let _replacement = UdpSocket::bind(address)
        .await
        .expect("Shutdown releases the socket");
}

#[tokio::test]
async fn outgoing_budget_is_bounded_and_never_builds_a_delivery_backlog() {
    let mut configuration = config(61);
    configuration.per_connection.packets_per_second = 1;
    let mut service = Service::start(configuration).await;
    let a = client().await;
    let welcome = join(&mut service, &a, 61, 1, 1).await;
    // WELCOME used the initial outbound packet allowance.
    assert!(matches!(
        service.send(welcome.connection, 0, b"over budget").await,
        Err(SendError::RateLimited)
    ));
    assert!(
        timeout(Duration::from_millis(30), a.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    assert_eq!(service.statistics().await.send_dropped, 1);
    // Shutdown notification is subject to the same budget as application data.
    assert_eq!(service.stop().await.send_dropped, 2);
}

#[tokio::test]
async fn retrying_a_handshake_does_not_reset_duplicate_protection() {
    let mut service = Service::start(config(67)).await;
    let a = client().await;
    let welcome = join(&mut service, &a, 67, 1, 77).await;
    wire(&a, service.address, data(&welcome, 100, 0, b"once")).await;
    assert!(matches!(
        service.event().await,
        Event::Message { sequence: 100, .. }
    ));
    wire(&a, service.address, hello(67, 1, 77, 0)).await;
    receive(&a, service.address, Kind::Welcome).await;
    wire(&a, service.address, data(&welcome, 100, 0, b"duplicate")).await;
    wire(&a, service.address, data(&welcome, 101, 0, b"next")).await;
    assert!(matches!(
        service.event().await,
        Event::Message { sequence: 101, .. }
    ));
    assert_eq!(service.statistics().await.replay_dropped, 1);
    service.stop().await;
}

#[tokio::test]
async fn client_disconnect_removes_only_that_connection_and_preserves_the_service() {
    let mut service = Service::start(config(71)).await;
    let a = client().await;
    let b = client().await;
    let first = join(&mut service, &a, 71, 1, 1).await;
    let second = join(&mut service, &b, 71, 1, 2).await;
    let mut disconnect = data(
        &first,
        0,
        0,
        &(DisconnectReason::Client as u16).to_le_bytes(),
    );
    disconnect.kind = Kind::Disconnect;
    wire(&a, service.address, disconnect).await;
    assert!(
        matches!(service.event().await, Event::Disconnected { connection, reason: DisconnectReason::Client } if connection.id == first.connection)
    );
    assert!(matches!(
        service.send(first.connection, 0, b"gone").await,
        Err(SendError::UnknownConnection)
    ));
    wire(&b, service.address, data(&second, 0, 0, b"unaffected")).await;
    assert!(
        matches!(service.event().await, Event::Message { connection, .. } if connection == second.connection)
    );
    service.stop().await;
}

#[tokio::test]
async fn small_application_payload_limits_do_not_break_fixed_handshake_messages() {
    let mut configuration = config(73);
    configuration.max_payload = 8;
    let mut service = Service::start(configuration).await;
    let a = client().await;
    let welcome = join(&mut service, &a, 73, 1, 1).await;
    assert_eq!(Welcome::decode(&welcome.payload).unwrap().max_payload, 8);
    wire(&a, service.address, data(&welcome, 1, 0, &[0; 9])).await;
    wire(&a, service.address, data(&welcome, 1, 0, b"accepted")).await;
    assert!(
        matches!(service.event().await, Event::Message { payload, .. } if payload == b"accepted")
    );
    assert!(matches!(
        service.send(welcome.connection, 0, &[0; 9]).await,
        Err(SendError::Payload)
    ));
    service
        .send(welcome.connection, 0, b"response")
        .await
        .unwrap();
    assert_eq!(
        receive(&a, service.address, Kind::Data).await.payload,
        b"response"
    );
    service.stop().await;
}
