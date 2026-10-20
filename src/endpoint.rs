use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use rand::{RngCore, rngs::OsRng};
use thiserror::Error;
use tokio::net::UdpSocket;

use crate::limit::{Bucket, Budget};
use crate::protocol::{self, ConnectionToken, Hello, Kind, Packet, Reject, RejectCode, Welcome};
use crate::replay::ReplayWindow;
use crate::{Connection, ConnectionId, DisconnectReason, Event, ServerConfig};

#[derive(Clone, Debug, Default)]
pub struct Statistics {
    pub received: u64,
    pub invalid: u64,
    pub rejected: u64,
    pub rate_limited: u64,
    pub replay_dropped: u64,
    pub connected: u64,
    pub disconnected: u64,
    pub sent: u64,
    pub send_dropped: u64,
    pub socket_errors: u64,
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("Endpoint has been shut down")]
    Closed,
    #[error("Connection does not belong to this endpoint or has disconnected")]
    UnknownConnection,
    #[error("Payload exceeds the configured maximum")]
    Payload,
    #[error("Channel is outside the configured range")]
    Channel,
    #[error("Outgoing traffic budget exhausted; datagram was not queued")]
    RateLimited,
    #[error("Socket is temporarily unavailable; datagram was not queued")]
    Backpressure,
    #[error(transparent)]
    Io(#[from] io::Error),
}

struct Peer {
    connection: Connection,
    nonce: u64,
    token: ConnectionToken,
    seen: Instant,
    inbound: Budget,
    outbound: Budget,
    control_replay: ReplayWindow,
    data_replay: Vec<ReplayWindow>,
    control_sequence: u32,
    data_sequences: Vec<u32>,
}

/// One anonymous game-service endpoint. The application drives this endpoint
/// through `next_event` and owns its own world/match state and timers.
///
/// `next_event` is cancellation-safe in `tokio::select!`. Poll it regularly;
/// blocking game work also blocks heartbeat processing in this task. Dropping
/// the endpoint releases its socket without starting/stopping a Tokio runtime.
pub struct Endpoint {
    socket: Option<UdpSocket>,
    address: SocketAddrV4,
    config: ServerConfig,
    peers: HashMap<ConnectionId, Peer>,
    addresses: HashMap<SocketAddrV4, ConnectionId>,
    events: VecDeque<Event>,
    admission: HashMap<Ipv4Addr, (Bucket, Instant)>,
    inbound: Budget,
    outbound: Budget,
    statistics: Statistics,
}

impl Endpoint {
    pub async fn bind(config: ServerConfig) -> io::Result<Self> {
        config.validate().map_err(io::Error::other)?;
        let socket = UdpSocket::bind(config.bind).await?;
        // Establish writable readiness before synchronous, nonqueued sends.
        socket.writable().await?;
        let SocketAddr::V4(address) = socket.local_addr()? else {
            return Err(io::Error::other("ADLN v1 endpoint requires IPv4"));
        };
        let now = Instant::now();
        Ok(Self {
            socket: Some(socket),
            address,
            inbound: Budget::new(&config.global, now),
            outbound: Budget::new(&config.global, now),
            config,
            peers: HashMap::new(),
            addresses: HashMap::new(),
            events: VecDeque::new(),
            admission: HashMap::new(),
            statistics: Statistics::default(),
        })
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.address
    }

    pub fn connection(&self, id: ConnectionId) -> Option<&Connection> {
        self.peers.get(&id).map(|peer| &peer.connection)
    }

    pub fn connections(&self) -> impl Iterator<Item = &Connection> {
        self.peers.values().map(|peer| &peer.connection)
    }

    pub fn statistics(&self) -> &Statistics {
        &self.statistics
    }

    /// Channel numbering starts at zero. Best-effort data can be lost or
    /// reordered. Each channel has its own duplicate window and send sequence.
    /// There is no implicit forwarding, sender prefix or application routing.
    pub fn send(
        &mut self,
        recipient: ConnectionId,
        channel: u16,
        payload: &[u8],
    ) -> Result<(), SendError> {
        if self.socket.is_none() {
            return Err(SendError::Closed);
        }
        if payload.len() > self.config.max_payload {
            return Err(SendError::Payload);
        }
        if channel >= self.config.channels {
            return Err(SendError::Channel);
        }
        let peer = self
            .peers
            .get_mut(&recipient)
            .ok_or(SendError::UnknownConnection)?;
        let sequence = &mut peer.data_sequences[channel as usize];
        let packet = Packet {
            kind: Kind::Data,
            connection: recipient,
            token: peer.token,
            sequence: *sequence,
            channel,
            payload: payload.to_vec(),
        };
        *sequence = sequence.wrapping_add(1);
        let address = peer.connection.address;
        self.emit(address, Some(recipient), packet)
    }

    /// Local disconnects also produce a Disconnected event. Event storage is
    /// bounded by the connection capacity: no new connections are read until pending
    /// events have been consumed. Notification on the wire is best effort.
    pub fn disconnect(
        &mut self,
        connection: ConnectionId,
        reason: DisconnectReason,
    ) -> Result<(), SendError> {
        let result = self.send_control(
            connection,
            Kind::Disconnect,
            (reason as u16).to_le_bytes().to_vec(),
        );
        if self.peers.contains_key(&connection) {
            self.remove(connection, reason);
        }
        result
    }

    /// Closes the socket immediately. Drain remaining Disconnected events with
    /// `next_event`; it returns None once those events have been consumed.
    pub fn shutdown(&mut self) {
        let connections: Vec<_> = self.peers.keys().copied().collect();
        for connection in connections {
            let _ = self.disconnect(connection, DisconnectReason::ServerShutdown);
        }
        self.socket.take();
    }

    pub async fn next_event(&mut self) -> io::Result<Option<Event>> {
        let mut buffer = [0u8; protocol::HEADER_SIZE + protocol::MAX_PAYLOAD + 1];
        let mut processed = 0;
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }
            if self.socket.is_none() {
                return Ok(None);
            }
            let now = Instant::now();
            let expired = self.peers.iter().find_map(|(id, peer)| {
                (now.saturating_duration_since(peer.seen) >= self.config.idle_timeout)
                    .then_some(*id)
            });
            if let Some(connection) = expired {
                let _ = self.disconnect(connection, DisconnectReason::IdleTimeout);
                continue;
            }
            if processed >= 64 {
                tokio::task::yield_now().await;
                processed = 0;
            }
            let deadline = self
                .peers
                .values()
                .map(|peer| peer.seen + self.config.idle_timeout)
                .min()
                .unwrap_or(now + Duration::from_secs(3600));
            let socket = self.socket.as_ref().unwrap();
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => (),
                result = socket.readable() => {
                    processed += 1;
                    match result.and_then(|()| socket.try_recv_from(&mut buffer)) {
                        Ok((length, SocketAddr::V4(source))) => {
                            self.receive(&buffer[..length], source, Instant::now())?;
                        }
                        Ok(_) => self.statistics.invalid += 1,
                        Err(error) if oversized(&error) => {
                            self.statistics.received += 1;
                            self.statistics.invalid += 1;
                            if !self.inbound.take(buffer.len(), Instant::now()) {
                                self.statistics.rate_limited += 1;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
                        Err(error) if transient(&error) => self.statistics.socket_errors += 1,
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }

    fn remove(&mut self, id: ConnectionId, reason: DisconnectReason) {
        if let Some(peer) = self.peers.remove(&id) {
            self.addresses.remove(&peer.connection.address);
            self.statistics.disconnected += 1;
            self.events.push_back(Event::Disconnected {
                connection: peer.connection,
                reason,
            });
        }
    }

    fn emit(
        &mut self,
        address: SocketAddrV4,
        peer: Option<ConnectionId>,
        packet: Packet,
    ) -> Result<(), SendError> {
        let socket = self.socket.as_ref().ok_or(SendError::Closed)?;
        let bytes = packet.encode().map_err(|_| SendError::Payload)?;
        let now = Instant::now();
        if !self.outbound.take(bytes.len(), now)
            || peer.is_some_and(|id| {
                !self
                    .peers
                    .get_mut(&id)
                    .is_some_and(|peer| peer.outbound.take(bytes.len(), now))
            })
        {
            self.statistics.rate_limited += 1;
            self.statistics.send_dropped += 1;
            return Err(SendError::RateLimited);
        }
        match socket.try_send_to(&bytes, address.into()) {
            Ok(length) if length == bytes.len() => {
                self.statistics.sent += 1;
                Ok(())
            }
            Ok(_) => {
                self.statistics.send_dropped += 1;
                Err(SendError::Backpressure)
            }
            Err(error) if transient(&error) => {
                self.statistics.send_dropped += 1;
                self.statistics.socket_errors += 1;
                Err(SendError::Backpressure)
            }
            Err(error) => Err(SendError::Io(error)),
        }
    }

    fn send_control(
        &mut self,
        id: ConnectionId,
        kind: Kind,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        let peer = self
            .peers
            .get_mut(&id)
            .ok_or(SendError::UnknownConnection)?;
        let packet = Packet {
            kind,
            connection: id,
            token: peer.token,
            sequence: peer.control_sequence,
            channel: 0,
            payload,
        };
        peer.control_sequence = peer.control_sequence.wrapping_add(1);
        let address = peer.connection.address;
        self.emit(address, Some(id), packet)
    }

    fn control_result(result: Result<(), SendError>) -> io::Result<()> {
        match result {
            Ok(()) | Err(SendError::RateLimited | SendError::Backpressure) => Ok(()),
            Err(SendError::Io(error)) => Err(error),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    fn receive(&mut self, bytes: &[u8], address: SocketAddrV4, now: Instant) -> io::Result<()> {
        self.statistics.received += 1;
        if !self.inbound.take(bytes.len(), now) {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        let packet = match Packet::decode(bytes) {
            Ok(packet)
                if packet.kind != Kind::Data || packet.payload.len() <= self.config.max_payload =>
            {
                packet
            }
            _ => {
                self.statistics.invalid += 1;
                return Ok(());
            }
        };
        if packet.kind == Kind::Hello {
            return self.hello(packet, address, now);
        }
        let Some(peer) = self.peers.get_mut(&packet.connection) else {
            self.statistics.rejected += 1;
            return Ok(());
        };
        if peer.connection.address != address || peer.token != packet.token {
            self.statistics.rejected += 1;
            return Ok(());
        }
        if !peer.inbound.take(bytes.len(), now) {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        let replay = match packet.kind {
            Kind::Ping if packet.channel == 0 && packet.payload.is_empty() => {
                &mut peer.control_replay
            }
            Kind::Disconnect
                if packet.channel == 0
                    && packet.payload == (DisconnectReason::Client as u16).to_le_bytes() =>
            {
                &mut peer.control_replay
            }
            Kind::Data if packet.channel < self.config.channels => {
                &mut peer.data_replay[packet.channel as usize]
            }
            _ => {
                self.statistics.invalid += 1;
                return Ok(());
            }
        };
        if !replay.accept(packet.sequence) {
            self.statistics.replay_dropped += 1;
            return Ok(());
        }
        peer.seen = now;
        match packet.kind {
            Kind::Ping => {
                Self::control_result(self.send_control(packet.connection, Kind::Pong, vec![]))
            }
            Kind::Disconnect => {
                self.remove(packet.connection, DisconnectReason::Client);
                Ok(())
            }
            Kind::Data => {
                self.events.push_back(Event::Message {
                    connection: packet.connection,
                    channel: packet.channel,
                    sequence: packet.sequence,
                    payload: packet.payload,
                });
                Ok(())
            }
            _ => unreachable!("Request shape was validated"),
        }
    }

    fn admit_source(&mut self, ip: Ipv4Addr, now: Instant) -> bool {
        self.admission
            .retain(|_, (_, last)| now.saturating_duration_since(*last) < Duration::from_secs(60));
        if !self.admission.contains_key(&ip)
            && self.admission.len() >= self.config.max_admission_sources
        {
            return false;
        }
        let (bucket, last) = self.admission.entry(ip).or_insert_with(|| {
            (
                Bucket::new(self.config.handshakes_per_ip_per_second, now),
                now,
            )
        });
        *last = now;
        bucket.take(1, now)
    }

    fn hello(&mut self, packet: Packet, address: SocketAddrV4, now: Instant) -> io::Result<()> {
        let hello = match Hello::decode(&packet.payload) {
            Ok(hello)
                if hello.nonce != 0
                    && packet.connection.0 == 0
                    && packet.token == ConnectionToken::ZERO
                    && packet.channel == 0 =>
            {
                hello
            }
            _ => {
                self.statistics.invalid += 1;
                return Ok(());
            }
        };
        if !self.admit_source(*address.ip(), now) {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        let reject = if hello.game != self.config.game {
            Some(RejectCode::Game)
        } else if !self
            .config
            .application_versions
            .contains(&hello.application_version)
        {
            Some(RejectCode::ApplicationVersion)
        } else if hello.required_features & !protocol::SUPPORTED_FEATURES != 0 {
            Some(RejectCode::Features)
        } else {
            None
        };
        if let Some(code) = reject {
            return self.reject(address, hello.nonce, code);
        }
        let id = if let Some(id) = self.addresses.get(&address).copied() {
            let peer = &self.peers[&id];
            if peer.nonce != hello.nonce
                || peer.connection.application_version != hello.application_version
            {
                // An unauthenticated HELLO cannot replace a live connection.
                return self.reject(address, hello.nonce, RejectCode::EndpointInUse);
            }
            id
        } else {
            if self.peers.len() >= self.config.max_connections {
                return self.reject(address, hello.nonce, RejectCode::Capacity);
            }
            let id = loop {
                let value = ConnectionId(u64::from_le_bytes(random_bytes()?));
                if value.0 != 0 && !self.peers.contains_key(&value) {
                    break value;
                }
            };
            let token = loop {
                let value = ConnectionToken::from_bytes(random_bytes()?);
                if value != ConnectionToken::ZERO {
                    break value;
                }
            };
            let connection = Connection {
                id,
                address,
                game: hello.game,
                application_version: hello.application_version,
            };
            self.peers.insert(
                id,
                Peer {
                    connection: connection.clone(),
                    nonce: hello.nonce,
                    token,
                    seen: now,
                    inbound: Budget::new(&self.config.per_connection, now),
                    outbound: Budget::new(&self.config.per_connection, now),
                    control_replay: ReplayWindow::default(),
                    data_replay: (0..self.config.channels)
                        .map(|_| ReplayWindow::default())
                        .collect(),
                    control_sequence: 0,
                    data_sequences: vec![0; self.config.channels as usize],
                },
            );
            self.addresses.insert(address, id);
            self.statistics.connected += 1;
            self.events.push_back(Event::Connected(connection));
            id
        };
        // HELLO retries do not refresh liveness: only possession of the issued
        // token can keep the established connection alive after initial admission.
        let welcome = Welcome {
            game: hello.game,
            application_version: hello.application_version,
            nonce: hello.nonce,
            idle_timeout_ms: self.config.idle_timeout.as_millis() as u32,
            heartbeat_interval_ms: self.config.heartbeat_interval.as_millis() as u32,
            max_payload: self.config.max_payload as u16,
            channels: self.config.channels,
            features: protocol::SUPPORTED_FEATURES,
        };
        Self::control_result(self.send_control(id, Kind::Welcome, welcome.encode()))
    }

    fn reject(&mut self, address: SocketAddrV4, nonce: u64, code: RejectCode) -> io::Result<()> {
        self.statistics.rejected += 1;
        Self::control_result(self.emit(
            address,
            None,
            Packet {
                kind: Kind::Reject,
                connection: ConnectionId(0),
                token: ConnectionToken::ZERO,
                sequence: 0,
                channel: 0,
                payload: Reject { nonce, code }.encode(),
            },
        ))
    }
}

fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0; N];
    OsRng.try_fill_bytes(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

fn transient(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::Interrupted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

fn oversized(error: &io::Error) -> bool {
    cfg!(windows) && error.raw_os_error() == Some(10040)
}
