use super::*;
use crate::auth::{Credential, DeviceId, Keys, LookupError};
use tokio::task::JoinSet;

pub(super) struct Session {
    pub identity: Identity,
    pub keys: Keys,
    request: Vec<u8>,
    challenge: Vec<u8>,
    welcome: Vec<u8>,
}
pub(super) struct Pending {
    id: ConnectionId,
    token: ConnectionToken,
    request: Vec<u8>,
    hello: Hello,
    device: DeviceId,
    pub deadline: Instant,
    session: Option<Session>,
}
type LookupResult = (SocketAddrV4, ConnectionId, Result<Credential, LookupError>);
#[derive(Default)]
pub(super) struct Authentication {
    pub store: Option<Arc<dyn CredentialStore>>,
    pub pending: HashMap<SocketAddrV4, Pending>,
    pub tasks: JoinSet<LookupResult>,
}

impl Authentication {
    pub fn reserves(&self, id: ConnectionId) -> bool {
        self.pending.values().any(|pending| pending.id == id)
    }
}

impl Endpoint {
    pub(super) fn auth_hello(
        &mut self,
        packet: Packet,
        bytes: &[u8],
        address: SocketAddrV4,
        now: Instant,
    ) -> io::Result<()> {
        let Some((hello, device)) = auth::parse_hello(&packet.payload) else {
            self.statistics.invalid += 1;
            return Ok(());
        };
        if packet.connection.0 != 0
            || packet.token != ConnectionToken::ZERO
            || packet.channel != 0
            || packet.sequence != 0
            || hello.nonce == 0
            || hello.game != self.config.game
            || !self
                .config
                .application_versions
                .contains(&hello.application_version)
            || hello.required_features != 0
            || bytes[bytes.len() - auth::TAG_SIZE..] != [0; auth::TAG_SIZE]
        {
            self.statistics.invalid += 1;
            return Ok(());
        }
        if !self.admit_source(*address.ip(), now) {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        // Repeated HELLO cannot replace a session, refresh its deadline or reset replay state.
        if let Some(id) = self.addresses.get(&address).copied() {
            if let Some(session) = self.peers[&id].session.as_ref()
                && session.request == packet.payload
            {
                let challenge = session.challenge.clone();
                return Self::control_result(self.emit_bytes(address, Some(id), &challenge));
            }
            self.statistics.auth_failed += 1;
            return Ok(());
        }
        if let Some(pending) = self.authentication.pending.get(&address) {
            if pending.request == packet.payload
                && let Some(session) = &pending.session
            {
                let challenge = session.challenge.clone();
                return Self::control_result(self.emit_bytes(address, None, &challenge));
            }
            return Ok(());
        }
        let Some(store) = self.authentication.store.clone() else {
            self.statistics.auth_failed += 1;
            return Ok(());
        };
        if self.authentication.pending.len() >= 64
            || self.authentication.tasks.len() >= 64
            || self.peers.len() + self.authentication.pending.len() >= self.config.max_connections
        {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        let id = loop {
            let id = ConnectionId(u64::from_le_bytes(random_bytes()?));
            if id.0 != 0
                && !self.peers.contains_key(&id)
                && !self
                    .authentication
                    .pending
                    .values()
                    .any(|pending| pending.id == id)
            {
                break id;
            }
        };
        let token = loop {
            let token = ConnectionToken::from_bytes(random_bytes()?);
            if token != ConnectionToken::ZERO {
                break token;
            }
        };
        self.authentication.pending.insert(
            address,
            Pending {
                id,
                token,
                request: packet.payload,
                hello,
                device: device.clone(),
                deadline: now + Duration::from_secs(10),
                session: None,
            },
        );
        self.authentication.tasks.spawn(async move {
            let result =
                tokio::time::timeout(Duration::from_secs(3), store.lookup(device, hello.game))
                    .await
                    .unwrap_or(Err(LookupError::Unavailable));
            (address, id, result)
        });
        Ok(())
    }

    pub(super) fn auth_lookup_complete(
        &mut self,
        address: SocketAddrV4,
        id: ConnectionId,
        result: Result<Credential, LookupError>,
    ) -> io::Result<()> {
        let Some(pending) = self.authentication.pending.get(&address) else {
            return Ok(());
        };
        if pending.id != id {
            return Ok(());
        }
        let credential = match result {
            Ok(credential) if credential.identity.device == pending.device => credential,
            result => {
                self.statistics.auth_failed += 1;
                if matches!(result, Err(LookupError::Unavailable)) {
                    self.statistics.auth_backend_errors += 1;
                }
                self.authentication.pending.remove(&address);
                return Ok(());
            }
        };
        let pending = self.authentication.pending.get_mut(&address).unwrap();
        let welcome = Welcome {
            game: pending.hello.game,
            application_version: pending.hello.application_version,
            nonce: pending.hello.nonce,
            idle_timeout_ms: self.config.idle_timeout.as_millis() as u32,
            heartbeat_interval_ms: self.config.heartbeat_interval.as_millis() as u32,
            max_payload: self.config.max_payload as u16,
            channels: self.config.channels,
            features: 0,
        }
        .encode();
        let mut payload = pending.request.clone();
        payload.extend(random_bytes::<32>()?);
        payload.extend(&welcome);
        let challenge = Packet {
            kind: Kind::AuthChallenge,
            connection: id,
            token: pending.token,
            sequence: 0,
            channel: 0,
            payload,
        };
        let keys = Keys::derive(&credential.secret, &challenge).map_err(io::Error::other)?;
        let challenge =
            auth::encode(&challenge, Some(&credential.secret)).map_err(io::Error::other)?;
        pending.session = Some(Session {
            identity: credential.identity,
            keys,
            request: pending.request.clone(),
            challenge: challenge.clone(),
            welcome,
        });
        Self::control_result(self.emit_bytes(address, None, &challenge))
    }

    pub(super) fn auth_proof(
        &mut self,
        packet: Packet,
        bytes: &[u8],
        address: SocketAddrV4,
        now: Instant,
    ) -> io::Result<()> {
        if packet.channel != 0 || packet.sequence != 0 || !packet.payload.is_empty() {
            self.statistics.invalid += 1;
            return Ok(());
        }
        if !self.admit_source(*address.ip(), now) {
            self.statistics.rate_limited += 1;
            return Ok(());
        }
        // Retry acknowledgement only: no extra Connected event, liveness or replay reset.
        if let Some(peer) = self.peers.get(&packet.connection) {
            if peer.connection.address == address
                && peer.token == packet.token
                && let Some(session) = &peer.session
                && auth::verify(bytes, &session.keys.client)
            {
                let accepted = Packet {
                    kind: Kind::AuthAccepted,
                    connection: packet.connection,
                    token: peer.token,
                    sequence: 0,
                    channel: 0,
                    payload: session.welcome.clone(),
                };
                return Self::control_result(self.emit(address, Some(packet.connection), accepted));
            }
            self.statistics.auth_failed += 1;
            return Ok(());
        }
        let valid = self
            .authentication
            .pending
            .get(&address)
            .is_some_and(|pending| {
                pending.deadline > now
                    && pending.id == packet.connection
                    && pending.token == packet.token
                    && pending
                        .session
                        .as_ref()
                        .is_some_and(|session| auth::verify(bytes, &session.keys.client))
            });
        if !valid {
            self.statistics.auth_failed += 1;
            return Ok(());
        }
        let pending = self.authentication.pending.remove(&address).unwrap();
        let session = pending.session.unwrap();
        let accepted = Packet {
            kind: Kind::AuthAccepted,
            connection: pending.id,
            token: pending.token,
            sequence: 0,
            channel: 0,
            payload: session.welcome.clone(),
        };
        let connection = Connection {
            id: pending.id,
            address,
            game: pending.hello.game,
            application_version: pending.hello.application_version,
        };
        self.peers.insert(
            pending.id,
            Peer {
                connection: connection.clone(),
                nonce: pending.hello.nonce,
                token: pending.token,
                session: Some(session),
                seen: now,
                inbound: Budget::new(&self.config.per_connection, now),
                outbound: Budget::new(&self.config.per_connection, now),
                control_replay: ReplayWindow::default(),
                data_replay: (0..self.config.channels)
                    .map(|_| ReplayWindow::default())
                    .collect(),
                control_sequence: 1,
                data_sequences: vec![0; self.config.channels as usize],
            },
        );
        self.addresses.insert(address, pending.id);
        self.statistics.connected += 1;
        self.events.push_back(Event::Connected(connection));
        Self::control_result(self.emit(address, Some(pending.id), accepted))
    }
}
