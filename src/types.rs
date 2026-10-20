use std::net::SocketAddrV4;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GameId(pub u32);

/// Identifies one live connection, not an account or a saved credential.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Connection {
    pub id: ConnectionId,
    pub address: SocketAddrV4,
    pub game: GameId,
    pub application_version: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DisconnectReason {
    Client = 1,
    Application = 2,
    IdleTimeout = 3,
    ServerShutdown = 4,
}

impl DisconnectReason {
    pub fn from_wire(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Client),
            2 => Some(Self::Application),
            3 => Some(Self::IdleTimeout),
            4 => Some(Self::ServerShutdown),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Event {
    Connected(Connection),
    Message {
        connection: ConnectionId,
        channel: u16,
        sequence: u32,
        payload: Vec<u8>,
    },
    Disconnected {
        connection: Connection,
        reason: DisconnectReason,
    },
}
