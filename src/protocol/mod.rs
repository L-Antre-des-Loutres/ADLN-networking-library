//! ADL DS Network protocol v1. All integers are little-endian; the fixed header
//! is 40 bytes. Its final two bytes are reserved and must be zero.
//! Sequence windows are independent per application channel and control stream.
mod handshake;

use std::fmt;

use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::ConnectionId;
pub use handshake::{Hello, Reject, RejectCode, Welcome};

pub const MAGIC: [u8; 4] = *b"ADLN";
pub const VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 40;
pub const MAX_PAYLOAD: usize = 1024;
/// No delivery/security extensions are implemented in this initial version.
pub const SUPPORTED_FEATURES: u32 = 0;
pub const FEATURE_RELIABLE: u32 = 1;
pub const FEATURE_ENCRYPTED: u32 = 2;

#[derive(Clone, Copy, Default, Eq)]
pub struct ConnectionToken([u8; 16]);

impl ConnectionToken {
    pub const ZERO: Self = Self([0; 16]);
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl PartialEq for ConnectionToken {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl fmt::Debug for ConnectionToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionToken([redacted])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Kind {
    Hello = 1,
    Welcome = 2,
    Reject = 3,
    Ping = 4,
    Pong = 5,
    Data = 6,
    Disconnect = 7,
    AuthHello = 8,
    AuthChallenge = 9,
    AuthProof = 10,
    AuthAccepted = 11,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    /// Header offset 5; magic/version/length occupy offsets 0..8.
    pub kind: Kind,
    /// Offsets 8..16. Zero until WELCOME assigns an ID.
    pub connection: ConnectionId,
    /// Offsets 16..32. Server-generated; binds packets to the live endpoint.
    pub token: ConnectionToken,
    /// Offsets 32..36. Wraps at 2^32, separately per channel/control stream.
    pub sequence: u32,
    /// Offsets 36..38. Controls require zero; data uses a negotiated channel.
    pub channel: u16,
    /// Starts at offset 40. Game payloads are never interpreted by the library.
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.encode_version(VERSION)
    }

    pub(crate) fn encode_version(&self, version: u8) -> Result<Vec<u8>, ProtocolError> {
        if version == VERSION && self.kind as u8 >= Kind::AuthHello as u8 {
            return Err(ProtocolError::Kind);
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(ProtocolError::Length);
        }
        let mut bytes = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        bytes.extend(MAGIC);
        bytes.extend([version, self.kind as u8]);
        bytes.extend((self.payload.len() as u16).to_le_bytes());
        bytes.extend(self.connection.0.to_le_bytes());
        bytes.extend(self.token.0);
        bytes.extend(self.sequence.to_le_bytes());
        bytes.extend(self.channel.to_le_bytes());
        bytes.extend([0, 0]);
        bytes.extend(&self.payload);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::decode_version(bytes, VERSION)
    }

    pub(crate) fn decode_version(bytes: &[u8], version: u8) -> Result<Self, ProtocolError> {
        if bytes.len() < HEADER_SIZE {
            return Err(ProtocolError::Length);
        }
        if bytes[..4] != MAGIC || bytes[4] != version {
            return Err(ProtocolError::Version);
        }
        if bytes[38..40] != [0, 0] {
            return Err(ProtocolError::Reserved);
        }
        let kind = match bytes[5] {
            1 => Kind::Hello,
            2 => Kind::Welcome,
            3 => Kind::Reject,
            4 => Kind::Ping,
            5 => Kind::Pong,
            6 => Kind::Data,
            7 => Kind::Disconnect,
            8 if version == 2 => Kind::AuthHello,
            9 if version == 2 => Kind::AuthChallenge,
            10 if version == 2 => Kind::AuthProof,
            11 if version == 2 => Kind::AuthAccepted,
            _ => return Err(ProtocolError::Kind),
        };
        let length = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
        if length > MAX_PAYLOAD || bytes.len() != HEADER_SIZE + length {
            return Err(ProtocolError::Length);
        }
        Ok(Self {
            kind,
            connection: ConnectionId(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
            token: ConnectionToken(bytes[16..32].try_into().unwrap()),
            sequence: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            channel: u16::from_le_bytes(bytes[36..38].try_into().unwrap()),
            payload: bytes[HEADER_SIZE..].to_vec(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ProtocolError {
    #[error("Invalid packet or message length")]
    Length,
    #[error("Unsupported protocol magic or version")]
    Version,
    #[error("Unknown message kind or code")]
    Kind,
    #[error("Reserved fields must be zero")]
    Reserved,
}
