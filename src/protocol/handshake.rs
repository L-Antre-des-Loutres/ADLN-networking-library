use super::ProtocolError;
use crate::GameId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hello {
    pub game: GameId,
    pub application_version: u32,
    /// Nonzero client-generated retry identifier; not a login secret.
    pub nonce: u64,
    pub required_features: u32,
}

impl Hello {
    pub const SIZE: usize = 20;
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = self.game.0.to_le_bytes().to_vec();
        bytes.extend(self.application_version.to_le_bytes());
        bytes.extend(self.nonce.to_le_bytes());
        bytes.extend(self.required_features.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::SIZE {
            return Err(ProtocolError::Length);
        }
        Ok(Self {
            game: GameId(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            application_version: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            nonce: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            required_features: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Welcome {
    pub game: GameId,
    pub application_version: u32,
    pub nonce: u64,
    pub idle_timeout_ms: u32,
    pub heartbeat_interval_ms: u32,
    /// Maximum application DATA payload; not a limit on fixed control messages.
    pub max_payload: u16,
    /// Data channel count; control sequencing is an additional independent stream.
    pub channels: u16,
    pub features: u32,
}

impl Welcome {
    pub const SIZE: usize = 32;
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = self.game.0.to_le_bytes().to_vec();
        bytes.extend(self.application_version.to_le_bytes());
        bytes.extend(self.nonce.to_le_bytes());
        bytes.extend(self.idle_timeout_ms.to_le_bytes());
        bytes.extend(self.heartbeat_interval_ms.to_le_bytes());
        bytes.extend(self.max_payload.to_le_bytes());
        bytes.extend(self.channels.to_le_bytes());
        bytes.extend(self.features.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != Self::SIZE {
            return Err(ProtocolError::Length);
        }
        Ok(Self {
            game: GameId(u32::from_le_bytes(bytes[..4].try_into().unwrap())),
            application_version: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            nonce: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            idle_timeout_ms: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            heartbeat_interval_ms: u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            max_payload: u16::from_le_bytes(bytes[24..26].try_into().unwrap()),
            channels: u16::from_le_bytes(bytes[26..28].try_into().unwrap()),
            features: u32::from_le_bytes(bytes[28..32].try_into().unwrap()),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum RejectCode {
    Game = 1,
    ApplicationVersion = 2,
    Features = 3,
    Capacity = 4,
    EndpointInUse = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reject {
    pub nonce: u64,
    pub code: RejectCode,
}

impl Reject {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = self.nonce.to_le_bytes().to_vec();
        bytes.extend((self.code as u16).to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != 10 {
            return Err(ProtocolError::Length);
        }
        let code = match u16::from_le_bytes(bytes[8..10].try_into().unwrap()) {
            1 => RejectCode::Game,
            2 => RejectCode::ApplicationVersion,
            3 => RejectCode::Features,
            4 => RejectCode::Capacity,
            5 => RejectCode::EndpointInUse,
            _ => return Err(ProtocolError::Kind),
        };
        Ok(Self {
            nonce: u64::from_le_bytes(bytes[..8].try_into().unwrap()),
            code,
        })
    }
}
