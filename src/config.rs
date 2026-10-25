use std::net::SocketAddrV4;
use std::time::Duration;

use thiserror::Error;

use crate::{GameId, protocol};

#[derive(Clone, Debug)]
pub struct TrafficLimits {
    pub packets_per_second: u32,
    pub bytes_per_second: u32,
}

impl TrafficLimits {
    pub(crate) fn validate(&self) -> bool {
        (1..=1_000_000).contains(&self.packets_per_second)
            && (1..=100_000_000).contains(&self.bytes_per_second)
    }
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub bind: SocketAddrV4,
    pub game: GameId,
    pub application_versions: Vec<u32>,
    /// Process protection only; gameplay population rules belong to the game.
    pub max_connections: usize,
    /// Maximum application DATA payload; control messages have fixed sizes.
    pub max_payload: usize,
    pub channels: u16,
    pub idle_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub per_connection: TrafficLimits,
    pub global: TrafficLimits,
    pub handshakes_per_ip_per_second: u32,
    pub max_admission_sources: usize,
}

impl ServerConfig {
    /// Includes the tag and the largest fixed login control message in budgets.
    pub fn validate_authenticated(&self) -> Result<(), ConfigError> {
        self.validate()?;
        let size = (protocol::HEADER_SIZE
            + self.max_payload.max(crate::auth::CHALLENGE_SIZE)
            + crate::auth::TAG_SIZE) as u32;
        if self.per_connection.bytes_per_second < size || self.global.bytes_per_second < size {
            return Err(ConfigError::Limits);
        }
        Ok(())
    }

    pub fn new(bind: SocketAddrV4, game: GameId, application_versions: Vec<u32>) -> Self {
        Self {
            bind,
            game,
            application_versions,
            max_connections: 256,
            max_payload: protocol::MAX_PAYLOAD,
            channels: 16,
            idle_timeout: Duration::from_secs(15),
            heartbeat_interval: Duration::from_secs(1),
            per_connection: TrafficLimits {
                packets_per_second: 256,
                bytes_per_second: 262_144,
            },
            global: TrafficLimits {
                packets_per_second: 32_768,
                bytes_per_second: 8_388_608,
            },
            handshakes_per_ip_per_second: 16,
            max_admission_sources: 1024,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.game.0 == 0
            || self.application_versions.is_empty()
            || self.application_versions.len() > 64
            || self.application_versions.contains(&0)
            || self
                .application_versions
                .iter()
                .enumerate()
                .any(|(index, value)| self.application_versions[..index].contains(value))
        {
            return Err(ConfigError::Application);
        }
        if !(1..=8192).contains(&self.max_connections)
            || !(1..=protocol::MAX_PAYLOAD).contains(&self.max_payload)
            || !(1..=64).contains(&self.channels)
            || !(1..=65536).contains(&self.max_admission_sources)
            || !(1..=100_000).contains(&self.handshakes_per_ip_per_second)
            || !self.per_connection.validate()
            || !self.global.validate()
        {
            return Err(ConfigError::Limits);
        }
        let datagram_size =
            (protocol::HEADER_SIZE + self.max_payload.max(protocol::Welcome::SIZE)) as u32;
        if self.per_connection.bytes_per_second < datagram_size
            || self.global.bytes_per_second < datagram_size
        {
            return Err(ConfigError::Limits);
        }
        if self.heartbeat_interval < Duration::from_millis(10)
            || self.idle_timeout > Duration::from_secs(3600)
            || self.idle_timeout < self.heartbeat_interval.saturating_mul(3)
        {
            return Err(ConfigError::Timers);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ConfigError {
    #[error("Specify a nonzero game ID and 1..64 distinct nonzero application versions")]
    Application,
    #[error("Connection, payload, channel or traffic limits are invalid")]
    Limits,
    #[error(
        "Heartbeat must be at least 10ms, idle timeout at least three heartbeats and at most 1h"
    )]
    Timers,
}
