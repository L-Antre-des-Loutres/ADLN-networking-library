//! Anonymous, ADLN transport for independent game services.
//! Applications own their state, routing and timers. No game grouping, player
//! host, account backend, logging loop or background runtime is imposed.
//! UDP payloads are not encrypted. Connection tokens are not account credentials.
mod config;
mod endpoint;
mod limit;
pub mod protocol;
mod replay;
mod types;

pub use config::{ConfigError, ServerConfig, TrafficLimits};
pub use endpoint::{Endpoint, SendError, Statistics};
pub use types::{Connection, ConnectionId, DisconnectReason, Event, GameId};
