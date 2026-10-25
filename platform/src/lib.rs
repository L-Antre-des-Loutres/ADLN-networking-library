//! Server-only account storage. Keep the PocketBase service token and wrapping
//! key on the VPS; never include them in a ROM, save or browser bundle.
//! Existing players/discord_users/platforms collections are read without mutation.
mod pocketbase;
pub mod secrets;
mod token;
pub use pocketbase::PocketBase;

use adln_networking::auth::{CredentialStore, Secret};
use serde::Deserialize;
use std::{io, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

/// Presence of [accounts] opts in; omission keeps anonymous-only operation.
/// Environment values are deliberately never part of a serializable config.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub pocketbase_url: String,
    #[serde(default = "token_env")]
    pub token_env: String,
    /// Reloaded at every login. Takes precedence over the startup-only token_env.
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    #[serde(default = "key_env")]
    pub wrapping_key_env: String,
}
fn token_env() -> String {
    "ADLN_POCKETBASE_TOKEN".into()
}
fn key_env() -> String {
    "ADLN_DEVICE_WRAPPING_KEY".into()
}
impl Config {
    pub fn validate(&self) -> io::Result<()> {
        pocketbase::base_url(&self.pocketbase_url)?;
        if self
            .token_file
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(io::Error::other(
                "PocketBase token file path must be absolute",
            ));
        }
        for name in [&self.token_env, &self.wrapping_key_env] {
            if name.is_empty()
                || name.len() > 128
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err(io::Error::other(
                    "Account environment variable names must use A-Z, 0-9 or underscore",
                ));
            }
        }
        if self.token_env == self.wrapping_key_env {
            return Err(io::Error::other(
                "Account secrets require distinct environment variables",
            ));
        }
        Ok(())
    }
    /// Loads secrets only at actual startup, not during --check-config.
    pub async fn connect(&self) -> io::Result<Arc<dyn CredentialStore>> {
        self.validate()?;
        let token = if self.token_file.is_none() {
            Some(Zeroizing::new(std::env::var(&self.token_env).map_err(
                |_| io::Error::other("PocketBase service token environment variable is missing"),
            )?))
        } else {
            None
        };
        let key = Zeroizing::new(std::env::var(&self.wrapping_key_env).map_err(|_| {
            io::Error::other("Device wrapping key environment variable is missing")
        })?);
        let mut bytes = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(key.as_bytes(), bytes.as_mut()).map_err(|_| {
            io::Error::other("Device wrapping key must be 64 hexadecimal characters")
        })?;
        let store = if let Some(path) = &self.token_file {
            PocketBase::from_token_file(&self.pocketbase_url, path.clone(), Secret::new(*bytes))
                .await?
        } else {
            PocketBase::new(
                &self.pocketbase_url,
                token.as_ref().unwrap().as_str(),
                Secret::new(*bytes),
            )?
        };
        Ok(Arc::new(store))
    }
}
