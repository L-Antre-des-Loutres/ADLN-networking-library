use crate::secrets;
use crate::token::{self, TokenSource};
use adln_networking::{
    GameId,
    auth::{Credential, CredentialStore, DeviceId, Identity, Lookup, LookupError, Secret},
};
use reqwest::{Client, Url, header::AUTHORIZATION};
use serde::Deserialize;
use std::{io, path::PathBuf, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct PocketBase {
    inner: Arc<Inner>,
}
struct Inner {
    client: Client,
    base: Url,
    wrapping: Secret,
    token: TokenSource,
}

pub(crate) fn base_url(value: &str) -> io::Result<Url> {
    let url = Url::parse(value).map_err(|_| io::Error::other("Invalid PocketBase URL"))?;
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if !(url.scheme() == "https" || url.scheme() == "http" && loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().ends_with('/')
    {
        return Err(io::Error::other(
            "PocketBase URL must end with / and use HTTPS (HTTP allowed only on loopback), without credentials, query or fragment",
        ));
    }
    Ok(url)
}
impl PocketBase {
    pub fn new(url: &str, bearer: &str, wrapping: Secret) -> io::Result<Self> {
        Self::with_source(
            url,
            TokenSource::Fixed(token::header(bearer.as_bytes())?),
            wrapping,
        )
    }

    /// Replace the token file atomically to rotate credentials without stopping
    /// the service. Mount its parent directory when running in a container:
    /// a bind mount of a single file can keep referring to its old inode.
    pub async fn from_token_file(url: &str, path: PathBuf, wrapping: Secret) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::other(
                "PocketBase token file path must be absolute",
            ));
        }
        let source = TokenSource::File(path);
        source.header().await?;
        Self::with_source(url, source, wrapping)
    }

    fn with_source(url: &str, token: TokenSource, wrapping: Secret) -> io::Result<Self> {
        let base = base_url(url)?;
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .connect_timeout(Duration::from_secs(1))
            .no_proxy()
            .build()
            .map_err(|_| io::Error::other("Could not initialize PocketBase HTTPS client"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                client,
                base,
                wrapping,
                token,
            }),
        })
    }
    async fn fetch(&self, device: DeviceId, game: GameId) -> Result<Credential, LookupError> {
        let authorization = self
            .inner
            .token
            .header()
            .await
            .map_err(|_| LookupError::Unavailable)?;
        let url = self
            .inner
            .base
            .join(&format!(
                "api/collections/adln_devices/records/{}",
                device.as_str()
            ))
            .map_err(|_| LookupError::Unavailable)?;
        let mut response = self
            .inner
            .client
            .get(url)
            .header(AUTHORIZATION, authorization)
            .query(&[("expand", "player,player.platform")])
            .send()
            .await
            .map_err(|_| LookupError::Unavailable)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(LookupError::Denied);
        }
        if response.status() != reqwest::StatusCode::OK {
            return Err(LookupError::Unavailable);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| LookupError::Unavailable)?
        {
            if bytes.len() + chunk.len() > 65536 {
                return Err(LookupError::Unavailable);
            }
            bytes.extend(chunk);
        }
        let record: Device = serde_json_from_slice(&bytes)?;
        let player = record.expand.player;
        let game =
            String::from_utf8(game.0.to_le_bytes().to_vec()).map_err(|_| LookupError::Denied)?;
        if record.id != device.as_str()
            || record.revoked
            || !record.games.contains(&game)
            || player.id != record.player
            || DeviceId::parse(&player.id).is_none()
            || DeviceId::parse(&player.discord_user).is_none()
            || DeviceId::parse(&player.platform).is_none()
            || player.platform != player.expand.platform.id
            || player.expand.platform.name != "DS Games"
            || player.account_id.trim().is_empty()
            || player.account_id.len() > 128
        {
            return Err(LookupError::Denied);
        }
        let secret = secrets::open(
            &self.inner.wrapping,
            &device,
            &player.id,
            &record.secret_ciphertext,
        )
        .ok_or(LookupError::Denied)?;
        Ok(Credential {
            secret,
            identity: Identity {
                device,
                player: player.id,
                account_id: player.account_id,
            },
        })
    }
}
impl CredentialStore for PocketBase {
    fn lookup(&self, device: DeviceId, game: GameId) -> Lookup {
        let this = self.clone();
        Box::pin(async move { this.fetch(device, game).await })
    }
}
fn serde_json_from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, LookupError> {
    // reqwest's JSON helper cannot bound the response body before allocation.
    serde_json::from_slice(bytes).map_err(|_| LookupError::Unavailable)
}
// Missing fields/expansions fail closed; revoked and games must be explicit.
#[derive(Deserialize)]
struct Device {
    id: String,
    player: String,
    secret_ciphertext: String,
    revoked: bool,
    games: Vec<String>,
    expand: DeviceExpansion,
}
#[derive(Deserialize)]
struct DeviceExpansion {
    player: Player,
}
#[derive(Deserialize)]
struct Player {
    id: String,
    account_id: String,
    discord_user: String,
    platform: String,
    expand: PlayerExpansion,
}
#[derive(Deserialize)]
struct PlayerExpansion {
    platform: Platform,
}
#[derive(Deserialize)]
struct Platform {
    id: String,
    name: String,
}
