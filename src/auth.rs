//! Optional device authentication. ADLN/1 remains anonymous; ADLN/2 appends a
//! 32-byte HMAC-SHA256 to the same header/payload. Nothing is encrypted.
//! AuthHello = Hello (20 bytes) + public device ID (15 ASCII bytes),
//! with a zero tag. Challenge = that request + random 32 bytes + Welcome (32).
//! Its tag uses the device secret. HKDF binds both directional session keys to
//! the complete challenge header/payload. Proof has no payload; Accepted carries
//! Welcome. Both use session keys. Never fall back to anonymous after failure.
//! Clients must check the echoed request and use a fresh nonce for each new login
//! (reuse it only for retries), verify Challenge before deriving keys, and verify
//! Accepted before entering the game. Use separate replay windows per channel
//! and control stream, and abandon a session before SEQUENCE_LIMIT. A saved
//! credential is a bearer secret at rest: copying a save copies its identity.
use crate::{
    GameId,
    protocol::{Hello, Packet, ProtocolError},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{fmt, future::Future, pin::Pin};
use zeroize::Zeroizing;

pub const VERSION: u8 = 2;
pub const TAG_SIZE: usize = 32;
pub const HELLO_SIZE: usize = Hello::SIZE + 15;
pub const CHALLENGE_SIZE: usize = HELLO_SIZE + 32 + crate::protocol::Welcome::SIZE;
// End a linked connection before sequence wrap; never reuse a session sequence.
pub const SEQUENCE_LIMIT: u32 = 0x7fff_ffff;
const MAC_DOMAIN: &[u8] = b"ADLN/2 authenticated datagram\0";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeviceId(String);
impl DeviceId {
    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 15
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
        .then(|| Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct Secret(Zeroizing<[u8; 32]>);
impl Secret {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub device: DeviceId,
    /// PocketBase players record ID, never supplied by the client.
    pub player: String,
    /// Existing platform account_id; not the Discord ID.
    pub account_id: String,
}
pub struct Credential {
    pub identity: Identity,
    pub secret: Secret,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    Denied,
    Unavailable,
}
pub type Lookup = Pin<Box<dyn Future<Output = Result<Credential, LookupError>> + Send>>;
/// Backends must be asynchronous. The endpoint bounds concurrency and lookup time.
pub trait CredentialStore: Send + Sync {
    fn lookup(&self, device: DeviceId, game: GameId) -> Lookup;
}

pub struct Keys {
    pub client: Secret,
    pub server: Secret,
}
impl Keys {
    pub fn derive(secret: &Secret, challenge: &Packet) -> Result<Self, ProtocolError> {
        let context = challenge.encode_version(VERSION)?;
        let hkdf = Hkdf::<Sha256>::new(Some(b"ADLN/2 device session\0"), secret.as_bytes());
        let mut output = Zeroizing::new([0u8; 64]);
        hkdf.expand(&context, output.as_mut())
            .expect("64 bytes is a valid HKDF output");
        Ok(Self {
            client: Secret::new(output[..32].try_into().unwrap()),
            server: Secret::new(output[32..].try_into().unwrap()),
        })
    }
}

pub fn hello_payload(hello: Hello, device: &DeviceId) -> Vec<u8> {
    let mut bytes = hello.encode();
    bytes.extend(device.as_str().as_bytes());
    bytes
}
pub fn parse_hello(bytes: &[u8]) -> Option<(Hello, DeviceId)> {
    if bytes.len() != HELLO_SIZE {
        return None;
    }
    Some((
        Hello::decode(&bytes[..Hello::SIZE]).ok()?,
        DeviceId::parse(std::str::from_utf8(&bytes[Hello::SIZE..]).ok()?)?,
    ))
}

pub fn encode(packet: &Packet, key: Option<&Secret>) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = packet.encode_version(VERSION)?;
    let tag = key.map(|key| tag(key, &bytes)).unwrap_or([0; TAG_SIZE]);
    bytes.extend(tag);
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<Packet, ProtocolError> {
    let end = bytes
        .len()
        .checked_sub(TAG_SIZE)
        .ok_or(ProtocolError::Length)?;
    Packet::decode_version(&bytes[..end], VERSION)
}
pub fn verify(bytes: &[u8], key: &Secret) -> bool {
    let Some(end) = bytes.len().checked_sub(TAG_SIZE) else {
        return false;
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC key size");
    mac.update(MAC_DOMAIN);
    mac.update(&bytes[..end]);
    mac.verify_slice(&bytes[end..]).is_ok()
}
fn tag(key: &Secret, bytes: &[u8]) -> [u8; TAG_SIZE] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC key size");
    mac.update(MAC_DOMAIN);
    mac.update(bytes);
    mac.finalize().into_bytes().into()
}
