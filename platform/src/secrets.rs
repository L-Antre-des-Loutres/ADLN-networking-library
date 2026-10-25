//! Recoverable device secrets use AES-256-GCM under a VPS-held wrapping key.
//! Format: "v1." + URL-safe unpadded base64(nonce[12] || ciphertext[32] || tag[16]).
//! AAD binds the ciphertext to both its public device ID and players record ID.
//! Only a trusted provisioning backend should call seal; output is stored in
//! adln_devices.secret_ciphertext. A save receives the original device secret.
use adln_networking::auth::{DeviceId, Secret};
use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use std::io;
use zeroize::Zeroizing;

fn aad(device: &DeviceId, player: &str) -> Vec<u8> {
    format!("ADLN/device-secret/1\0{}\0{player}", device.as_str()).into_bytes()
}
pub fn seal(key: &Secret, device: &DeviceId, player: &str, secret: &Secret) -> io::Result<String> {
    let mut nonce = [0; 12];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| io::Error::other("Device secret nonce generation failed"))?;
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("32 byte AES key");
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: secret.as_bytes(),
                aad: &aad(device, player),
            },
        )
        .map_err(|_| io::Error::other("Device secret encryption failed"))?;
    let mut envelope = nonce.to_vec();
    envelope.extend(encrypted);
    Ok(format!("v1.{}", URL_SAFE_NO_PAD.encode(envelope)))
}
pub fn open(key: &Secret, device: &DeviceId, player: &str, envelope: &str) -> Option<Secret> {
    // Reject before decoding to bound allocation even for malformed DB records.
    if envelope.len() != 83 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(envelope.strip_prefix("v1.")?).ok()?;
    if bytes.len() != 60 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).ok()?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&bytes[..12]),
                Payload {
                    msg: &bytes[12..],
                    aad: &aad(device, player),
                },
            )
            .ok()?,
    );
    Some(Secret::new(plain.as_slice().try_into().ok()?))
}
