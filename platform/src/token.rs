use reqwest::header::HeaderValue;
use std::{
    io,
    path::{Path, PathBuf},
};
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

const MAX_TOKEN_BYTES: usize = 8192;

/// Read a token for each lookup so replacing the file also works for clones of
/// the adapter. No stale-token fallback: a broken rotation denies new logins.
pub(crate) enum TokenSource {
    Fixed(HeaderValue),
    File(PathBuf),
}

impl TokenSource {
    pub async fn header(&self) -> io::Result<HeaderValue> {
        match self {
            Self::Fixed(value) => Ok(value.clone()),
            Self::File(path) => read_file(path).await,
        }
    }
}

pub(crate) fn header(bytes: &[u8]) -> io::Result<HeaderValue> {
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(io::Error::other("PocketBase service token is too large"));
    }
    let value = std::str::from_utf8(bytes)
        .map_err(|_| io::Error::other("Invalid PocketBase service token"))?
        .trim();
    if value.is_empty() {
        return Err(io::Error::other("PocketBase service token is empty"));
    }
    let mut header = HeaderValue::from_str(value)
        .map_err(|_| io::Error::other("Invalid PocketBase service token"))?;
    header.set_sensitive(true);
    Ok(header)
}

async fn read_file(path: &Path) -> io::Result<HeaderValue> {
    if !tokio::fs::metadata(path)
        .await
        .map_err(|_| io::Error::other("Could not inspect PocketBase token file"))?
        .is_file()
    {
        return Err(io::Error::other(
            "PocketBase token file must be a regular file",
        ));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|_| io::Error::other("Could not open PocketBase token file"))?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take((MAX_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| io::Error::other("Could not read PocketBase token file"))?;
    header(&bytes)
}
