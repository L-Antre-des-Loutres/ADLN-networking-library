use adln_networking::{
    GameId,
    auth::{CredentialStore, DeviceId, LookupError, Secret},
};
use adln_platform::{PocketBase, secrets};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

fn device() -> DeviceId {
    DeviceId::parse("device000000001").unwrap()
}
fn key() -> Secret {
    Secret::new([7; 32])
}
fn record() -> Value {
    json!({"id":"device000000001", "player":"player000000001", "revoked":false,
        "games":["MKDS"], "secret_ciphertext":secrets::seal(&key(), &device(), "player000000001", &Secret::new([42;32])).unwrap(),
        "expand":{"player":{"id":"player000000001", "account_id":"assigned-by-our-service",
            "discord_user":"discord00000001", "platform":"platform0000001",
            "expand":{"platform":{"id":"platform0000001", "name":"DS Games"}}}}})
}
async fn backend(status: u16, body: String) -> (PocketBase, tokio::task::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let n = socket.read(&mut buffer).await.unwrap();
            assert_ne!(n, 0);
            request.extend(&buffer[..n]);
            if request.windows(4).any(|s| s == b"\r\n\r\n") {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        // Oversized-response tests can drop the connection before the write finishes.
        let _ = socket.write_all(response.as_bytes()).await;
        String::from_utf8(request).unwrap()
    });
    (
        PocketBase::new(&url, "test-service-token", key()).unwrap(),
        task,
    )
}
async fn lookup(
    status: u16,
    record: Value,
) -> Result<adln_networking::auth::Credential, LookupError> {
    let (store, task) = backend(status, record.to_string()).await;
    let result = store
        .lookup(device(), GameId(u32::from_le_bytes(*b"MKDS")))
        .await;
    task.await.unwrap();
    result
}

#[tokio::test]
async fn reads_existing_ds_account_without_writing_shared_collections() {
    let (store, task) = backend(200, record().to_string()).await;
    let credential = store
        .lookup(device(), GameId(u32::from_le_bytes(*b"MKDS")))
        .await
        .unwrap();
    assert_eq!(credential.identity.account_id, "assigned-by-our-service");
    assert_eq!(credential.identity.player, "player000000001");
    assert_eq!(credential.secret.as_bytes(), &[42; 32]);
    let request = task.await.unwrap();
    assert!(request.starts_with("GET /api/collections/adln_devices/records/device000000001?expand=player%2Cplayer.platform HTTP/1.1\r\n"));
    assert!(
        request
            .to_ascii_lowercase()
            .contains("authorization: test-service-token\r\n")
    );
}

#[tokio::test]
async fn revoked_wrong_game_wrong_platform_and_modified_secret_fail_closed() {
    let mut revoked = record();
    revoked["revoked"] = json!(true);
    let mut wrong_game = record();
    wrong_game["games"] = json!(["HGSS"]);
    let mut platform = record();
    platform["expand"]["player"]["expand"]["platform"]["name"] = json!("Other service");
    let mut account = record();
    account["expand"]["player"]["account_id"] = json!("");
    let mut swapped = record();
    swapped["secret_ciphertext"] =
        json!(secrets::seal(&key(), &device(), "differentplayer", &Secret::new([42; 32])).unwrap());
    for record in [revoked, wrong_game, platform, account, swapped] {
        assert!(matches!(
            lookup(200, record).await,
            Err(LookupError::Denied)
        ));
    }
    assert!(matches!(
        lookup(404, json!({})).await,
        Err(LookupError::Denied)
    ));
    for status in [401, 403, 429, 500, 503] {
        assert!(matches!(
            lookup(status, json!({})).await,
            Err(LookupError::Unavailable)
        ));
    }
    assert!(matches!(
        lookup(200, json!({})).await,
        Err(LookupError::Unavailable)
    ));
}

#[tokio::test]
async fn limits_response_body_and_does_not_follow_redirects() {
    let (store, task) = backend(200, " ".repeat(70000)).await;
    assert!(matches!(
        store.lookup(device(), GameId(1)).await,
        Err(LookupError::Unavailable)
    ));
    task.await.unwrap();
    assert!(matches!(
        lookup(302, json!({})).await,
        Err(LookupError::Unavailable)
    ));
}

#[test]
fn secret_envelopes_bind_device_player_and_wrapping_key() {
    let ciphertext =
        secrets::seal(&key(), &device(), "player000000001", &Secret::new([42; 32])).unwrap();
    assert_eq!(
        secrets::open(&key(), &device(), "player000000001", &ciphertext)
            .unwrap()
            .as_bytes(),
        &[42; 32]
    );
    assert!(secrets::open(&key(), &device(), "someone-else", &ciphertext).is_none());
    assert!(
        secrets::open(
            &key(),
            &DeviceId::parse("device000000002").unwrap(),
            "player000000001",
            &ciphertext
        )
        .is_none()
    );
    assert!(
        secrets::open(
            &Secret::new([9; 32]),
            &device(),
            "player000000001",
            &ciphertext
        )
        .is_none()
    );
    for malformed in ["", "v1.invalid", &"x".repeat(100000)] {
        assert!(secrets::open(&key(), &device(), "player000000001", malformed).is_none());
    }
    assert_ne!(
        ciphertext,
        secrets::seal(&key(), &device(), "player000000001", &Secret::new([42; 32])).unwrap()
    );
}

#[test]
fn refuses_insecure_remote_storage_and_secret_bearing_urls() {
    for url in [
        "http://example.com/",
        "https://user:password@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#fragment",
        "https://example.com/pb",
    ] {
        assert!(PocketBase::new(url, "token", key()).is_err());
    }
    assert!(PocketBase::new("https://example.com/pb/", "token", key()).is_ok());
    assert!(PocketBase::new("http://[::1]:8090/", "token", key()).is_ok());
}

#[test]
fn private_http_requires_explicit_opt_in_and_keeps_url_credentials_disallowed() {
    let config = |url: &str, allow_http: bool| {
        serde_json::from_value::<adln_platform::Config>(json!({
            "pocketbase_url": url, "allow_http": allow_http,
        }))
        .unwrap()
    };
    assert!(config("http://pocketbase:8090/", false).validate().is_err());
    assert!(config("http://pocketbase:8090/", true).validate().is_ok());
    let default: adln_platform::Config = serde_json::from_value(json!({
        "pocketbase_url":"http://pocketbase:8090/",
    }))
    .unwrap();
    assert!(!default.allow_http);
    assert!(default.validate().is_err());
    for url in [
        "http://user:password@pocketbase:8090/",
        "http://pocketbase:8090/?token=secret",
        "http://pocketbase:8090/#fragment",
        "http://pocketbase:8090/pb",
        "ftp://pocketbase/",
    ] {
        assert!(config(url, true).validate().is_err());
    }
}

struct TokenFile {
    directory: std::path::PathBuf,
    path: std::path::PathBuf,
}
impl TokenFile {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("adln-token-test-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("pocketbase.token");
        std::fs::write(&path, "expired-service-token").unwrap();
        Self { directory, path }
    }
    fn replace(&self, bytes: &[u8]) {
        let next = self.directory.join("next.token");
        std::fs::write(&next, bytes).unwrap();
        std::fs::rename(next, &self.path).unwrap();
    }
}
impl Drop for TokenFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.directory.join("next.token"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}

async fn rotating_backend(
    replies: Vec<(u16, &'static str)>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for (status, expected_token) in replies {
            let (mut socket, _) =
                tokio::time::timeout(std::time::Duration::from_secs(3), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let n = socket.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                request.extend(&buffer[..n]);
                if request.windows(4).any(|s| s == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.contains(&format!("authorization: {expected_token}\r\n")));
            let body = if status == 200 {
                record().to_string()
            } else {
                "{}".into()
            };
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (url, task)
}

#[tokio::test]
async fn rotated_token_recovers_from_expiration_without_rebuilding_the_adapter() {
    let file = TokenFile::new();
    let (url, task) = rotating_backend(vec![
        (401, "expired-service-token"),
        (200, "renewed-service-token"),
        (200, "renewed-service-token"),
    ])
    .await;
    let store = PocketBase::from_token_file(&url, file.path.clone(), key())
        .await
        .unwrap();
    let clone = store.clone();
    let game = GameId(u32::from_le_bytes(*b"MKDS"));
    assert!(matches!(
        store.lookup(device(), game).await,
        Err(LookupError::Unavailable)
    ));
    file.replace(b"renewed-service-token\n");
    assert_eq!(
        clone
            .lookup(device(), game)
            .await
            .unwrap()
            .identity
            .account_id,
        "assigned-by-our-service"
    );
    assert!(store.lookup(device(), game).await.is_ok());
    task.await.unwrap();
}

#[tokio::test]
async fn broken_rotations_fail_closed_and_a_later_valid_file_recovers() {
    let file = TokenFile::new();
    let (url, task) = rotating_backend(vec![(200, "renewed-service-token")]).await;
    let store = PocketBase::from_token_file(&url, file.path.clone(), key())
        .await
        .unwrap();
    let game = GameId(u32::from_le_bytes(*b"MKDS"));
    std::fs::remove_file(&file.path).unwrap();
    assert!(matches!(
        store.lookup(device(), game).await,
        Err(LookupError::Unavailable)
    ));
    for invalid in [
        b"".to_vec(),
        b"bad\rtoken".to_vec(),
        vec![b'x'; 9000],
        vec![0xff],
    ] {
        file.replace(&invalid);
        assert!(matches!(
            store.lookup(device(), game).await,
            Err(LookupError::Unavailable)
        ));
    }
    file.replace(b"renewed-service-token");
    assert!(store.lookup(device(), game).await.is_ok());
    task.await.unwrap();
}

#[tokio::test]
async fn token_file_startup_rejects_missing_empty_or_relative_sources() {
    let file = TokenFile::new();
    let url = "http://127.0.0.1:8090/";
    assert!(
        PocketBase::from_token_file(url, file.directory.clone(), key())
            .await
            .is_err()
    );
    assert!(
        PocketBase::from_token_file(url, "relative.token".into(), key())
            .await
            .is_err()
    );
    file.replace(b"");
    assert!(
        PocketBase::from_token_file(url, file.path.clone(), key())
            .await
            .is_err()
    );
    std::fs::remove_file(&file.path).unwrap();
    assert!(
        PocketBase::from_token_file(url, file.path.clone(), key())
            .await
            .is_err()
    );
}
