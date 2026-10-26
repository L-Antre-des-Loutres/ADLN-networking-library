use reqwest::Url;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

// Only static categories and an HTTP status are logged. Never store or format
// request errors, device IDs, Authorization headers or PocketBase response data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Issue {
    TokenSource,
    Timeout,
    Connection,
    Request,
    Http(u16),
    BodyRead,
    BodyTooLarge,
    InvalidResponse,
}
impl Issue {
    pub fn request(error: &reqwest::Error) -> Self {
        if error.is_timeout() {
            Self::Timeout
        } else if error.is_connect() {
            Self::Connection
        } else {
            Self::Request
        }
    }
    fn description(self) -> (&'static str, &'static str) {
        match self {
            Self::TokenSource => (
                "service_token_unavailable",
                "Cannot read the PocketBase service token, or its contents are invalid.",
            ),
            Self::Timeout => (
                "timeout",
                "PocketBase request timed out. Check its address, port and connectivity.",
            ),
            Self::Connection => (
                "connection_failed",
                "Cannot connect to PocketBase. Check hostname/DNS, port, Docker network and TLS certificate.",
            ),
            Self::Request => (
                "request_failed",
                "PocketBase request failed before receiving a response.",
            ),
            Self::Http(401) => (
                "service_token_rejected",
                "PocketBase rejected the service token. It may be invalid or expired.",
            ),
            Self::Http(403) => (
                "permission_denied",
                "PocketBase denied access. Check the service account and collection API rules.",
            ),
            Self::Http(_) => (
                "http_error",
                "PocketBase returned an unexpected HTTP status. Check its address, reverse proxy and availability.",
            ),
            Self::BodyRead => (
                "response_read_failed",
                "Cannot read the PocketBase response.",
            ),
            Self::BodyTooLarge => (
                "response_too_large",
                "PocketBase response exceeded the allowed size.",
            ),
            Self::InvalidResponse => (
                "invalid_response",
                "PocketBase returned invalid account data. Check collection schemas and access to expanded player/platform records.",
            ),
        }
    }
}

#[derive(Default)]
struct State {
    initialized: bool,
    outage: Option<Outage>,
}
struct Outage {
    started: Instant,
    reported: Issue,
    reported_at: Instant,
    failures: u64,
}
#[derive(Default)]
pub(crate) struct Diagnostics(Mutex<State>);
impl Diagnostics {
    pub fn failure(&self, backend: &Url, operation: &'static str, issue: Issue) {
        let now = Instant::now();
        let emit = {
            let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            state.initialized = true;
            if let Some(outage) = &mut state.outage {
                outage.failures = outage.failures.saturating_add(1);
                // Repeated failures remain quiet. A changed cause can be reported
                // at most once per 30 seconds while the outage continues.
                if outage.reported != issue
                    && now.duration_since(outage.reported_at) >= Duration::from_secs(30)
                {
                    outage.reported = issue;
                    outage.reported_at = now;
                    true
                } else {
                    false
                }
            } else {
                state.outage = Some(Outage {
                    started: now,
                    reported: issue,
                    reported_at: now,
                    failures: 1,
                });
                true
            }
        };
        if !emit {
            return;
        }
        let (reason, message) = issue.description();
        // Include only the origin, never paths, user info, queries or device IDs.
        let backend = backend.origin().ascii_serialization();
        if let Issue::Http(status) = issue {
            tracing::warn!(event = "pocketbase_unavailable", %backend, operation, reason, http_status = status, message);
        } else {
            tracing::warn!(event = "pocketbase_unavailable", %backend, operation, reason, message);
        }
    }
    pub fn success(&self, backend: &Url, operation: &'static str) {
        let (first, outage) = {
            let mut state = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
            let first = !state.initialized;
            state.initialized = true;
            (first, state.outage.take())
        };
        let backend = backend.origin().ascii_serialization();
        if let Some(outage) = outage {
            tracing::info!(event = "pocketbase_recovered", %backend, operation,
                failed_requests = outage.failures, outage_seconds = outage.started.elapsed().as_secs(),
                message = "PocketBase requests are succeeding again.");
        } else if first {
            tracing::info!(event = "pocketbase_reachable", %backend, operation,
                message = "PocketBase responded successfully. A health check does not validate account permissions.");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::{
        io::{self, Write},
        sync::Arc,
    };

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn logs_transitions_without_spam_and_never_formats_sensitive_url_parts() {
        let captured = Capture::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .flatten_event(true)
            .without_time()
            .with_target(false)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let backend = Url::parse(
            "https://user:PRIVATE-PASSWORD@pb.invalid/private-device?token=PRIVATE-TOKEN",
        )
        .unwrap();
        let diagnostics = Diagnostics::default();
        tracing::subscriber::with_default(subscriber, || {
            diagnostics.success(&backend, "startup_health");
            for _ in 0..100 {
                diagnostics.success(&backend, "credential_lookup");
            }
            for _ in 0..101 {
                diagnostics.failure(&backend, "credential_lookup", Issue::Connection);
            }
            diagnostics.failure(&backend, "credential_lookup", Issue::Http(401));
            diagnostics.success(&backend, "credential_lookup");
            diagnostics.failure(&backend, "credential_lookup", Issue::Http(401));
            diagnostics.success(&backend, "credential_lookup");
        });
        let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for private in [
            "PRIVATE-PASSWORD",
            "PRIVATE-TOKEN",
            "private-device",
            "user:",
        ] {
            assert!(!output.contains(private));
        }
        let events: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0]["event"], "pocketbase_reachable");
        assert_eq!(events[1]["reason"], "connection_failed");
        assert_eq!(events[2]["event"], "pocketbase_recovered");
        assert_eq!(events[2]["failed_requests"], 102);
        assert_eq!(events[3]["reason"], "service_token_rejected");
        assert_eq!(events[3]["http_status"], 401);
        assert_eq!(events[4]["event"], "pocketbase_recovered");
    }
}
