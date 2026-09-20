use futures_util::Stream;
use serde::Serialize;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use url::Url;

pub const ROUTE_DEFAULT_SYSTEM: &str = "default_system";
pub const ROUTE_EXPLICIT_PROXY: &str = "explicit_proxy";
pub const ROUTE_EMBEDDED_WARP: &str = "embedded_warp";
pub const ROUTE_MANUAL_PROXY: &str = "manual_proxy";
static LOG_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const MAX_LOGS: usize = 80;
const MAX_TOKEN_FETCH_LOGS: usize = 30;
const UNSET_MILLIS: u64 = u64::MAX;
const STREAM_AWAITING: u8 = 0;
const STREAM_ACTIVE: u8 = 1;
const STREAM_FINISHING: u8 = 2;
const STREAM_COMPLETED: u8 = 3;
const STREAM_ERROR: u8 = 4;
const STREAM_CANCELLED: u8 = 5;

#[derive(Debug)]
pub struct StreamLifecycle {
    started: Instant,
    response_header_ms: u64,
    state: AtomicU8,
    first_chunk_ms: AtomicU64,
    last_chunk_ms: AtomicU64,
    stream_total_ms: AtomicU64,
    stream_bytes: AtomicU64,
    stream_chunks: AtomicU64,
    max_idle_ms: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamLifecycleSnapshot {
    pub state: &'static str,
    pub first_chunk_ms: Option<u128>,
    pub last_chunk_ms: Option<u128>,
    pub stream_total_ms: Option<u128>,
    pub stream_bytes: u64,
    pub stream_chunks: u64,
    pub max_idle_ms: Option<u128>,
    pub current_idle_ms: Option<u128>,
}

impl StreamLifecycle {
    pub fn new(started: Instant, response_header_ms: u128) -> Self {
        let response_header_ms = millis_to_u64(response_header_ms);
        Self {
            started,
            response_header_ms,
            state: AtomicU8::new(STREAM_AWAITING),
            first_chunk_ms: AtomicU64::new(UNSET_MILLIS),
            last_chunk_ms: AtomicU64::new(UNSET_MILLIS),
            stream_total_ms: AtomicU64::new(UNSET_MILLIS),
            stream_bytes: AtomicU64::new(0),
            stream_chunks: AtomicU64::new(0),
            max_idle_ms: AtomicU64::new(0),
        }
    }

    pub fn observe_chunk(&self, bytes: usize) {
        loop {
            match self.state.load(Ordering::Acquire) {
                STREAM_AWAITING => {
                    if self
                        .state
                        .compare_exchange(
                            STREAM_AWAITING,
                            STREAM_ACTIVE,
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .is_ok()
                    {
                        break;
                    }
                }
                STREAM_ACTIVE => break,
                _ => return,
            }
        }

        let elapsed_ms = elapsed_millis(self.started.elapsed());
        self.stream_bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
        self.stream_chunks.fetch_add(1, Ordering::Relaxed);
        let previous_ms = self.last_chunk_ms.swap(elapsed_ms, Ordering::Relaxed);
        let idle_start_ms = if previous_ms == UNSET_MILLIS {
            self.response_header_ms
        } else {
            previous_ms
        };
        self.max_idle_ms
            .fetch_max(elapsed_ms.saturating_sub(idle_start_ms), Ordering::Relaxed);
        let _ = self.first_chunk_ms.compare_exchange(
            UNSET_MILLIS,
            elapsed_ms,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    pub fn complete(&self) {
        self.finish(STREAM_COMPLETED);
    }

    pub fn error(&self) {
        self.finish(STREAM_ERROR);
    }

    pub fn cancel(&self) {
        self.finish(STREAM_CANCELLED);
    }

    pub fn snapshot(&self) -> StreamLifecycleSnapshot {
        let state = self.state.load(Ordering::Acquire);
        let elapsed_ms = elapsed_millis(self.started.elapsed());
        let chunks = self.stream_chunks.load(Ordering::Relaxed);
        let last_chunk_ms = self.last_chunk_ms.load(Ordering::Relaxed);
        StreamLifecycleSnapshot {
            state: match state {
                STREAM_AWAITING => "awaiting_first_chunk",
                STREAM_ACTIVE | STREAM_FINISHING => "streaming",
                STREAM_COMPLETED => "completed",
                STREAM_ERROR => "error",
                STREAM_CANCELLED => "cancelled",
                _ => "unknown",
            },
            first_chunk_ms: optional_millis(self.first_chunk_ms.load(Ordering::Relaxed)),
            last_chunk_ms: optional_millis(last_chunk_ms),
            stream_total_ms: optional_millis(self.stream_total_ms.load(Ordering::Relaxed)),
            stream_bytes: self.stream_bytes.load(Ordering::Relaxed),
            stream_chunks: chunks,
            max_idle_ms: (chunks > 0
                || matches!(state, STREAM_COMPLETED | STREAM_ERROR | STREAM_CANCELLED))
            .then(|| u128::from(self.max_idle_ms.load(Ordering::Relaxed))),
            current_idle_ms: matches!(state, STREAM_AWAITING | STREAM_ACTIVE | STREAM_FINISHING)
                .then(|| {
                    let last_activity_ms = if last_chunk_ms == UNSET_MILLIS {
                        self.response_header_ms
                    } else {
                        last_chunk_ms
                    };
                    u128::from(elapsed_ms.saturating_sub(last_activity_ms))
                }),
        }
    }

    fn finish(&self, final_state: u8) {
        loop {
            let state = self.state.load(Ordering::Acquire);
            if !matches!(state, STREAM_AWAITING | STREAM_ACTIVE) {
                return;
            }
            if self
                .state
                .compare_exchange(
                    state,
                    STREAM_FINISHING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }
        let elapsed_ms = elapsed_millis(self.started.elapsed());
        let last_chunk_ms = self.last_chunk_ms.load(Ordering::Relaxed);
        let last_activity_ms = if last_chunk_ms == UNSET_MILLIS {
            self.response_header_ms
        } else {
            last_chunk_ms
        };
        self.max_idle_ms
            .fetch_max(elapsed_ms.saturating_sub(last_activity_ms), Ordering::Relaxed);
        self.stream_total_ms.store(elapsed_ms, Ordering::Relaxed);
        self.state.store(final_state, Ordering::Release);
    }
}

pub struct ObservedStream<S> {
    inner: Pin<Box<S>>,
    lifecycle: Arc<StreamLifecycle>,
    finished: bool,
}

impl<S> ObservedStream<S> {
    pub fn new(stream: S, lifecycle: Arc<StreamLifecycle>) -> Self {
        Self {
            inner: Box::pin(stream),
            lifecycle,
            finished: false,
        }
    }
}

impl<S, B, E> Stream for ObservedStream<S>
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
{
    type Item = Result<B, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                this.lifecycle.observe_chunk(chunk.as_ref().len());
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.finished = true;
                this.lifecycle.error();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.finished = true;
                this.lifecycle.complete();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> Drop for ObservedStream<S> {
    fn drop(&mut self) {
        if !self.finished {
            self.lifecycle.cancel();
        }
    }
}

fn elapsed_millis(duration: Duration) -> u64 {
    millis_to_u64(duration.as_millis())
}

fn millis_to_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX - 1)
}

fn optional_millis(value: u64) -> Option<u128> {
    (value != UNSET_MILLIS).then(|| u128::from(value))
}

#[derive(Clone, Debug, Default)]
pub struct NetworkLogDetails {
    pub flow: String,
    pub transport: String,
    pub target_origin: String,
    pub final_origin: Option<String>,
    pub route_kind: String,
    pub proxy_endpoint: Option<String>,
    pub peer_addr: Option<String>,
    pub http_version: Option<String>,
    pub model: Option<String>,
    pub content_encoding: String,
    pub body_bytes: usize,
    pub turn_state_action: String,
    pub turn_state_len: Option<usize>,
    pub returned_turn_state_len: Option<usize>,
    pub error_kind: Option<String>,
    pub response_status: Option<u16>,
    pub response_header_ms: Option<u128>,
    pub stream_lifecycle: Option<Arc<StreamLifecycle>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub id: u64,
    pub ts: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// Kept for compatibility with older renderers. This is response-header latency.
    pub ms: u128,
    pub response_header_ms: u128,
    pub flow: String,
    pub transport: String,
    pub target_origin: String,
    pub final_origin: Option<String>,
    pub route_kind: String,
    pub proxy_endpoint: Option<String>,
    pub peer_addr: Option<String>,
    pub http_version: Option<String>,
    pub model: Option<String>,
    pub content_encoding: String,
    pub body_bytes: usize,
    pub turn_state_action: String,
    pub turn_state_len: Option<usize>,
    pub returned_turn_state_len: Option<usize>,
    pub error_kind: Option<String>,
    pub stream_state: String,
    pub first_chunk_ms: Option<u128>,
    pub last_chunk_ms: Option<u128>,
    pub stream_total_ms: Option<u128>,
    pub stream_bytes: u64,
    pub stream_chunks: u64,
    pub max_idle_ms: Option<u128>,
    pub current_idle_ms: Option<u128>,
    #[serde(skip)]
    stream_lifecycle: Option<Arc<StreamLifecycle>>,
}

impl LogEntry {
    pub fn new(
        method: &str,
        path: &str,
        status: u16,
        started: Instant,
        details: NetworkLogDetails,
    ) -> Self {
        let response_header_ms = details
            .response_header_ms
            .unwrap_or_else(|| started.elapsed().as_millis());
        let stream_lifecycle = details.stream_lifecycle.clone();
        let stream = stream_lifecycle
            .as_ref()
            .map(|lifecycle| lifecycle.snapshot());
        Self {
            id: LOG_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            ts: chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, false),
            method: method.to_string(),
            path: path.to_string(),
            status,
            ms: response_header_ms,
            response_header_ms,
            flow: details.flow,
            transport: details.transport,
            target_origin: details.target_origin,
            final_origin: details.final_origin,
            route_kind: details.route_kind,
            proxy_endpoint: details.proxy_endpoint,
            peer_addr: details.peer_addr,
            http_version: details.http_version,
            model: details.model,
            content_encoding: details.content_encoding,
            body_bytes: details.body_bytes,
            turn_state_action: details.turn_state_action,
            turn_state_len: details.turn_state_len,
            returned_turn_state_len: details.returned_turn_state_len,
            error_kind: details.error_kind,
            stream_state: stream
                .as_ref()
                .map(|snapshot| snapshot.state)
                .unwrap_or("not_tracked")
                .into(),
            first_chunk_ms: stream.as_ref().and_then(|snapshot| snapshot.first_chunk_ms),
            last_chunk_ms: stream.as_ref().and_then(|snapshot| snapshot.last_chunk_ms),
            stream_total_ms: stream
                .as_ref()
                .and_then(|snapshot| snapshot.stream_total_ms),
            stream_bytes: stream
                .as_ref()
                .map(|snapshot| snapshot.stream_bytes)
                .unwrap_or(0),
            stream_chunks: stream
                .as_ref()
                .map(|snapshot| snapshot.stream_chunks)
                .unwrap_or(0),
            max_idle_ms: stream.as_ref().and_then(|snapshot| snapshot.max_idle_ms),
            current_idle_ms: stream
                .as_ref()
                .and_then(|snapshot| snapshot.current_idle_ms),
            stream_lifecycle,
        }
    }

    pub fn snapshot(&self) -> Self {
        let mut entry = self.clone();
        let Some(lifecycle) = &self.stream_lifecycle else {
            return entry;
        };
        let stream = lifecycle.snapshot();
        entry.stream_state = stream.state.into();
        entry.first_chunk_ms = stream.first_chunk_ms;
        entry.last_chunk_ms = stream.last_chunk_ms;
        entry.stream_total_ms = stream.stream_total_ms;
        entry.stream_bytes = stream.stream_bytes;
        entry.stream_chunks = stream.stream_chunks;
        entry.max_idle_ms = stream.max_idle_ms;
        entry.current_idle_ms = stream.current_idle_ms;
        entry
    }
}

pub fn safe_text(raw: &str, max_chars: usize) -> String {
    raw.trim()
        .chars()
        .filter(|ch| !ch.is_control())
        .take(max_chars)
        .collect()
}

pub fn endpoint_origin(raw: &str) -> String {
    let Ok(url) = Url::parse(raw.trim()) else {
        return "invalid-endpoint".into();
    };
    let Some(host) = url.host_str() else {
        return "invalid-endpoint".into();
    };
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    match url.port_or_known_default() {
        Some(port) => format!("{}://{}:{}", url.scheme(), host, port),
        None => format!("{}://{}", url.scheme(), host),
    }
}

pub fn network_details(upstream: &str, proxy: &str) -> NetworkLogDetails {
    let proxy = proxy.trim();
    NetworkLogDetails {
        flow: "business".into(),
        transport: "http".into(),
        target_origin: endpoint_origin(upstream),
        route_kind: if proxy.is_empty() {
            ROUTE_DEFAULT_SYSTEM.into()
        } else {
            ROUTE_EXPLICIT_PROXY.into()
        },
        proxy_endpoint: (!proxy.is_empty()).then(|| endpoint_origin(proxy)),
        content_encoding: "none".into(),
        turn_state_action: "not_applicable".into(),
        ..NetworkLogDetails::default()
    }
}

pub fn token_network_details(
    upstream: &str,
    proxy: &str,
    embedded_warp: bool,
    model: &str,
) -> NetworkLogDetails {
    NetworkLogDetails {
        flow: "token_fetch".into(),
        transport: "http_sse".into(),
        target_origin: endpoint_origin(upstream),
        route_kind: if embedded_warp {
            ROUTE_EMBEDDED_WARP.into()
        } else {
            ROUTE_MANUAL_PROXY.into()
        },
        proxy_endpoint: Some(endpoint_origin(proxy)),
        model: Some(safe_text(model, 80)).filter(|value| !value.is_empty()),
        content_encoding: "json".into(),
        turn_state_action: "awaiting_response".into(),
        ..NetworkLogDetails::default()
    }
}

pub fn safe_content_encoding(raw: Option<&str>) -> String {
    let value = raw.unwrap_or("none").trim().to_ascii_lowercase();
    match value.as_str() {
        "" | "identity" => "none".into(),
        "gzip" | "br" | "deflate" | "zstd" => value,
        _ => "other".into(),
    }
}

pub fn request_error_kind(error: &reqwest::Error) -> String {
    if error.is_connect() {
        "connect"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_request() {
        "request"
    } else if error.is_body() {
        "body"
    } else if error.is_decode() {
        "decode"
    } else {
        "upstream"
    }
    .into()
}

pub fn push(logs: &mut VecDeque<LogEntry>, entry: LogEntry) {
    if entry.flow == "token_fetch" {
        let token_count = logs
            .iter()
            .filter(|existing| existing.flow == "token_fetch")
            .count();
        if token_count >= MAX_TOKEN_FETCH_LOGS {
            if let Some(index) = logs
                .iter()
                .position(|existing| existing.flow == "token_fetch")
            {
                logs.remove(index);
            }
        } else if logs.len() >= MAX_LOGS {
            logs.pop_front();
        }
    } else if logs.len() >= MAX_LOGS {
        logs.pop_front();
    }
    logs.push_back(entry);
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use futures_util::StreamExt;

    #[test]
    fn endpoint_origin_keeps_route_and_drops_credentials() {
        assert_eq!(
            endpoint_origin("socks5h://user:secret@127.0.0.1:1080/path?token=hidden"),
            "socks5h://127.0.0.1:1080"
        );
        assert_eq!(
            endpoint_origin("https://chatgpt.com/backend-api/codex"),
            "https://chatgpt.com:443"
        );
    }

    #[test]
    fn network_details_distinguishes_explicit_and_default_routes() {
        let direct = network_details("https://chatgpt.com/backend-api/codex", "");
        assert_eq!(direct.route_kind, ROUTE_DEFAULT_SYSTEM);
        assert!(direct.proxy_endpoint.is_none());

        let proxied = network_details(
            "https://chatgpt.com/backend-api/codex",
            "http://user:secret@localhost:7897",
        );
        assert_eq!(proxied.route_kind, ROUTE_EXPLICIT_PROXY);
        assert_eq!(
            proxied.proxy_endpoint.as_deref(),
            Some("http://localhost:7897")
        );
    }

    #[test]
    fn token_details_identify_warp_without_exposing_credentials() {
        let details = token_network_details(
            "https://chatgpt.com/backend-api/codex",
            "socks5h://statekit:private@127.0.0.1:1080",
            true,
            "gpt-6-astra",
        );
        assert_eq!(details.flow, "token_fetch");
        assert_eq!(details.route_kind, ROUTE_EMBEDDED_WARP);
        assert_eq!(
            details.proxy_endpoint.as_deref(),
            Some("socks5h://127.0.0.1:1080")
        );
        assert_eq!(details.model.as_deref(), Some("gpt-6-astra"));
    }

    #[test]
    fn token_details_identify_manual_proxy() {
        let details = token_network_details(
            "https://chatgpt.com/backend-api/codex",
            "socks5h://proxy.example.test:44445",
            false,
            "gpt-6-astra",
        );
        assert_eq!(details.route_kind, ROUTE_MANUAL_PROXY);
        assert_eq!(
            details.proxy_endpoint.as_deref(),
            Some("socks5h://proxy.example.test:44445")
        );
    }

    #[test]
    fn safe_text_removes_log_controls_and_bounds_input() {
        assert_eq!(safe_text("  gpt-6\nastra\t-extra", 12), "gpt-6astra-e");
    }

    #[test]
    fn token_fetch_bursts_do_not_evict_all_business_logs() {
        let mut entries = VecDeque::new();
        for _ in 0..60 {
            push(
                &mut entries,
                LogEntry::new(
                    "POST",
                    "/responses",
                    200,
                    Instant::now(),
                    network_details("https://chatgpt.com", ""),
                ),
            );
        }
        for _ in 0..100 {
            push(
                &mut entries,
                LogEntry::new(
                    "POST",
                    "/responses",
                    502,
                    Instant::now(),
                    token_network_details(
                        "https://chatgpt.com",
                        "socks5h://127.0.0.1:1080",
                        true,
                        "gpt-6-astra",
                    ),
                ),
            );
        }

        assert_eq!(entries.len(), MAX_LOGS);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.flow == "token_fetch")
                .count(),
            MAX_TOKEN_FETCH_LOGS
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.flow == "business")
                .count(),
            MAX_LOGS - MAX_TOKEN_FETCH_LOGS
        );
    }

    #[test]
    fn stream_lifecycle_tracks_chunks_idle_time_and_completion() {
        let started = Instant::now() - Duration::from_millis(80);
        let lifecycle = StreamLifecycle::new(started, 20);
        lifecycle.observe_chunk(12);
        lifecycle.observe_chunk(30);
        lifecycle.complete();

        let snapshot = lifecycle.snapshot();
        assert_eq!(snapshot.state, "completed");
        assert_eq!(snapshot.stream_bytes, 42);
        assert_eq!(snapshot.stream_chunks, 2);
        assert!(snapshot.first_chunk_ms.is_some_and(|ms| ms >= 80));
        assert!(snapshot.last_chunk_ms.is_some_and(|ms| ms >= 80));
        assert!(snapshot.stream_total_ms.is_some_and(|ms| ms >= 80));
        assert!(snapshot.max_idle_ms.is_some_and(|ms| ms >= 60));
    }

    #[test]
    fn terminal_stream_state_cannot_be_overwritten_by_drop_cancellation() {
        let lifecycle = StreamLifecycle::new(Instant::now(), 0);
        lifecycle.observe_chunk(4);
        lifecycle.error();
        lifecycle.cancel();
        assert_eq!(lifecycle.snapshot().state, "error");
    }

    #[test]
    fn terminal_stream_state_includes_silence_before_first_chunk() {
        let started = Instant::now() - Duration::from_millis(80);
        let lifecycle = StreamLifecycle::new(started, 20);
        lifecycle.complete();
        let snapshot = lifecycle.snapshot();
        assert_eq!(snapshot.stream_chunks, 0);
        assert!(snapshot.max_idle_ms.is_some_and(|ms| ms >= 60));
    }

    #[test]
    fn terminal_stream_state_includes_trailing_silence() {
        let lifecycle = StreamLifecycle::new(Instant::now(), 0);
        lifecycle.observe_chunk(1);
        std::thread::sleep(Duration::from_millis(20));
        lifecycle.error();
        assert!(lifecycle.snapshot().max_idle_ms.is_some_and(|ms| ms >= 15));

        let cancelled = StreamLifecycle::new(Instant::now(), 0);
        cancelled.observe_chunk(1);
        std::thread::sleep(Duration::from_millis(20));
        cancelled.cancel();
        assert!(cancelled
            .snapshot()
            .max_idle_ms
            .is_some_and(|ms| ms >= 15));
    }

    #[test]
    fn log_snapshot_reads_live_stream_metrics_without_logging_content() {
        let started = Instant::now();
        let lifecycle = Arc::new(StreamLifecycle::new(started, 7));
        let details = NetworkLogDetails {
            response_header_ms: Some(7),
            stream_lifecycle: Some(lifecycle.clone()),
            ..network_details("https://chatgpt.com", "")
        };
        let entry = LogEntry::new("POST", "/responses", 200, started, details);
        assert_eq!(entry.snapshot().stream_state, "awaiting_first_chunk");

        lifecycle.observe_chunk(128);
        let active = entry.snapshot();
        assert_eq!(active.stream_state, "streaming");
        assert_eq!(active.stream_bytes, 128);
        assert_eq!(active.stream_chunks, 1);

        lifecycle.complete();
        assert_eq!(entry.snapshot().stream_state, "completed");
    }

    #[tokio::test]
    async fn observed_stream_records_success_error_and_downstream_cancellation() {
        let completed = Arc::new(StreamLifecycle::new(Instant::now(), 0));
        let chunks = stream::iter(vec![Ok::<_, &'static str>(vec![1_u8, 2]), Ok(vec![3])]);
        let output: Vec<_> = ObservedStream::new(chunks, completed.clone()).collect().await;
        assert_eq!(output.len(), 2);
        let snapshot = completed.snapshot();
        assert_eq!(snapshot.state, "completed");
        assert_eq!(snapshot.stream_bytes, 3);
        assert_eq!(snapshot.stream_chunks, 2);

        let failed = Arc::new(StreamLifecycle::new(Instant::now(), 0));
        let chunks = stream::iter(vec![Ok::<_, &'static str>(vec![1_u8]), Err("broken")]);
        let output: Vec<_> = ObservedStream::new(chunks, failed.clone()).collect().await;
        assert!(output[1].is_err());
        assert_eq!(failed.snapshot().state, "error");

        let cancelled = Arc::new(StreamLifecycle::new(Instant::now(), 0));
        let stream = ObservedStream::new(stream::pending::<Result<Vec<u8>, &'static str>>(), cancelled.clone());
        drop(stream);
        assert_eq!(cancelled.snapshot().state, "cancelled");
    }
}
