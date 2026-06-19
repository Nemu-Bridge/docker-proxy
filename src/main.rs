use chrono::Local;
use docker_proxy::audit::{AuditEvent, AuditSink};
use docker_proxy::config::ProxyConfig;
use docker_proxy::metrics::Metrics;
use docker_proxy::rules::{
    apply_response_filters, collect_response_filters, evaluate_request_detailed, AuthLimiter,
    EvaluationContext, RateLimiter, RuleResult,
};
use docker_proxy::tls::{self, CertIdentity};
use docker_proxy::upgrade::is_upgrade_request;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    HeaderMap, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use regex::Regex;
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{atomic::Ordering, Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

#[cfg(unix)]
use tokio::net::UnixStream;
use tracing::{error, info, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type HttpResponse = Response<Full<Bytes>>;

const MAX_REQ_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_RESP_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_CONCURRENT_CONNS: usize = 1024;
const MAX_PATH_LEN: usize = 8192;
const MAX_TOKEN_LEN: usize = 4096;
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);
const UPGRADE_IDLE_TIMEOUT: Duration = Duration::from_secs(3600);
const UPGRADE_RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);
const UPGRADE_COPY_BUF_BYTES: usize = 32 * 1024;
const AUTH_FAIL_MAX: u32 = 10;
const AUTH_FAIL_WINDOW: Duration = Duration::from_secs(60);
const AUTH_FAIL_LOCKOUT: Duration = Duration::from_secs(300);

#[cfg(unix)]
type UpstreamIo = TokioIo<UnixStream>;

#[cfg(windows)]
type UpstreamIo = TokioIo<TcpStream>;

#[cfg(unix)]
async fn connect_upstream(path: &std::path::Path) -> Result<UpstreamIo, BoxError> {
    let stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await??;
    Ok(TokioIo::new(stream))
}

#[cfg(windows)]
async fn connect_upstream(_path: &std::path::Path) -> Result<UpstreamIo, BoxError> {
    Err("Windows is not a supported runtime platform for docker-proxy".into())
}

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "content-length",
];

const CLIENT_FORWARD_DROP_HEADERS: &[&str] = &[
    "authorization",
    "host",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "forwarded",
    "via",
];

#[derive(Clone)]
struct ProxyState {
    socket_path: PathBuf,
    env_secret: String,
    config_holder: Arc<RwLock<Arc<ProxyConfig>>>,
    rate_limiter: Arc<RateLimiter>,
    auth_limiter: Arc<AuthLimiter>,
    metrics: Arc<Metrics>,
    audit: AuditSink,
    metrics_path: Option<String>,
}

impl ProxyState {
    fn current_config(&self) -> Arc<ProxyConfig> {
        self.config_holder
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    #[cfg(unix)]
    fn swap_config(&self, new_cfg: Arc<ProxyConfig>) {
        let mut g = self
            .config_holder
            .write()
            .unwrap_or_else(|p| p.into_inner());
        *g = new_cfg;
    }
}

fn resolve_socket_path(config_socket: Option<&String>) -> Option<PathBuf> {
    if let Some(sock) = config_socket {
        let p = PathBuf::from(sock);
        if p.exists() {
            info!("found socket at: {} (from config)", p.display());
            return Some(p);
        }
        warn!("config socket '{}' does not exist", sock);
    }

    if let Ok(path) = env::var("DOCKER_SOCKET") {
        let p = PathBuf::from(&path);
        if p.exists() {
            info!("found socket at: {} (from DOCKER_SOCKET env)", p.display());
            return Some(p);
        }
        warn!("DOCKER_SOCKET is set to '{}' but path does not exist", path);
    }

    let candidates: Vec<PathBuf> = {
        #[cfg(target_os = "macos")]
        {
            let home = env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
            vec![
                PathBuf::from(format!("{}/.docker/run/docker.sock", home)),
                PathBuf::from("/var/run/docker.sock"),
                PathBuf::from(format!("{}/.docker/desktop/docker.sock", home)),
            ]
        }
        #[cfg(not(target_os = "macos"))]
        {
            vec![
                PathBuf::from("/var/run/docker.sock"),
                PathBuf::from("/run/docker.sock"),
            ]
        }
    };

    for candidate in &candidates {
        if candidate.exists() {
            info!("found socket at: {}", candidate.display());
            return Some(candidate.clone());
        }
    }

    error!("docker socket not found — tried:");
    for candidate in &candidates {
        error!("  {}", candidate.display());
    }
    None
}

fn make_response(status: StatusCode, body: &'static str) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(""))))
}

fn make_response_string(status: StatusCode, body: String) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(""))))
}

fn make_response_bytes(status: StatusCode, content_type: &str, body: Vec<u8>) -> HttpResponse {
    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from(""))))
}

fn sanitize_for_log(s: &str) -> String {
    s.chars()
        .take(256)
        .map(|c| {
            if c.is_control() || c == '"' || c == '\\' {
                '?'
            } else {
                c
            }
        })
        .collect()
}

fn log_request(
    peer: SocketAddr,
    method: &hyper::Method,
    path: &str,
    user_agent: &str,
    status: StatusCode,
) {
    let now = Local::now().format("%m/%d/%Y %H:%M:%S");
    info!(
        "[{}] {} {} {} - {} - \"{}\"",
        now,
        peer.ip(),
        method,
        sanitize_for_log(path),
        status.as_u16(),
        sanitize_for_log(user_agent)
    );
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff: u32 = (a.len() ^ b.len()) as u32;
    for i in 0..max_len {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= (x ^ y) as u32;
    }
    diff == 0
}

fn percent_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let h = (bytes[i + 1] as char).to_digit(16);
            let l = (bytes[i + 2] as char).to_digit(16);
            match (h, l) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                }
                _ => return None,
            }
        } else {
            out.push(b);
            i += 1;
        }
    }
    Some(out)
}

fn strip_api_version_prefix(path: &str) -> &str {
    if !path.starts_with("/v") || path.len() < 3 {
        return path;
    }
    if let Some(second_slash) = path[2..].find('/') {
        let version_part = &path[2..2 + second_slash];
        if !version_part.is_empty()
            && version_part != "."
            && version_part.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return &path[2 + second_slash..];
        }
    }
    path
}

fn requires_json_body(path: &str) -> bool {
    if path == "/containers/create" {
        return true;
    }
    if Regex::new(r"^/containers/[^/]+/update$")
        .map(|r| r.is_match(path))
        .unwrap_or(false)
    {
        return true;
    }
    false
}

fn parse_trusted_proxies(raw: &[String]) -> Vec<IpNet> {
    raw.iter().filter_map(|s| s.parse::<IpNet>().ok()).collect()
}

fn compute_client_ip(peer: &SocketAddr, headers: &HeaderMap, trusted_proxies: &[IpNet]) -> IpAddr {
    let peer_ip = peer.ip();
    if !trusted_proxies.iter().any(|net| net.contains(&peer_ip)) {
        return peer_ip;
    }

    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        if let Ok(ip) = v.trim().parse::<IpAddr>() {
            return ip;
        }
    }

    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for entry in v.split(',').map(|s| s.trim()).rev() {
            if let Ok(ip) = entry.parse::<IpAddr>() {
                if !trusted_proxies.iter().any(|net| net.contains(&ip)) {
                    return ip;
                }
            }
        }
    }

    if let Some(v) = headers.get("forwarded").and_then(|v| v.to_str().ok()) {
        for segment in v.split(',').rev() {
            for param in segment.split(';') {
                let param = param.trim();
                if let Some(rest) = param.strip_prefix("for=") {
                    let raw = rest.trim_matches('"');
                    let raw = raw
                        .strip_prefix('[')
                        .and_then(|s| s.strip_suffix(']'))
                        .unwrap_or(raw);
                    if let Ok(ip) = raw.parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }

    peer_ip
}

fn canonicalize_path(raw: &str) -> Option<String> {
    if raw.is_empty() || !raw.starts_with('/') {
        return None;
    }
    if raw.len() > MAX_PATH_LEN {
        return None;
    }
    let decoded_bytes = percent_decode(raw)?;
    if decoded_bytes
        .iter()
        .any(|&b| b == 0 || b < 0x20 || b == 0x7f)
    {
        return None;
    }
    let decoded = String::from_utf8(decoded_bytes).ok()?;
    let decoded = strip_api_version_prefix(&decoded).to_string();
    let trailing_slash = decoded.len() > 1 && decoded.ends_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&segments.join("/"));
    if trailing_slash && out.len() > 1 {
        out.push('/');
    }
    Some(out)
}

fn extract_bearer_token(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let mut iter = headers.get_all("authorization").iter();
    let first = match iter.next() {
        Some(v) => v,
        None => return Ok(None),
    };
    if iter.next().is_some() {
        return Err(());
    }
    let v = first.to_str().map_err(|_| ())?;
    match v.strip_prefix("Bearer ") {
        Some(t) if !t.is_empty() && t.len() <= MAX_TOKEN_LEN => Ok(Some(t.to_string())),
        _ => Err(()),
    }
}

fn resolve_token_role(config: &ProxyConfig, env_secret: &str, token: &str) -> Option<String> {
    let token_bytes = token.as_bytes();
    if let Some(ref auth_config) = config.auth {
        let mut matched: Option<String> = None;
        if let Some(ref tokens) = auth_config.tokens {
            for t in tokens.iter() {
                let eq = constant_time_eq(t.token.expose_secret().as_bytes(), token_bytes);
                if eq && matched.is_none() {
                    matched = Some(t.role.clone().unwrap_or_else(|| "user".to_string()));
                }
            }
        }
        if let Some(role) = matched {
            return Some(role);
        }
        if let Some(ref secret) = auth_config.secret {
            if !secret.expose_secret().is_empty()
                && constant_time_eq(secret.expose_secret().as_bytes(), token_bytes)
            {
                return Some("admin".to_string());
            }
        }
        return None;
    }
    if !env_secret.is_empty() && constant_time_eq(env_secret.as_bytes(), token_bytes) {
        return Some("admin".to_string());
    }
    None
}

fn is_auth_strictly_configured(config: &ProxyConfig, env_secret: &str) -> bool {
    if let Some(ref auth) = config.auth {
        let t = auth.auth_type.as_deref();
        if t == Some("none") {
            return true;
        }
        if t == Some("mtls") {
            return true;
        }
        let has_tokens = auth
            .tokens
            .as_ref()
            .map(|tk| tk.iter().any(|x| !x.token.expose_secret().is_empty()))
            .unwrap_or(false);
        let has_secret = auth
            .secret
            .as_ref()
            .map(|s| !s.expose_secret().is_empty())
            .unwrap_or(false);
        return has_tokens || has_secret;
    }
    !env_secret.is_empty()
}

enum AuthOutcome {
    Allowed {
        role: Option<String>,
        identity: Option<String>,
    },
    Denied(StatusCode, &'static str),
}

fn authenticate(
    state: &ProxyState,
    config: &ProxyConfig,
    headers: &HeaderMap,
    peer: &SocketAddr,
    cert: Option<&CertIdentity>,
) -> AuthOutcome {
    let auth_key = peer.ip().to_string();

    if state.auth_limiter.is_blocked(&auth_key) {
        return AuthOutcome::Denied(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many authentication failures",
        );
    }

    let auth_type = config.auth.as_ref().and_then(|a| a.auth_type.as_deref());

    if auth_type == Some("none") {
        return AuthOutcome::Allowed {
            role: None,
            identity: None,
        };
    }

    if auth_type == Some("mtls") {
        let id = match cert {
            Some(c) => c,
            None => {
                return AuthOutcome::Denied(
                    StatusCode::UNAUTHORIZED,
                    "mTLS required but no client certificate presented",
                );
            }
        };
        let mtls_cfg = config.auth.as_ref().and_then(|a| a.mtls.as_ref());
        match tls::resolve_mtls_role(id, mtls_cfg) {
            Some(role) => {
                state.auth_limiter.record_success(&auth_key);
                let ident = id.common_name.clone().or_else(|| id.sans.first().cloned());
                AuthOutcome::Allowed {
                    role: Some(role),
                    identity: ident,
                }
            }
            None => {
                state
                    .metrics
                    .auth_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                if state.auth_limiter.record_failure(
                    &auth_key,
                    AUTH_FAIL_MAX,
                    AUTH_FAIL_WINDOW,
                    AUTH_FAIL_LOCKOUT,
                ) {
                    state
                        .metrics
                        .auth_lockouts_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                AuthOutcome::Denied(
                    StatusCode::UNAUTHORIZED,
                    "Client certificate not authorized",
                )
            }
        }
    } else {
        if !is_auth_strictly_configured(config, &state.env_secret) {
            return AuthOutcome::Denied(
                StatusCode::UNAUTHORIZED,
                "Authentication is not configured",
            );
        }
        let token = match extract_bearer_token(headers) {
            Ok(Some(t)) => t,
            Ok(None) => {
                state
                    .metrics
                    .auth_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                if state.auth_limiter.record_failure(
                    &auth_key,
                    AUTH_FAIL_MAX,
                    AUTH_FAIL_WINDOW,
                    AUTH_FAIL_LOCKOUT,
                ) {
                    state
                        .metrics
                        .auth_lockouts_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                return AuthOutcome::Denied(StatusCode::UNAUTHORIZED, "Missing authorization");
            }
            Err(()) => {
                state
                    .metrics
                    .auth_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                if state.auth_limiter.record_failure(
                    &auth_key,
                    AUTH_FAIL_MAX,
                    AUTH_FAIL_WINDOW,
                    AUTH_FAIL_LOCKOUT,
                ) {
                    state
                        .metrics
                        .auth_lockouts_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                return AuthOutcome::Denied(StatusCode::UNAUTHORIZED, "Malformed authorization");
            }
        };

        match resolve_token_role(config, &state.env_secret, &token) {
            Some(role) => {
                state.auth_limiter.record_success(&auth_key);
                AuthOutcome::Allowed {
                    role: Some(role),
                    identity: None,
                }
            }
            None => {
                state
                    .metrics
                    .auth_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                if state.auth_limiter.record_failure(
                    &auth_key,
                    AUTH_FAIL_MAX,
                    AUTH_FAIL_WINDOW,
                    AUTH_FAIL_LOCKOUT,
                ) {
                    state
                        .metrics
                        .auth_lockouts_total
                        .fetch_add(1, Ordering::Relaxed);
                }
                AuthOutcome::Denied(StatusCode::UNAUTHORIZED, "Invalid token")
            }
        }
    }
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    cert: Option<Arc<CertIdentity>>,
    state: Arc<ProxyState>,
) -> Result<HttpResponse, Infallible> {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);

    let method = req.method().clone();
    let raw_path = req.uri().path().to_string();
    let raw_query = req.uri().query().map(|q| q.to_string());

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();

    let canonical_path = match canonicalize_path(&raw_path) {
        Some(p) => p,
        None => {
            state
                .metrics
                .bad_request_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &raw_path,
                &user_agent,
                StatusCode::BAD_REQUEST,
            );
            return Ok(make_response(
                StatusCode::BAD_REQUEST,
                "Malformed request path",
            ));
        }
    };

    if let Some(ref q) = raw_query {
        if q.len() > MAX_PATH_LEN || q.bytes().any(|b| b == 0 || b < 0x20 || b == 0x7f) {
            state
                .metrics
                .bad_request_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_REQUEST,
            );
            return Ok(make_response(
                StatusCode::BAD_REQUEST,
                "Malformed query string",
            ));
        }
    }

    let canonical_path_and_query = match &raw_query {
        Some(q) => format!("{canonical_path}?{q}"),
        None => canonical_path.clone(),
    };

    let config = state.current_config();

    let (user_role, identity) =
        match authenticate(&state, &config, req.headers(), &peer, cert.as_deref()) {
            AuthOutcome::Allowed { role, identity } => (role, identity),
            AuthOutcome::Denied(status, msg) => {
                state
                    .metrics
                    .requests_denied
                    .fetch_add(1, Ordering::Relaxed);
                if state.audit.is_enabled() {
                    let mut ev = AuditEvent::new(
                        "auth_denied",
                        peer.ip(),
                        method.as_str(),
                        &canonical_path,
                        &user_agent,
                    );
                    ev.status = status.as_u16();
                    ev.message = Some(msg.to_string());
                    state.audit.send(ev);
                }
                log_request(peer, &method, &canonical_path, &user_agent, status);
                return Ok(make_response(status, msg));
            }
        };

    if let Some(ref mp) = state.metrics_path {
        if canonical_path == *mp && method == hyper::Method::GET {
            let body = state.metrics.render_prometheus();
            return Ok(make_response_bytes(
                StatusCode::OK,
                "text/plain; version=0.0.4; charset=utf-8",
                body.into_bytes(),
            ));
        }
    }

    let trusted_proxies: Vec<IpNet> = config
        .global
        .as_ref()
        .and_then(|g| g.trusted_proxies.as_ref())
        .map(|v| parse_trusted_proxies(v))
        .unwrap_or_default();
    let client_ip = compute_client_ip(&peer, req.headers(), &trusted_proxies).to_string();

    let upgrade_requested = is_upgrade_request(req.headers());

    let mut header_map: HashMap<String, String> = HashMap::new();
    for (key, value) in req.headers().iter() {
        if let Ok(v) = value.to_str() {
            header_map
                .entry(key.as_str().to_string())
                .or_insert_with(|| v.to_string());
        }
    }

    let upgrade_value = req
        .headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let forward_headers: Vec<(String, hyper::header::HeaderValue)> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            let name = k.as_str();
            if HOP_BY_HOP_HEADERS.contains(&name) {
                return None;
            }
            if CLIENT_FORWARD_DROP_HEADERS.contains(&name) {
                return None;
            }
            if name == "upgrade" {
                return None;
            }
            Some((name.to_string(), v.clone()))
        })
        .collect();

    let rules = config.rules.as_deref().unwrap_or(&[]);

    if upgrade_requested {
        state.metrics.upgrade_total.fetch_add(1, Ordering::Relaxed);
        let eval_ctx = EvaluationContext {
            path: canonical_path.clone(),
            method: method.to_string(),
            headers: header_map,
            client_ip,
            body_json: None,
            user_role: user_role.clone(),
        };
        let decision = evaluate_request_detailed(rules, &eval_ctx, &state.rate_limiter);
        if let Some(ref rn) = decision.rule_name {
            if decision.dry_run {
                state
                    .metrics
                    .requests_dry_run
                    .fetch_add(1, Ordering::Relaxed);
                state.metrics.record_rule_deny(rn, true);
                if state.audit.is_enabled() {
                    let mut ev = AuditEvent::new(
                        "dry_run",
                        peer.ip(),
                        method.as_str(),
                        &canonical_path,
                        &user_agent,
                    );
                    ev.user_role = user_role.clone();
                    ev.identity = identity.clone();
                    ev.rule_name = Some(rn.clone());
                    ev.rule_action = decision.action.clone();
                    ev.dry_run = true;
                    state.audit.send(ev);
                }
            }
        }
        if let RuleResult::Deny { status, message } = decision.result {
            state
                .metrics
                .requests_denied
                .fetch_add(1, Ordering::Relaxed);
            if let Some(ref rn) = decision.rule_name {
                state.metrics.record_rule_deny(rn, false);
            }
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
            if state.audit.is_enabled() {
                let mut ev = AuditEvent::new(
                    "deny",
                    peer.ip(),
                    method.as_str(),
                    &canonical_path,
                    &user_agent,
                );
                ev.user_role = user_role.clone();
                ev.identity = identity.clone();
                ev.rule_name = decision.rule_name.clone();
                ev.rule_action = decision.action.clone();
                ev.status = status_code.as_u16();
                ev.message = Some(message.clone());
                state.audit.send(ev);
            }
            log_request(peer, &method, &canonical_path, &user_agent, status_code);
            return Ok(make_response_string(status_code, message));
        }
        state
            .metrics
            .requests_allowed
            .fetch_add(1, Ordering::Relaxed);
        return Ok(handle_upgrade(
            req,
            peer,
            method,
            canonical_path,
            canonical_path_and_query,
            user_agent,
            forward_headers,
            upgrade_value,
            state.clone(),
        )
        .await);
    }

    let (_parts, body) = req.into_parts();
    let _ = _parts;
    let limited = Limited::new(body, MAX_REQ_BODY_BYTES);
    let body_bytes: Bytes = match timeout(BODY_READ_TIMEOUT, limited.collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) => {
            if e.is::<LengthLimitError>() {
                state
                    .metrics
                    .body_too_large_total
                    .fetch_add(1, Ordering::Relaxed);
                warn!("body exceeded size limit");
                log_request(
                    peer,
                    &method,
                    &canonical_path,
                    &user_agent,
                    StatusCode::PAYLOAD_TOO_LARGE,
                );
                return Ok(make_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large",
                ));
            }
            state
                .metrics
                .bad_request_total
                .fetch_add(1, Ordering::Relaxed);
            warn!("body read failed: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_REQUEST,
            );
            return Ok(make_response(
                StatusCode::BAD_REQUEST,
                "Request body invalid",
            ));
        }
        Err(_) => {
            state
                .metrics
                .request_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::REQUEST_TIMEOUT,
            );
            return Ok(make_response(
                StatusCode::REQUEST_TIMEOUT,
                "Request body read timeout",
            ));
        }
    };
    let body_json: Option<JsonValue> = if body_bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice(&body_bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                if requires_json_body(&canonical_path) {
                    state
                        .metrics
                        .bad_request_total
                        .fetch_add(1, Ordering::Relaxed);
                    log_request(
                        peer,
                        &method,
                        &canonical_path,
                        &user_agent,
                        StatusCode::BAD_REQUEST,
                    );
                    return Ok(make_response_string(
                        StatusCode::BAD_REQUEST,
                        format!("Request body must be valid JSON for this endpoint: {e}"),
                    ));
                }
                None
            }
        }
    };

    let eval_ctx = EvaluationContext {
        path: canonical_path.clone(),
        method: method.to_string(),
        headers: header_map,
        client_ip,
        body_json,
        user_role: user_role.clone(),
    };

    let decision = evaluate_request_detailed(rules, &eval_ctx, &state.rate_limiter);

    if decision.dry_run {
        if let Some(ref rn) = decision.rule_name {
            state
                .metrics
                .requests_dry_run
                .fetch_add(1, Ordering::Relaxed);
            state.metrics.record_rule_deny(rn, true);
            if state.audit.is_enabled() {
                let mut ev = AuditEvent::new(
                    "dry_run",
                    peer.ip(),
                    method.as_str(),
                    &canonical_path,
                    &user_agent,
                );
                ev.user_role = user_role.clone();
                ev.identity = identity.clone();
                ev.rule_name = Some(rn.clone());
                ev.rule_action = decision.action.clone();
                ev.dry_run = true;
                state.audit.send(ev);
            }
        }
    }

    match decision.result {
        RuleResult::Deny { status, message } => {
            state
                .metrics
                .requests_denied
                .fetch_add(1, Ordering::Relaxed);
            if decision.action.as_deref() == Some("rate_limit") {
                state
                    .metrics
                    .rate_limited_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            if let Some(ref rn) = decision.rule_name {
                state.metrics.record_rule_deny(rn, false);
            }
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
            if state.audit.is_enabled() {
                let mut ev = AuditEvent::new(
                    "deny",
                    peer.ip(),
                    method.as_str(),
                    &canonical_path,
                    &user_agent,
                );
                ev.user_role = user_role.clone();
                ev.identity = identity.clone();
                ev.rule_name = decision.rule_name.clone();
                ev.rule_action = decision.action.clone();
                ev.status = status_code.as_u16();
                ev.message = Some(message.clone());
                state.audit.send(ev);
            }
            log_request(peer, &method, &canonical_path, &user_agent, status_code);
            return Ok(make_response_string(status_code, message));
        }
        RuleResult::Allow => {}
    }

    let response_filters = collect_response_filters(rules, &eval_ctx);
    let _ = upgrade_value;

    let upstream_start = Instant::now();

    let upstream_io = match timeout(CONNECT_TIMEOUT, connect_upstream(&state.socket_path)).await {
        Ok(Ok(io)) => io,
        Ok(Err(e)) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("failed to connect to docker socket: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "docker socket unavailable",
            ));
        }
        Err(_) => {
            state
                .metrics
                .upstream_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            error!("docker socket connect timed out");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::GATEWAY_TIMEOUT,
            );
            return Ok(make_response(
                StatusCode::GATEWAY_TIMEOUT,
                "docker socket connect timeout",
            ));
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(upstream_io).await {
        Ok(v) => v,
        Err(e) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("docker handshake failed: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "docker handshake failed",
            ));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("docker connection closed: {e}");
        }
    });

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(canonical_path_and_query.as_str())
        .header("host", "docker.proxy")
        .header("connection", "close");

    for (name, value) in &forward_headers {
        builder = builder.header(name.as_str(), value);
    }

    let proxied_req = match builder.body(Full::new(body_bytes)) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to build upstream request: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "failed to build upstream request",
            ));
        }
    };

    let res = match timeout(UPSTREAM_TIMEOUT, sender.send_request(proxied_req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("docker request failed: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "docker request failed",
            ));
        }
        Err(_) => {
            state
                .metrics
                .upstream_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::GATEWAY_TIMEOUT,
            );
            return Ok(make_response(
                StatusCode::GATEWAY_TIMEOUT,
                "docker upstream timeout",
            ));
        }
    };

    let status = res.status();
    let content_type = res
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let upstream_headers = res.headers().clone();

    let (_rparts, rbody) = res.into_parts();
    let limited_resp = Limited::new(rbody, MAX_RESP_BODY_BYTES);

    let response_bytes = match timeout(UPSTREAM_TIMEOUT, limited_resp.collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(e)) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("failed to read docker response: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "failed to read docker response",
            ));
        }
        Err(_) => {
            state
                .metrics
                .upstream_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::GATEWAY_TIMEOUT,
            );
            return Ok(make_response(
                StatusCode::GATEWAY_TIMEOUT,
                "docker response timeout",
            ));
        }
    };

    let elapsed_ms = upstream_start
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64;
    state.metrics.observe_upstream_latency_ms(elapsed_ms);

    let final_bytes = if !response_filters.is_empty() && content_type.contains("application/json") {
        apply_response_filters(&response_filters, &response_bytes)
    } else {
        response_bytes.to_vec()
    };

    state
        .metrics
        .requests_allowed
        .fetch_add(1, Ordering::Relaxed);
    log_request(peer, &method, &canonical_path, &user_agent, status);

    let mut response_builder = Response::builder().status(status);
    let mut emitted_content_type = false;
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if HOP_BY_HOP_HEADERS.contains(&name) {
            continue;
        }
        if name == "content-length" {
            continue;
        }
        if name == "content-type" {
            emitted_content_type = true;
        }
        response_builder = response_builder.header(k, v);
    }
    if !emitted_content_type {
        response_builder = response_builder.header("content-type", content_type);
    }

    let resp = match response_builder.body(Full::new(Bytes::from(final_bytes))) {
        Ok(r) => r,
        Err(e) => {
            error!("failed to build client response: {e}");
            return Ok(make_response(
                StatusCode::BAD_GATEWAY,
                "failed to build response",
            ));
        }
    };
    Ok(resp)
}

#[allow(clippy::too_many_arguments)]
async fn handle_upgrade(
    mut req: Request<Incoming>,
    peer: SocketAddr,
    method: hyper::Method,
    canonical_path: String,
    canonical_path_and_query: String,
    user_agent: String,
    forward_headers: Vec<(String, hyper::header::HeaderValue)>,
    upgrade_value: Option<String>,
    state: Arc<ProxyState>,
) -> HttpResponse {
    let upstream_io = match timeout(CONNECT_TIMEOUT, connect_upstream(&state.socket_path)).await {
        Ok(Ok(io)) => io,
        Ok(Err(e)) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("upgrade: docker connect failed: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return make_response(StatusCode::BAD_GATEWAY, "docker socket unavailable");
        }
        Err(_) => {
            state
                .metrics
                .upstream_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::GATEWAY_TIMEOUT,
            );
            return make_response(StatusCode::GATEWAY_TIMEOUT, "docker socket connect timeout");
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(upstream_io).await {
        Ok(v) => v,
        Err(e) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("upgrade: docker handshake failed: {e}");
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return make_response(StatusCode::BAD_GATEWAY, "docker handshake failed");
        }
    };

    let conn_with_upgrades = conn.with_upgrades();
    let conn_join = tokio::spawn(async move {
        if let Err(e) = conn_with_upgrades.await {
            tracing::debug!("docker upgrade conn closed: {e}");
        }
    });

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(canonical_path_and_query.as_str())
        .header("host", "docker.proxy")
        .header("connection", "upgrade");

    if let Some(ref u) = upgrade_value {
        builder = builder.header("upgrade", u.as_str());
    }
    for (name, value) in &forward_headers {
        builder = builder.header(name.as_str(), value);
    }

    let proxied_req = match builder.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => {
            error!("upgrade: build request failed: {e}");
            conn_join.abort();
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return make_response(StatusCode::BAD_GATEWAY, "failed to build upstream request");
        }
    };

    let upstream_res = match timeout(UPSTREAM_TIMEOUT, sender.send_request(proxied_req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            state
                .metrics
                .upstream_errors_total
                .fetch_add(1, Ordering::Relaxed);
            error!("upgrade: send_request failed: {e}");
            conn_join.abort();
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::BAD_GATEWAY,
            );
            return make_response(StatusCode::BAD_GATEWAY, "docker request failed");
        }
        Err(_) => {
            state
                .metrics
                .upstream_timeouts_total
                .fetch_add(1, Ordering::Relaxed);
            conn_join.abort();
            log_request(
                peer,
                &method,
                &canonical_path,
                &user_agent,
                StatusCode::GATEWAY_TIMEOUT,
            );
            return make_response(StatusCode::GATEWAY_TIMEOUT, "docker upstream timeout");
        }
    };

    let upstream_status = upstream_res.status();
    let upstream_headers = upstream_res.headers().clone();

    if upstream_status != StatusCode::SWITCHING_PROTOCOLS {
        let (_parts, body) = upstream_res.into_parts();
        let limited = Limited::new(body, MAX_RESP_BODY_BYTES);
        let bytes = match timeout(UPSTREAM_TIMEOUT, limited.collect()).await {
            Ok(Ok(b)) => b.to_bytes(),
            _ => Bytes::new(),
        };
        log_request(peer, &method, &canonical_path, &user_agent, upstream_status);
        let mut rb = Response::builder().status(upstream_status);
        for (k, v) in upstream_headers.iter() {
            let name = k.as_str();
            if HOP_BY_HOP_HEADERS.contains(&name) {
                continue;
            }
            if name == "content-length" {
                continue;
            }
            rb = rb.header(k, v);
        }
        return rb
            .body(Full::new(bytes))
            .unwrap_or_else(|_| make_response(StatusCode::BAD_GATEWAY, "upgrade rejected"));
    }

    let client_upgrade_fut = hyper::upgrade::on(&mut req);
    let docker_upgrade_fut = hyper::upgrade::on(upstream_res);

    let metrics_for_task = state.metrics.clone();
    tokio::spawn(async move {
        let client_upgraded = match timeout(UPGRADE_RESOLVE_TIMEOUT, client_upgrade_fut).await {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                metrics_for_task
                    .upstream_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!("client upgrade failed: {e}");
                conn_join.abort();
                return;
            }
            Err(_) => {
                metrics_for_task
                    .upstream_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!("client upgrade resolve timeout");
                conn_join.abort();
                return;
            }
        };
        let docker_upgraded = match timeout(UPGRADE_RESOLVE_TIMEOUT, docker_upgrade_fut).await {
            Ok(Ok(u)) => u,
            Ok(Err(e)) => {
                metrics_for_task
                    .upstream_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!("docker upgrade failed: {e}");
                conn_join.abort();
                return;
            }
            Err(_) => {
                metrics_for_task
                    .upstream_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::debug!("docker upgrade resolve timeout");
                conn_join.abort();
                return;
            }
        };

        let mut client_io = TokioIo::new(client_upgraded);
        let mut docker_io = TokioIo::new(docker_upgraded);

        let (mut cr, mut cw) = tokio::io::split(&mut client_io);
        let (mut dr, mut dw) = tokio::io::split(&mut docker_io);

        let c2d = async {
            let mut buf = vec![0u8; UPGRADE_COPY_BUF_BYTES];
            loop {
                let n = match timeout(UPGRADE_IDLE_TIMEOUT, cr.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => break,
                };
                if dw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = dw.shutdown().await;
        };

        let d2c = async {
            let mut buf = vec![0u8; UPGRADE_COPY_BUF_BYTES];
            loop {
                let n = match timeout(UPGRADE_IDLE_TIMEOUT, dr.read(&mut buf)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(_)) | Err(_) => break,
                };
                if cw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            let _ = cw.shutdown().await;
        };

        tokio::join!(c2d, d2c);
        conn_join.abort();
    });

    let mut response_builder = Response::builder().status(upstream_status);
    for (k, v) in upstream_headers.iter() {
        let name = k.as_str();
        if name == "content-length" {
            continue;
        }
        if HOP_BY_HOP_HEADERS.contains(&name) && name != "connection" && name != "upgrade" {
            continue;
        }
        response_builder = response_builder.header(k, v);
    }

    log_request(peer, &method, &canonical_path, &user_agent, upstream_status);
    response_builder
        .body(Full::new(Bytes::new()))
        .unwrap_or_else(|_| make_response(StatusCode::BAD_GATEWAY, "upgrade response build failed"))
}

fn init_tracing(log_format: &str, log_level: Option<&str>) -> Result<(), BoxError> {
    let mut filter = tracing_subscriber::EnvFilter::from_default_env()
        .add_directive("docker_proxy=info".parse()?);
    if let Some(level) = log_level {
        filter = filter.add_directive(format!("docker_proxy={level}").parse()?);
    }
    if log_format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .without_time()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .without_time()
            .init();
    }
    Ok(())
}

fn render_effective_rules(config: &ProxyConfig) -> String {
    let mut out = String::new();
    out.push_str("# Effective configuration\n\n");
    if let Some(ref g) = config.global {
        out.push_str(&format!("port: {}\n", g.port.unwrap_or(2376)));
        if let Some(ref s) = g.socket {
            out.push_str(&format!("socket: {s}\n"));
        }
        if let Some(ref f) = g.log_format {
            out.push_str(&format!("log_format: {f}\n"));
        }
        if let Some(ref t) = g.tls {
            out.push_str(&format!(
                "tls: cert={}, key={}, client_ca={}\n",
                t.cert,
                t.key,
                t.client_ca.as_deref().unwrap_or("(none)")
            ));
        }
        if let Some(ref m) = g.metrics {
            out.push_str(&format!(
                "metrics: enabled={}, path={}\n",
                m.enabled.unwrap_or(false),
                m.path.as_deref().unwrap_or("/metrics")
            ));
        }
    }
    if let Some(ref a) = config.auth {
        out.push_str(&format!(
            "auth.type: {}\n",
            a.auth_type.as_deref().unwrap_or("(unset)")
        ));
        if let Some(ref toks) = a.tokens {
            out.push_str(&format!("auth.tokens: {} configured\n", toks.len()));
        }
    }
    out.push_str("\nrules (after priority sort):\n");
    if let Some(ref rules) = config.rules {
        for (i, r) in rules.iter().enumerate() {
            out.push_str(&format!(
                "  {}. {} [priority={}, action={}{}]\n",
                i + 1,
                r.name,
                r.priority.unwrap_or(0),
                r.action,
                if r.dry_run.unwrap_or(false) {
                    ", dry_run"
                } else {
                    ""
                }
            ));
        }
    } else {
        out.push_str("  (no rules configured)\n");
    }
    out
}

fn load_config_from_default_path() -> Result<(ProxyConfig, Option<PathBuf>), String> {
    let path = env::var("DOCKER_PROXY_CONFIG")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            let cwd = PathBuf::from("config.yaml");
            if cwd.exists() {
                Some(cwd)
            } else {
                None
            }
        });
    match path {
        Some(p) => {
            let cfg = ProxyConfig::load_from_path(&p)?;
            Ok((cfg, Some(p)))
        }
        None => Ok((ProxyConfig::load()?, None)),
    }
}

async fn create_listener(
    config: &ProxyConfig,
) -> Result<(TcpListener, Option<TlsAcceptor>, String), BoxError> {
    let port = config
        .global
        .as_ref()
        .and_then(|g| g.port)
        .or_else(|| {
            env::var("DOCKER_PROXY_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(2376);

    let bind_host = config
        .global
        .as_ref()
        .and_then(|g| g.bind.clone())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let tls_config_opt = config.global.as_ref().and_then(|g| g.tls.clone());
    if bind_host != "127.0.0.1" && bind_host != "localhost" && tls_config_opt.is_none() {
        warn!(
            "binding to non-loopback {} without TLS — tokens will travel in cleartext",
            bind_host
        );
    }

    let tls_acceptor = match tls_config_opt {
        Some(ref tls_cfg) => {
            tls::install_default_crypto_provider();
            let sc = tls::build_server_config(tls_cfg).map_err(|e| {
                error!("TLS init failed: {e}");
                e
            })?;
            info!(
                "TLS enabled (cert={}, client_ca={})",
                tls_cfg.cert,
                tls_cfg.client_ca.as_deref().unwrap_or("(none)")
            );
            Some(TlsAcceptor::from(sc))
        }
        None => None,
    };

    let addr_str = format!("{bind_host}:{port}");
    let listener = TcpListener::bind(&addr_str).await?;
    Ok((listener, tls_acceptor, addr_str))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args: Vec<String> = env::args().collect();
    let mut check_config = false;
    let mut explicit_config: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--check-config" => check_config = true,
            "--config" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("--config requires a path argument");
                    std::process::exit(2);
                }
                explicit_config = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                println!(
                    "docker-proxy [--config <path>] [--check-config]\n  --config        path to YAML config (default: $DOCKER_PROXY_CONFIG or ./config.yaml)\n  --check-config  parse and print effective rule set, then exit"
                );
                return Ok(());
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if let Some(ref p) = explicit_config {
        env::set_var("DOCKER_PROXY_CONFIG", p);
    }

    let (config, loaded_from) = match load_config_from_default_path() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("config load failed: {e}");
            std::process::exit(2);
        }
    };

    let log_format = config
        .global
        .as_ref()
        .and_then(|g| g.log_format.clone())
        .unwrap_or_else(|| "text".to_string());

    if check_config {
        eprintln!(
            "Loaded config from: {}",
            loaded_from
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(defaults — no file found)".to_string())
        );
        println!("{}", render_effective_rules(&config));
        return Ok(());
    }

    let log_level = config.global.as_ref().and_then(|g| g.log_level.as_deref());
    init_tracing(&log_format, log_level)?;

    if let Some(level) = log_level {
        info!("config log_level override: {level}");
    }

    let config_socket = config.global.as_ref().and_then(|g| g.socket.as_ref());
    let socket_path = match resolve_socket_path(config_socket) {
        Some(p) => p,
        None => {
            error!("cannot start — set DOCKER_SOCKET or ensure docker is running");
            std::process::exit(1);
        }
    };

    let env_secret = env::var("DOCKER_PROXY_SECRET").unwrap_or_default();
    if !env_secret.is_empty()
        && config.auth.as_ref().and_then(|a| a.auth_type.as_deref()) == Some("none")
    {
        warn!("DOCKER_PROXY_SECRET is set but auth.type is 'none'; the secret will be ignored");
    }

    if !is_auth_strictly_configured(&config, &env_secret) {
        error!("auth is not configured — proxy will reject all requests");
        error!(
            "set DOCKER_PROXY_SECRET, configure auth.tokens / auth.secret / auth.type=mtls in config.yaml, \
             or set auth.type: none to explicitly disable authentication"
        );
    }

    let metrics = Arc::new(Metrics::new());
    let metrics_path = config
        .global
        .as_ref()
        .and_then(|g| g.metrics.as_ref())
        .and_then(|m| {
            if m.enabled.unwrap_or(false) {
                Some(m.path.clone().unwrap_or_else(|| "/metrics".to_string()))
            } else {
                None
            }
        });
    if let Some(ref p) = metrics_path {
        info!("metrics endpoint exposed at {}", p);
    }

    let audit = match config.global.as_ref().and_then(|g| g.audit_log.clone()) {
        Some(p) if !p.is_empty() => {
            info!("audit log enabled at {}", p);
            AuditSink::spawn(PathBuf::from(p))
        }
        _ => AuditSink::disabled(),
    };

    let rate_limiter = Arc::new(RateLimiter::new());
    let auth_limiter = Arc::new(AuthLimiter::new());

    let config_arc = Arc::new(config);
    let config_holder = Arc::new(RwLock::new(config_arc.clone()));

    let state = Arc::new(ProxyState {
        socket_path,
        env_secret,
        config_holder: config_holder.clone(),
        rate_limiter: rate_limiter.clone(),
        auth_limiter: auth_limiter.clone(),
        metrics: metrics.clone(),
        audit: audit.clone(),
        metrics_path,
    });

    let rl_cleanup = rate_limiter;
    let al_cleanup = auth_limiter;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            rl_cleanup.cleanup();
            al_cleanup.cleanup();
        }
    });

    let reload_notify = Arc::new(Notify::new());
    spawn_sighup_reloader(state.clone(), loaded_from.clone(), reload_notify.clone());

    let mut first_bind = true;
    loop {
        let config = state.current_config();
        match create_listener(&config).await {
            Ok((listener, tls_acceptor, addr_str)) => {
                let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));
                let rule_count = config.rules.as_ref().map(|r| r.len()).unwrap_or(0);
                info!(
                    "docker-proxy listening on {} ({}{} rule{}, log_format={})",
                    addr_str,
                    if tls_acceptor.is_some() { "TLS, " } else { "" },
                    rule_count,
                    if rule_count == 1 { "" } else { "s" },
                    log_format,
                );
                drop(config);

                let mut reload = false;
                while !reload {
                    tokio::select! {
                        accept_result = listener.accept() => {
                            match accept_result {
                                Ok((stream, peer)) => {
                                    let permit = match conn_sem.clone().try_acquire_owned() {
                                        Ok(p) => p,
                                        Err(_) => {
                                            warn!(
                                                "connection limit reached — dropping connection from {}",
                                                peer
                                            );
                                            drop(stream);
                                            continue;
                                        }
                                    };

                                    let state = state.clone();
                                    let tls_acceptor = tls_acceptor.clone();

                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        if let Some(acc) = tls_acceptor {
                                            serve_tls(stream, peer, acc, state).await;
                                        } else {
                                            serve_plain(stream, peer, state).await;
                                        }
                                    });
                                }
                                Err(e) => {
                                    error!("accept error: {e}");
                                    continue;
                                }
                            }
                        }
                        _ = reload_notify.notified() => {
                            info!("SIGHUP received; restarting listener");
                            reload = true;
                        }
                    }
                }
                first_bind = false;
            }
            Err(e) => {
                if first_bind {
                    return Err(e);
                }
                error!("failed to rebind listener after SIGHUP: {e}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn serve_plain(stream: TcpStream, peer: SocketAddr, state: Arc<ProxyState>) {
    let io = TokioIo::new(stream);
    let serve = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(
            io,
            service_fn(move |req| handle(req, peer, None, state.clone())),
        )
        .with_upgrades();
    if let Err(e) = timeout(UPGRADE_IDLE_TIMEOUT, serve).await.unwrap_or(Ok(())) {
        tracing::debug!("connection error from {peer}: {e}");
    }
}

async fn serve_tls(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    state: Arc<ProxyState>,
) {
    let tls_stream = match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::debug!("TLS handshake failed from {peer}: {e}");
            return;
        }
        Err(_) => {
            tracing::debug!("TLS handshake timeout from {peer}");
            return;
        }
    };

    let identity = {
        let (_io, conn) = tls_stream.get_ref();
        conn.peer_certificates()
            .and_then(|certs| certs.first().cloned())
            .and_then(|leaf| tls::extract_identity(&leaf))
            .map(Arc::new)
    };

    let io = TokioIo::new(tls_stream);
    let serve = http1::Builder::new()
        .keep_alive(false)
        .serve_connection(
            io,
            service_fn(move |req| handle(req, peer, identity.clone(), state.clone())),
        )
        .with_upgrades();
    if let Err(e) = timeout(UPGRADE_IDLE_TIMEOUT, serve).await.unwrap_or(Ok(())) {
        tracing::debug!("TLS connection error from {peer}: {e}");
    }
}

#[cfg(unix)]
fn spawn_sighup_reloader(
    state: Arc<ProxyState>,
    loaded_from: Option<PathBuf>,
    reload_notify: Arc<Notify>,
) {
    let path = match loaded_from {
        Some(p) => p,
        None => return,
    };
    tokio::spawn(async move {
        let mut signal = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                error!("SIGHUP listener install failed: {e}");
                return;
            }
        };
        info!("SIGHUP reload listener installed for {}", path.display());
        loop {
            match signal.recv().await {
                Some(()) => match ProxyConfig::load_from_path(&path) {
                    Ok(cfg) => {
                        let rules_n = cfg.rules.as_ref().map(|r| r.len()).unwrap_or(0);
                        state.swap_config(Arc::new(cfg));
                        info!("config reloaded ({} rules active)", rules_n);
                        reload_notify.notify_one();
                    }
                    Err(e) => {
                        error!("config reload failed (keeping current): {e}");
                    }
                },
                None => break,
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_reloader(
    _state: Arc<ProxyState>,
    _loaded_from: Option<PathBuf>,
    _reload_notify: Arc<Notify>,
) {
}

#[allow(dead_code)]
fn _force_ipaddr_use(_: IpAddr) {}
