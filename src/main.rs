mod config;
mod rules;

use chrono::Local;
use config::ProxyConfig;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use rules::{apply_response_filters, collect_response_filters, evaluate_request, EvaluationContext, RateLimiter, RuleResult};
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};
use tokio::net::{TcpListener, UnixStream};
use tracing::{error, info, warn};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type HttpResponse = Response<Full<Bytes>>;

#[derive(Clone)]
struct ProxyState {
    socket_path: PathBuf,
    secret: String,
    config: ProxyConfig,
    rate_limiter: Arc<RateLimiter>,
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
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn make_response_string(status: StatusCode, body: String) -> HttpResponse {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn log_request(peer: SocketAddr, method: &hyper::Method, path: &str, user_agent: &str, status: StatusCode) {
    let now = Local::now().format("%m/%d/%Y %H:%M:%S");
    info!(
        "[{}] {} {} {} - {} - \"{}\"",
        now,
        peer.ip(),
        method,
        path,
        status.as_u16(),
        user_agent
    );
}

fn resolve_auth(state: &ProxyState, auth_header: &str) -> Option<String> {
    let token = auth_header.strip_prefix("Bearer ")?;

    if let Some(ref auth_config) = state.config.auth {
        if let Some(ref tokens) = auth_config.tokens {
            if let Some(t) = tokens.iter().find(|t| t.token == token) {
                return Some(t.role.clone().unwrap_or_else(|| "user".to_string()));
            }
        }
        if let Some(ref secret) = auth_config.secret {
            if !secret.is_empty() && token == secret {
                return Some("admin".to_string());
            }
        }
        return None;
    }

    if !state.secret.is_empty() && token == state.secret {
        return Some("admin".to_string());
    }

    None
}

fn check_auth(state: &ProxyState, auth_header: &str) -> bool {
    if let Some(ref auth_config) = state.config.auth {
        if let Some(ref auth_type) = auth_config.auth_type {
            if auth_type == "none" {
                return true;
            }
        }

        let has_tokens = auth_config.tokens.as_ref().map(|t| !t.is_empty()).unwrap_or(false);
        let has_secret = auth_config.secret.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

        if !has_tokens && !has_secret {
            return true;
        }

        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return false,
        };

        if let Some(ref tokens) = auth_config.tokens {
            if tokens.iter().any(|t| t.token == token) {
                return true;
            }
        }

        if let Some(ref secret) = auth_config.secret {
            if !secret.is_empty() && token == secret {
                return true;
            }
        }

        return false;
    }

    if !state.secret.is_empty() {
        let token = match auth_header.strip_prefix("Bearer ") {
            Some(t) => t,
            None => return false,
        };
        return token == state.secret;
    }

    true
}

async fn handle(
    req: Request<Incoming>,
    peer: SocketAddr,
    state: Arc<ProxyState>,
) -> Result<HttpResponse, Infallible> {
    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !check_auth(&state, auth_header) {
        log_request(peer, req.method(), req.uri().path(), "-", StatusCode::UNAUTHORIZED);
        return Ok(make_response(StatusCode::UNAUTHORIZED, "Unauthorized"));
    }

    let user_role = resolve_auth(&state, auth_header);

    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();
    let path_only = req.uri().path().to_string();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    let headers = req.headers().clone();

    let mut header_map: HashMap<String, String> = HashMap::new();
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(key.as_str().to_string(), v.to_string());
        }
    }

    let body_bytes = match req.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => {
            error!("failed to read request body: {e}");
            log_request(peer, &method, &path_and_query, &user_agent, StatusCode::BAD_GATEWAY);
            return Ok(make_response(StatusCode::BAD_GATEWAY, "failed to read request body"));
        }
    };

    let body_json: Option<JsonValue> = if body_bytes.is_empty() {
        None
    } else {
        serde_json::from_slice(&body_bytes).ok()
    };

    let client_ip = peer.ip().to_string();

    let eval_ctx = EvaluationContext {
        path: path_only.clone(),
        method: method.to_string(),
        headers: header_map,
        client_ip: client_ip.clone(),
        body_json: body_json.clone(),
        user_role: user_role.clone(),
    };

    let rules = state.config.rules.as_deref().unwrap_or(&[]);

    match evaluate_request(rules, &eval_ctx, &state.rate_limiter) {
        RuleResult::Deny { status, message } => {
            let status_code = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
            log_request(peer, &method, &path_and_query, &user_agent, status_code);
            return Ok(make_response_string(status_code, message));
        }
        RuleResult::Allow => {}
    }

    let response_filters = collect_response_filters(rules, &eval_ctx);

    let unix_stream = match UnixStream::connect(&state.socket_path).await {
        Ok(s) => s,
        Err(e) => {
            error!("failed to connect to docker socket: {e}");
            log_request(peer, &method, &path_and_query, &user_agent, StatusCode::BAD_GATEWAY);
            return Ok(make_response(StatusCode::BAD_GATEWAY, "docker socket unavailable"));
        }
    };

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(unix_stream)).await {
        Ok(v) => v,
        Err(e) => {
            error!("docker handshake failed: {e}");
            log_request(peer, &method, &path_and_query, &user_agent, StatusCode::BAD_GATEWAY);
            return Ok(make_response(StatusCode::BAD_GATEWAY, "docker handshake failed"));
        }
    };

    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!("docker connection closed: {e}");
        }
    });

    let mut builder = Request::builder()
        .method(method.clone())
        .uri(path_and_query.as_str())
        .header("host", "localhost")
        .header("connection", "close");

    for (key, value) in headers.iter() {
        if key != "authorization" && key != "host" && key != "connection" {
            builder = builder.header(key, value);
        }
    }

    let proxied_req = builder.body(Full::new(body_bytes)).unwrap();

    match sender.send_request(proxied_req).await {
        Ok(res) => {
            let status = res.status();
            let content_type = res
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();

            let response_bytes = match res.collect().await {
                Ok(b) => b.to_bytes(),
                Err(e) => {
                    error!("failed to read docker response: {e}");
                    log_request(peer, &method, &path_and_query, &user_agent, StatusCode::BAD_GATEWAY);
                    return Ok(make_response(StatusCode::BAD_GATEWAY, "failed to read docker response"));
                }
            };

            let final_bytes = if !response_filters.is_empty()
                && content_type.contains("application/json")
            {
                apply_response_filters(&response_filters, &response_bytes)
            } else {
                response_bytes.to_vec()
            };

            log_request(peer, &method, &path_and_query, &user_agent, status);

            Ok(Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(Full::new(Bytes::from(final_bytes)))
                .unwrap())
        }
        Err(e) => {
            error!("docker request failed: {e}");
            log_request(peer, &method, &path_and_query, &user_agent, StatusCode::BAD_GATEWAY);
            Ok(make_response(StatusCode::BAD_GATEWAY, "docker request failed"))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("docker_proxy=info".parse()?),
        )
        .without_time()
        .init();

    let config = ProxyConfig::load();

    if let Some(ref global) = config.global {
        if let Some(ref level) = global.log_level {
            info!("config log_level override: {}", level);
        }
    }

    let config_socket = config
        .global
        .as_ref()
        .and_then(|g| g.socket.as_ref());
    let socket_path = match resolve_socket_path(config_socket) {
        Some(p) => p,
        None => {
            error!("cannot start — set DOCKER_SOCKET or ensure docker is running");
            std::process::exit(1);
        }
    };

    let secret = if config.is_auth_configured() {
        String::new()
    } else {
        env::var("DOCKER_PROXY_SECRET").unwrap_or_else(|_| {
            warn!("DOCKER_PROXY_SECRET not set — proxy is unauthenticated");
            String::new()
        })
    };

    let port: u16 = config
        .global
        .as_ref()
        .and_then(|g| g.port)
        .or_else(|| {
            env::var("DOCKER_PROXY_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
        })
        .unwrap_or(2376);

    let rate_limiter = Arc::new(RateLimiter::new());

    let state = Arc::new(ProxyState {
        socket_path,
        secret,
        config,
        rate_limiter: rate_limiter.clone(),
    });

    let rl_cleanup = rate_limiter;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            rl_cleanup.cleanup();
        }
    });

    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;

    let rule_count = state.config.rules.as_ref().map(|r| r.len()).unwrap_or(0);
    info!("docker-proxy listening on {} ({} rule{})", addr, rule_count, if rule_count == 1 { "" } else { "s" });

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                error!("accept error: {e}");
                continue;
            }
        };

        let state = state.clone();

        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle(req, peer, state.clone())),
                )
                .await
            {
                error!("connection error from {peer}: {e}");
            }
        });
    }
}
