use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: String,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default, rename = "type")]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub tokens: Option<Vec<TokenEntry>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: Option<serde_yaml::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionNode {
    Leaf(Condition),
    And {
        and: Vec<ConditionNode>,
    },
    Or {
        or: Vec<ConditionNode>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseFilterEntry {
    pub field: String,
    pub action: String,
    #[serde(default)]
    pub replacement: Option<String>,
}

fn default_rate_requests() -> u64 {
    50
}
fn default_rate_period() -> u64 {
    30
}
fn default_rate_penalty() -> u64 {
    30
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_rate_requests")]
    pub requests: u64,
    #[serde(default = "default_rate_period")]
    pub period: u64,
    #[serde(default = "default_rate_penalty")]
    pub penalty: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<ConditionNode>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub response_filter: Option<Vec<ResponseFilterEntry>>,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub global: Option<GlobalConfig>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub rules: Option<Vec<Rule>>,
}

#[allow(dead_code)]
fn expand_env(s: &str) -> String {
    let re = Regex::new(r"\$\{(?<name>\w+)\}").expect("invalid env var regex");
    re.replace_all(s, |caps: &regex::Captures| {
        env::var(&caps["name"]).unwrap_or_default()
    })
    .to_string()
}

#[allow(dead_code)]
fn expand_value_env(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::String(s) => *s = expand_env(s),
        serde_yaml::Value::Sequence(seq) => {
            for v in seq.iter_mut() {
                expand_value_env(v);
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
fn expand_node_env(node: &mut ConditionNode) {
    match node {
        ConditionNode::Leaf(condition) => {
            if let Some(ref mut value) = condition.value {
                expand_value_env(value);
            }
        }
        ConditionNode::And { and } => {
            for n in and.iter_mut() {
                expand_node_env(n);
            }
        }
        ConditionNode::Or { or } => {
            for n in or.iter_mut() {
                expand_node_env(n);
            }
        }
    }
}

#[allow(dead_code)]
impl ProxyConfig {
    fn resolve_env_vars(&mut self) {
        if let Some(ref mut auth) = self.auth {
            if let Some(ref mut secret) = auth.secret {
                *secret = expand_env(secret);
            }
            if let Some(ref mut tokens) = auth.tokens {
                for t in tokens.iter_mut() {
                    t.token = expand_env(&t.token);
                }
            }
        }
        if let Some(ref mut rules) = self.rules {
            for rule in rules.iter_mut() {
                if let Some(ref mut msg) = rule.message {
                    *msg = expand_env(msg);
                }
                for node in rule.conditions.iter_mut() {
                    expand_node_env(node);
                }
                if let Some(ref mut methods) = rule.methods {
                    for m in methods.iter_mut() {
                        *m = expand_env(m);
                    }
                }
            }
        }
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(port) = env::var("DOCKER_PROXY_PORT") {
            if let Ok(p) = port.parse::<u16>() {
                let global = self.global.get_or_insert_with(|| GlobalConfig {
                    port: None,
                    socket: None,
                    log_level: None,
                });
                global.port = Some(p);
            }
        }

        if let Ok(socket) = env::var("DOCKER_SOCKET") {
            let p = PathBuf::from(&socket);
            if p.exists() {
                let global = self.global.get_or_insert_with(|| GlobalConfig {
                    port: None,
                    socket: None,
                    log_level: None,
                });
                global.socket = Some(socket);
            }
        }

        if let Ok(secret) = env::var("DOCKER_PROXY_SECRET") {
            if !secret.is_empty() {
                let auth = self.auth.get_or_insert_with(|| AuthConfig {
                    auth_type: Some("bearer".to_string()),
                    secret: None,
                    tokens: None,
                });
                auth.secret = Some(secret);
            }
        }
    }

    pub fn is_auth_configured(&self) -> bool {
        match &self.auth {
            None => false,
            Some(a) => {
                a.auth_type.as_deref() == Some("none")
                    || a.tokens.as_ref().map(|t| !t.is_empty()).unwrap_or(false)
                    || a.secret.as_ref().map(|s| !s.is_empty()).unwrap_or(false)
            }
        }
    }

    pub fn load() -> Self {
        let config_path = env::var("DOCKER_PROXY_CONFIG")
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

        let mut config = match config_path {
            Some(ref path) if path.exists() => {
                info!("loading config from {}", path.display());
                match fs::read_to_string(path) {
                    Ok(content) => match serde_yaml::from_str::<ProxyConfig>(&content) {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            warn!("failed to parse config, using defaults: {e}");
                            ProxyConfig::default()
                        }
                    },
                    Err(e) => {
                        warn!("failed to read config file, using defaults: {e}");
                        ProxyConfig::default()
                    }
                }
            }
            _ => {
                info!("no config file found, using defaults");
                ProxyConfig::default()
            }
        };

        config.resolve_env_vars();
        config.apply_env_overrides();
        config
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        ProxyConfig {
            global: None,
            auth: None,
            rules: None,
        }
    }
}
