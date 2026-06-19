use regex::Regex;
use secrecy::{ExposeSecret, SecretString};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use std::{env, fs, path::PathBuf};
use tracing::info;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub socket: Option<String>,
    #[serde(default)]
    pub log_level: Option<String>,
    #[serde(default)]
    pub log_format: Option<String>,
    #[serde(default)]
    pub audit_log: Option<String>,
    #[serde(default)]
    pub bind: Option<String>,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub trusted_proxies: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub client_ca: Option<String>,
    #[serde(default)]
    pub require_client_cert: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRoleMapping {
    pub cn: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtlsConfig {
    #[serde(default)]
    pub cert_role_map: Option<Vec<CertRoleMapping>>,
    #[serde(default)]
    pub default_role: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecretToken(SecretString);

impl SecretToken {
    pub fn new(s: String) -> Self {
        Self(SecretString::new(s.into_boxed_str()))
    }

    pub fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }
}

impl<'de> Deserialize<'de> for SecretToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SecretTokenVisitor;

        impl<'de> Visitor<'de> for SecretTokenVisitor {
            type Value = SecretToken;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(SecretToken::new(v.to_string()))
            }
        }

        deserializer.deserialize_str(SecretTokenVisitor)
    }
}

impl Serialize for SecretToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.expose_secret())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    pub token: SecretToken,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default, rename = "type")]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub secret: Option<SecretToken>,
    #[serde(default)]
    pub tokens: Option<Vec<TokenEntry>>,
    #[serde(default)]
    pub mtls: Option<MtlsConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Condition {
    pub field: String,
    #[serde(default)]
    pub operator: String,
    #[serde(default)]
    pub value: Option<serde_yaml::Value>,
    #[serde(skip)]
    pub compiled_regex: Option<Regex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionNode {
    Leaf(Condition),
    And { and: Vec<ConditionNode> },
    Or { or: Vec<ConditionNode> },
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
#[derive(Default)]
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
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProxyConfig {
    #[serde(default)]
    pub global: Option<GlobalConfig>,
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    #[serde(default)]
    pub rules: Option<Vec<Rule>>,
}

fn expand_env(s: &str, required: bool) -> Result<String, String> {
    let re = Regex::new(r"\$\{(?<name>\w+)\}").expect("invalid env var regex");
    let mut missing: Vec<String> = Vec::new();
    let result = re
        .replace_all(s, |caps: &regex::Captures| match env::var(&caps["name"]) {
            Ok(v) => v,
            Err(_) => {
                missing.push(caps["name"].to_string());
                String::new()
            }
        })
        .to_string();
    if required && !missing.is_empty() {
        return Err(format!(
            "required environment variables missing: {}",
            missing.join(", ")
        ));
    }
    Ok(result)
}

fn expand_value_env(value: &mut serde_yaml::Value, required: bool) -> Result<(), String> {
    match value {
        serde_yaml::Value::String(s) => *s = expand_env(s, required)?,
        serde_yaml::Value::Sequence(seq) => {
            for v in seq.iter_mut() {
                expand_value_env(v, required)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn expand_node_env(node: &mut ConditionNode, required: bool) -> Result<(), String> {
    match node {
        ConditionNode::Leaf(condition) => {
            if let Some(ref mut value) = condition.value {
                expand_value_env(value, required)?;
            }
        }
        ConditionNode::And { and } => {
            for n in and.iter_mut() {
                expand_node_env(n, required)?;
            }
        }
        ConditionNode::Or { or } => {
            for n in or.iter_mut() {
                expand_node_env(n, required)?;
            }
        }
    }
    Ok(())
}

fn compile_regex_in_condition(condition: &mut Condition) -> Result<(), String> {
    if matches!(condition.operator.as_str(), "matches" | "not_matches") {
        if let Some(ref value) = condition.value {
            if let Some(s) = yaml_value_to_string(value) {
                let regex = Regex::new(&s)
                    .map_err(|e| format!("invalid regex for field '{}': {e}", condition.field))?;
                condition.compiled_regex = Some(regex);
            }
        }
    }
    Ok(())
}

fn compile_regexes_in_node(node: &mut ConditionNode) -> Result<(), String> {
    match node {
        ConditionNode::Leaf(condition) => compile_regex_in_condition(condition),
        ConditionNode::And { and } => and.iter_mut().try_for_each(compile_regexes_in_node),
        ConditionNode::Or { or } => or.iter_mut().try_for_each(compile_regexes_in_node),
    }
}

pub fn yaml_value_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

impl ProxyConfig {
    fn resolve_env_vars(&mut self) -> Result<(), String> {
        if let Some(ref mut auth) = self.auth {
            if let Some(ref mut secret) = auth.secret {
                let expanded = expand_env(secret.expose_secret(), true)?;
                *secret = SecretToken::new(expanded);
            }
            if let Some(ref mut tokens) = auth.tokens {
                for t in tokens.iter_mut() {
                    let expanded = expand_env(t.token.expose_secret(), true)?;
                    t.token = SecretToken::new(expanded);
                }
            }
        }
        if let Some(ref mut rules) = self.rules {
            for rule in rules.iter_mut() {
                if let Some(ref mut msg) = rule.message {
                    *msg = expand_env(msg, false)?;
                }
                for node in rule.conditions.iter_mut() {
                    expand_node_env(node, false)?;
                }
                if let Some(ref mut methods) = rule.methods {
                    for m in methods.iter_mut() {
                        *m = expand_env(m, false)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn compile_regexes(&mut self) -> Result<(), String> {
        if let Some(ref mut rules) = self.rules {
            for rule in rules.iter_mut() {
                for node in rule.conditions.iter_mut() {
                    compile_regexes_in_node(node)?;
                }
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if let Some(ref auth) = self.auth {
            if let Some(ref t) = auth.auth_type {
                match t.as_str() {
                    "none" | "bearer" | "mtls" => {}
                    other => return Err(format!("invalid auth.type: {other}")),
                }
            }
        }

        if let Some(ref rules) = self.rules {
            for rule in rules {
                if rule.name.is_empty() {
                    return Err("rule name cannot be empty".into());
                }
                if rule.action.is_empty() {
                    return Err(format!("rule '{}' has no action", rule.name));
                }
                if rule.conditions.is_empty() {
                    return Err(format!("rule '{}' has no conditions", rule.name));
                }
                if rule.action == "require_role" && rule.role.is_none() {
                    return Err(format!(
                        "rule '{}' uses require_role but has no role specified",
                        rule.name
                    ));
                }
                if rule.action == "rate_limit" && rule.rate_limit.is_none() {
                    return Err(format!(
                        "rule '{}' uses rate_limit but has no rate_limit config",
                        rule.name
                    ));
                }
                if rule.action == "response_filter" && rule.response_filter.is_none() {
                    return Err(format!(
                        "rule '{}' uses response_filter but has no response_filter entries",
                        rule.name
                    ));
                }
            }
        }

        if let Some(ref global) = self.global {
            if let Some(ref metrics) = global.metrics {
                if metrics.enabled == Some(true) {
                    let path = metrics.path.as_deref().unwrap_or("/metrics");
                    if path == "/" || path.is_empty() {
                        return Err("metrics path cannot be '/' or empty".into());
                    }
                    if path.starts_with("/v") {
                        return Err(format!(
                            "metrics path '{path}' looks like a Docker API versioned path"
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(port) = env::var("DOCKER_PROXY_PORT") {
            if let Ok(p) = port.parse::<u16>() {
                let global = self.global.get_or_insert_with(GlobalConfig::default);
                global.port = Some(p);
            }
        }

        if let Ok(socket) = env::var("DOCKER_SOCKET") {
            let p = PathBuf::from(&socket);
            if p.exists() {
                let global = self.global.get_or_insert_with(GlobalConfig::default);
                global.socket = Some(socket);
            }
        }

        if let Ok(secret) = env::var("DOCKER_PROXY_SECRET") {
            if !secret.is_empty() {
                let auth = self.auth.get_or_insert_with(|| AuthConfig {
                    auth_type: Some("bearer".to_string()),
                    secret: None,
                    tokens: None,
                    mtls: None,
                });
                auth.secret = Some(SecretToken::new(secret));
                if auth.auth_type.is_none() {
                    auth.auth_type = Some("bearer".to_string());
                }
            }
        }
    }

    pub fn is_auth_configured(&self) -> bool {
        match &self.auth {
            None => false,
            Some(a) => {
                a.auth_type.as_deref() == Some("none")
                    || a.auth_type.as_deref() == Some("mtls")
                    || a.tokens.as_ref().map(|t| !t.is_empty()).unwrap_or(false)
                    || a.secret
                        .as_ref()
                        .map(|s| !s.expose_secret().is_empty())
                        .unwrap_or(false)
            }
        }
    }

    pub fn sort_rules_by_priority(&mut self) {
        if let Some(ref mut rules) = self.rules {
            rules.sort_by_key(|r| std::cmp::Reverse(r.priority.unwrap_or(0)));
        }
    }

    pub fn load() -> Result<Self, String> {
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
                let content = fs::read_to_string(path)
                    .map_err(|e| format!("failed to read config file: {e}"))?;
                serde_yaml::from_str::<ProxyConfig>(&content)
                    .map_err(|e| format!("failed to parse config: {e}"))?
            }
            _ => {
                info!("no config file found, using defaults");
                ProxyConfig::default()
            }
        };

        config.resolve_env_vars()?;
        config.apply_env_overrides();
        config.compile_regexes()?;
        config.validate()?;
        config.sort_rules_by_priority();
        Ok(config)
    }

    pub fn load_from_path(path: &std::path::Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| format!("read failed: {e}"))?;
        let mut cfg: ProxyConfig =
            serde_yaml::from_str(&content).map_err(|e| format!("parse failed: {e}"))?;
        cfg.resolve_env_vars()?;
        cfg.apply_env_overrides();
        cfg.compile_regexes()?;
        cfg.validate()?;
        cfg.sort_rules_by_priority();
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
global:
  port: 1234
auth:
  type: bearer
  tokens:
    - token: test-token
      role: admin
rules:
  - name: test-rule
    action: deny
    conditions:
      - field: path
        operator: equals
        value: /test
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.global.as_ref().unwrap().port, Some(1234));
        assert_eq!(
            cfg.auth.as_ref().unwrap().auth_type.as_deref(),
            Some("bearer")
        );
        assert_eq!(cfg.rules.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.rules.as_ref().unwrap()[0].name, "test-rule");
    }

    #[test]
    fn test_defaults() {
        let yaml = r#"
rules:
  - name: r
    action: deny
    conditions:
      - field: path
        operator: equals
        value: "/"
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let rule = &cfg.rules.unwrap()[0];
        assert_eq!(rule.status, None);
        assert_eq!(rule.message, None);
        assert_eq!(rule.role, None);
    }

    #[test]
    fn test_rate_limit_defaults() {
        let yaml = r#"
rules:
  - name: rl
    action: rate_limit
    conditions:
      - field: path
        operator: matches
        value: "^/"
    rate_limit: {}
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = cfg.rules.unwrap();
        let rl = rules[0].rate_limit.as_ref().unwrap();
        assert_eq!(rl.requests, 50);
        assert_eq!(rl.period, 30);
        assert_eq!(rl.penalty, 30);
    }

    #[test]
    fn test_rate_limit_custom() {
        let yaml = r#"
rules:
  - name: rl
    action: rate_limit
    conditions:
      - field: path
        operator: matches
        value: "^/"
    rate_limit:
      requests: 100
      period: 10
      penalty: 60
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = cfg.rules.unwrap();
        let rl = rules[0].rate_limit.as_ref().unwrap();
        assert_eq!(rl.requests, 100);
        assert_eq!(rl.period, 10);
        assert_eq!(rl.penalty, 60);
    }

    #[test]
    fn test_env_expansion() {
        std::env::set_var("TEST_VAR", "expanded_value");
        let result = expand_env("prefix_${TEST_VAR}_suffix", false).unwrap();
        assert_eq!(result, "prefix_expanded_value_suffix");
        std::env::remove_var("TEST_VAR");
    }

    #[test]
    fn test_env_expansion_unset_not_required() {
        let result = expand_env("${NONEXISTENT_VAR_12345}", false).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_env_expansion_unset_required_errors() {
        let result = expand_env("${NONEXISTENT_VAR_12345}", true);
        assert!(result.is_err());
    }

    #[test]
    fn test_or_condition_parsing() {
        let yaml = r#"
rules:
  - name: or-rule
    action: deny
    conditions:
      - or:
          - field: path
            operator: starts_with
            value: /a
          - field: path
            operator: starts_with
            value: /b
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let conds = &cfg.rules.unwrap()[0].conditions;
        assert_eq!(conds.len(), 1);
        match &conds[0] {
            ConditionNode::Or { or } => assert_eq!(or.len(), 2),
            _ => panic!("expected Or node"),
        }
    }

    #[test]
    fn test_nested_conditions() {
        let yaml = r#"
rules:
  - name: nested
    action: deny
    conditions:
      - and:
          - or:
              - field: path
                operator: equals
                value: /x
              - field: path
                operator: equals
                value: /y
          - field: method
            operator: equals
            value: POST
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let conds = &cfg.rules.unwrap()[0].conditions;
        assert_eq!(conds.len(), 1);
        match &conds[0] {
            ConditionNode::And { and } => {
                assert_eq!(and.len(), 2);
                match &and[0] {
                    ConditionNode::Or { or } => assert_eq!(or.len(), 2),
                    _ => panic!("expected Or"),
                }
            }
            _ => panic!("expected And node"),
        }
    }

    #[test]
    fn test_response_filter_parsing() {
        let yaml = r#"
rules:
  - name: filter
    action: response_filter
    conditions:
      - field: path
        operator: equals
        value: /test
    response_filter:
      - field: Config.Env
        action: redact
      - field: Labels
        action: remove
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let rules = cfg.rules.unwrap();
        let filters = rules[0].response_filter.as_ref().unwrap();
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].field, "Config.Env");
        assert_eq!(filters[0].action, "redact");
        assert_eq!(filters[1].field, "Labels");
        assert_eq!(filters[1].action, "remove");
    }

    #[test]
    fn test_is_auth_configured_tokens() {
        let cfg = ProxyConfig {
            auth: Some(AuthConfig {
                auth_type: Some("bearer".into()),
                secret: None,
                tokens: Some(vec![TokenEntry {
                    token: SecretToken::new("t".into()),
                    role: Some("admin".into()),
                }]),
                mtls: None,
            }),
            ..Default::default()
        };
        assert!(cfg.is_auth_configured());
    }

    #[test]
    fn test_is_auth_configured_secret() {
        let cfg = ProxyConfig {
            auth: Some(AuthConfig {
                auth_type: Some("bearer".into()),
                secret: Some(SecretToken::new("s".into())),
                tokens: None,
                mtls: None,
            }),
            ..Default::default()
        };
        assert!(cfg.is_auth_configured());
    }

    #[test]
    fn test_is_auth_configured_none_type() {
        let cfg = ProxyConfig {
            auth: Some(AuthConfig {
                auth_type: Some("none".into()),
                secret: None,
                tokens: None,
                mtls: None,
            }),
            ..Default::default()
        };
        assert!(cfg.is_auth_configured());
    }

    #[test]
    fn test_is_auth_not_configured() {
        let cfg = ProxyConfig::default();
        assert!(!cfg.is_auth_configured());
    }

    #[test]
    fn test_condition_missing_operator_defaults() {
        let yaml = r#"
rules:
  - name: r
    action: deny
    conditions:
      - field: path
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let conds = &cfg.rules.unwrap()[0].conditions;
        assert_eq!(conds.len(), 1);
    }

    #[test]
    fn test_priority_sort_stable() {
        let yaml = r#"
rules:
  - name: a
    action: deny
    conditions:
      - field: path
        operator: equals
        value: /a
  - name: b
    action: deny
    priority: 100
    conditions:
      - field: path
        operator: equals
        value: /b
  - name: c
    action: deny
    priority: 100
    conditions:
      - field: path
        operator: equals
        value: /c
  - name: d
    action: deny
    priority: 50
    conditions:
      - field: path
        operator: equals
        value: /d
"#;
        let mut cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        cfg.sort_rules_by_priority();
        let names: Vec<&str> = cfg
            .rules
            .as_ref()
            .unwrap()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, vec!["b", "c", "d", "a"]);
    }

    #[test]
    fn test_tls_config_parsing() {
        let yaml = r#"
global:
  port: 2376
  tls:
    cert: /etc/docker-proxy/server.crt
    key: /etc/docker-proxy/server.key
    client_ca: /etc/docker-proxy/ca.crt
    require_client_cert: true
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let tls = cfg.global.as_ref().unwrap().tls.as_ref().unwrap();
        assert_eq!(tls.cert, "/etc/docker-proxy/server.crt");
        assert_eq!(tls.client_ca.as_deref(), Some("/etc/docker-proxy/ca.crt"));
        assert_eq!(tls.require_client_cert, Some(true));
    }

    #[test]
    fn test_mtls_role_map_parsing() {
        let yaml = r#"
auth:
  type: mtls
  mtls:
    cert_role_map:
      - cn: admin.example.com
        role: admin
      - cn: readonly.example.com
        role: readonly
    default_role: user
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        let mtls = cfg.auth.as_ref().unwrap().mtls.as_ref().unwrap();
        let map = mtls.cert_role_map.as_ref().unwrap();
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].cn, "admin.example.com");
        assert_eq!(map[0].role, "admin");
        assert_eq!(mtls.default_role.as_deref(), Some("user"));
    }

    #[test]
    fn test_dry_run_parsing() {
        let yaml = r#"
rules:
  - name: r
    action: deny
    dry_run: true
    conditions:
      - field: path
        operator: equals
        value: /x
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rules.unwrap()[0].dry_run, Some(true));
    }

    #[test]
    fn test_flat_conditions_and() {
        let yaml = r#"
rules:
  - name: r
    action: deny
    conditions:
      - field: path
        operator: equals
        value: /a
      - field: method
        operator: equals
        value: GET
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.rules.unwrap()[0].conditions.len(), 2);
    }

    #[test]
    fn test_validation_rejects_empty_action() {
        let yaml = r#"
rules:
  - name: r
    conditions:
      - field: path
        operator: equals
        value: /x
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_missing_require_role() {
        let yaml = r#"
rules:
  - name: r
    action: require_role
    conditions:
      - field: path
        operator: equals
        value: /x
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validation_accepts_valid_require_role() {
        let yaml = r#"
rules:
  - name: r
    action: require_role
    role: admin
    conditions:
      - field: path
        operator: equals
        value: /x
"#;
        let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.validate().is_ok());
    }
}
