use crate::config::{Condition, ConditionNode, ResponseFilterEntry, Rule};
use regex::Regex;
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use ipnet::IpNet;

const MAX_RATE_LIMIT_BUCKETS: usize = 16384;
const MAX_AUTH_LIMITER_KEYS: usize = 16384;

#[derive(Debug, Clone)]
pub enum RuleResult {
    Allow,
    Deny {
        status: u16,
        message: String,
    },
}

#[derive(Debug, Clone)]
pub struct RuleDecision {
    pub result: RuleResult,
    pub rule_name: Option<String>,
    pub action: Option<String>,
    pub dry_run: bool,
}

impl RuleDecision {
    pub fn allow() -> Self {
        RuleDecision {
            result: RuleResult::Allow,
            rule_name: None,
            action: None,
            dry_run: false,
        }
    }
}

pub struct EvaluationContext {
    pub path: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub client_ip: String,
    pub body_json: Option<JsonValue>,
    pub user_role: Option<String>,
}

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, RateBucket>>,
}

struct RateBucket {
    last_check: Instant,
    tokens: f64,
    max_tokens: f64,
    blocked_until: Option<Instant>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn check(&self, key: &str, max_requests: u64, period_secs: u64, penalty_secs: u64) -> bool {
        if max_requests == 0 {
            return false;
        }
        let max_tokens = max_requests as f64;
        let refill_rate = if period_secs == 0 {
            max_tokens
        } else {
            max_tokens / period_secs as f64
        };
        let now = Instant::now();

        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        if !buckets.contains_key(key) && buckets.len() >= MAX_RATE_LIMIT_BUCKETS {
            return false;
        }
        let bucket = buckets.entry(key.to_string()).or_insert_with(|| RateBucket {
            last_check: now,
            tokens: max_tokens,
            max_tokens,
            blocked_until: None,
        });

        if let Some(blocked) = bucket.blocked_until {
            if now < blocked {
                return false;
            }
            bucket.blocked_until = None;
            bucket.tokens = max_tokens;
            bucket.last_check = now;
        }

        let elapsed = (now - bucket.last_check).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_rate).min(max_tokens);
        bucket.last_check = now;
        bucket.max_tokens = max_tokens;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            bucket.blocked_until = Some(now + std::time::Duration::from_secs(penalty_secs));
            false
        }
    }

    pub fn cleanup(&self) {
        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        buckets.retain(|_, b| {
            if let Some(blocked) = b.blocked_until {
                now < blocked || b.tokens < b.max_tokens - 0.001
            } else {
                b.tokens < b.max_tokens - 0.001
            }
        });
    }
}

pub struct AuthLimiter {
    state: Mutex<HashMap<String, AuthLockoutState>>,
}

struct AuthLockoutState {
    failures: u32,
    first_failure: Instant,
    blocked_until: Option<Instant>,
}

impl AuthLimiter {
    pub fn new() -> Self {
        AuthLimiter {
            state: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_blocked(&self, key: &str) -> bool {
        let g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match g.get(key) {
            Some(s) => s.blocked_until.map_or(false, |u| Instant::now() < u),
            None => false,
        }
    }

    pub fn record_failure(&self, key: &str, max: u32, window: Duration, lockout: Duration) {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        if g.len() >= MAX_AUTH_LIMITER_KEYS && !g.contains_key(key) {
            return;
        }
        let entry = g.entry(key.to_string()).or_insert(AuthLockoutState {
            failures: 0,
            first_failure: now,
            blocked_until: None,
        });
        if let Some(u) = entry.blocked_until {
            if now >= u {
                entry.blocked_until = None;
                entry.failures = 0;
                entry.first_failure = now;
            }
        }
        if now.duration_since(entry.first_failure) > window {
            entry.failures = 0;
            entry.first_failure = now;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= max {
            entry.blocked_until = Some(now + lockout);
        }
    }

    pub fn record_success(&self, key: &str) {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        g.remove(key);
    }

    pub fn cleanup(&self) {
        let mut g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        g.retain(|_, s| match s.blocked_until {
            Some(u) => now < u,
            None => now.duration_since(s.first_failure) < Duration::from_secs(600),
        });
    }
}

fn json_get<'a>(root: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut current = root;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        if let JsonValue::Object(ref map) = current {
            current = map.get(segment)?;
        } else if let JsonValue::Array(ref arr) = current {
            let idx: usize = segment.parse().ok()?;
            current = arr.get(idx)?;
        } else {
            return None;
        }
    }
    Some(current)
}

fn json_get_mut<'a>(root: &'a mut JsonValue, path: &str) -> Option<&'a mut JsonValue> {
    let mut current = root;
    let segments: Vec<&str> = path.split('.').collect();
    let last_idx = segments.len().saturating_sub(1);
    for (i, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return None;
        }
        if i == last_idx {
            if let JsonValue::Object(ref mut map) = current {
                return map.get_mut(*segment);
            }
            if let JsonValue::Array(ref mut arr) = current {
                let idx: usize = segment.parse().ok()?;
                return arr.get_mut(idx);
            }
            return None;
        }
        if let JsonValue::Object(ref mut map) = current {
            current = map.get_mut(*segment)?;
        } else if let JsonValue::Array(ref mut arr) = current {
            let idx: usize = segment.parse().ok()?;
            current = arr.get_mut(idx)?;
        } else {
            return None;
        }
    }
    None
}

fn json_remove(root: &mut JsonValue, path: &str) -> bool {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    let parent_path = segments[..segments.len() - 1].join(".");
    let key = segments.last().unwrap();
    if let Some(parent) = json_get_mut(root, &parent_path) {
        if let JsonValue::Object(ref mut map) = parent {
            return map.remove(*key).is_some();
        }
    }
    false
}

fn yaml_value_to_string(value: &serde_yaml::Value) -> Option<String> {
    match value {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn match_path_condition(condition: &Condition, path: &str) -> bool {
    let val = match &condition.value {
        Some(v) => yaml_value_to_string(v),
        None => None,
    };

    match condition.operator.as_str() {
        "equals" => val.map_or(false, |v| path == v),
        "not_equals" => val.map_or(true, |v| path != v),
        "contains" => val.map_or(false, |v| path.contains(&v)),
        "not_contains" => val.map_or(true, |v| !path.contains(&v)),
        "starts_with" => val.map_or(false, |v| path.starts_with(&v)),
        "ends_with" => val.map_or(false, |v| path.ends_with(&v)),
        "matches" => val.map_or(false, |v| {
            Regex::new(&v).map(|r| r.is_match(path)).unwrap_or(false)
        }),
        "not_matches" => val.map_or(true, |v| {
            Regex::new(&v).map(|r| !r.is_match(path)).unwrap_or(true)
        }),
        "in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => seq.iter().any(|v| {
                yaml_value_to_string(v).map_or(false, |s| s == path)
            }),
            _ => false,
        },
        "not_in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => seq.iter().all(|v| {
                yaml_value_to_string(v).map_or(true, |s| s != path)
            }),
            _ => true,
        },
        _ => false,
    }
}

fn match_method_condition(condition: &Condition, method: &str) -> bool {
    let val = match &condition.value {
        Some(v) => yaml_value_to_string(v),
        None => None,
    };

    match condition.operator.as_str() {
        "equals" => val.map_or(false, |v| method.eq_ignore_ascii_case(&v)),
        "not_equals" => val.map_or(true, |v| !method.eq_ignore_ascii_case(&v)),
        "in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => seq.iter().any(|v| {
                yaml_value_to_string(v).map_or(false, |s| method.eq_ignore_ascii_case(&s))
            }),
            _ => false,
        },
        "not_in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => seq.iter().all(|v| {
                yaml_value_to_string(v).map_or(true, |s| !method.eq_ignore_ascii_case(&s))
            }),
            _ => true,
        },
        _ => false,
    }
}

fn match_header_condition(condition: &Condition, headers: &HashMap<String, String>, header_name: &str) -> bool {
    let header_val = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(header_name))
        .map(|(_, v)| v.as_str());
    let cond_val = condition.value.as_ref().and_then(yaml_value_to_string);

    match condition.operator.as_str() {
        "equals" => header_val.map_or(false, |v| cond_val.as_deref() == Some(v)),
        "not_equals" => header_val.map_or(true, |v| cond_val.as_deref() != Some(v)),
        "contains" => header_val.map_or(false, |v| cond_val.map_or(false, |cv| v.contains(&cv))),
        "not_contains" => header_val.map_or(true, |v| cond_val.map_or(true, |cv| !v.contains(&cv))),
        "starts_with" => header_val.map_or(false, |v| cond_val.map_or(false, |cv| v.starts_with(&cv))),
        "ends_with" => header_val.map_or(false, |v| cond_val.map_or(false, |cv| v.ends_with(&cv))),
        "matches" => header_val.map_or(false, |v| {
            cond_val.and_then(|cv| Regex::new(&cv).ok().map(|r| r.is_match(v))).unwrap_or(false)
        }),
        "exists" => header_val.is_some(),
        "not_exists" => header_val.is_none(),
        "in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => {
                header_val.map_or(false, |hv| seq.iter().any(|v| yaml_value_to_string(v).map_or(false, |s| s == hv)))
            }
            _ => false,
        },
        "not_in" => match &condition.value {
            Some(serde_yaml::Value::Sequence(seq)) => {
                header_val.map_or(true, |hv| seq.iter().all(|v| yaml_value_to_string(v).map_or(true, |s| s != hv)))
            }
            _ => true,
        },
        _ => false,
    }
}

fn match_ip_condition(condition: &Condition, client_ip_str: &str) -> bool {
    let client_ip: Option<IpAddr> = client_ip_str.parse().ok();

    match condition.operator.as_str() {
        "equals" => condition.value.as_ref().and_then(yaml_value_to_string).map_or(false, |v| {
            client_ip.map_or(false, |ip| ip.to_string() == v)
        }),
        "not_equals" => condition.value.as_ref().and_then(yaml_value_to_string).map_or(true, |v| {
            client_ip.map_or(true, |ip| ip.to_string() != v)
        }),
        "in" => {
            let cidrs: Vec<String> = match &condition.value {
                Some(serde_yaml::Value::Sequence(seq)) => seq
                    .iter()
                    .filter_map(|v| yaml_value_to_string(v))
                    .collect(),
                Some(v) => yaml_value_to_string(v).into_iter().collect(),
                None => vec![],
            };
            let ipnets: Vec<IpNet> = cidrs.iter().filter_map(|c| c.parse::<IpNet>().ok()).collect();
            if ipnets.is_empty() {
                client_ip.map_or(false, |ip| cidrs.iter().any(|s| s == &ip.to_string()))
            } else {
                client_ip.map_or(false, |ip| ipnets.iter().any(|net| net.contains(&ip)))
            }
        }
        "not_in" => {
            let cidrs: Vec<String> = match &condition.value {
                Some(serde_yaml::Value::Sequence(seq)) => seq
                    .iter()
                    .filter_map(|v| yaml_value_to_string(v))
                    .collect(),
                Some(v) => yaml_value_to_string(v).into_iter().collect(),
                None => vec![],
            };
            let ipnets: Vec<IpNet> = cidrs.iter().filter_map(|c| c.parse::<IpNet>().ok()).collect();
            if ipnets.is_empty() {
                client_ip.map_or(true, |ip| cidrs.iter().all(|s| s != &ip.to_string()))
            } else {
                client_ip.map_or(true, |ip| !ipnets.iter().any(|net| net.contains(&ip)))
            }
        }
        _ => false,
    }
}

fn match_body_condition(condition: &Condition, body_json: &Option<JsonValue>, field_path: &str) -> bool {
    let json_val = body_json.as_ref().and_then(|b| json_get(b, field_path));

    match condition.operator.as_str() {
        "exists" => json_val.is_some(),
        "not_exists" => json_val.is_none(),
        _ => {
            let cond_val = condition.value.as_ref();
            let json_val = match json_val {
                Some(v) => v,
                None => return false,
            };
            match condition.operator.as_str() {
                "equals" => cond_val.map_or(false, |cv| value_equal(cv, json_val)),
                "not_equals" => cond_val.map_or(true, |cv| !value_equal(cv, json_val)),
                "contains" => {
                    let json_str = match json_val {
                        JsonValue::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    cond_val
                        .and_then(yaml_value_to_string)
                        .map_or(false, |cv| json_str.contains(&cv))
                }
                "not_contains" => {
                    let json_str = match json_val {
                        JsonValue::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    cond_val
                        .and_then(yaml_value_to_string)
                        .map_or(true, |cv| !json_str.contains(&cv))
                }
                "in" => match cond_val {
                    Some(serde_yaml::Value::Sequence(seq)) => seq.iter().any(|v| value_equal(v, json_val)),
                    _ => false,
                },
                "not_in" => match cond_val {
                    Some(serde_yaml::Value::Sequence(seq)) => seq.iter().all(|v| !value_equal(v, json_val)),
                    _ => true,
                },
                "starts_with" => cond_val.and_then(yaml_value_to_string).map_or(false, |cv| {
                    let s = match json_val {
                        JsonValue::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    s.starts_with(&cv)
                }),
                "matches" => cond_val.and_then(yaml_value_to_string).map_or(false, |cv| {
                    let s = match json_val {
                        JsonValue::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    Regex::new(&cv).map(|r| r.is_match(&s)).unwrap_or(false)
                }),
                _ => false,
            }
        }
    }
}

fn value_equal(yaml_val: &serde_yaml::Value, json_val: &JsonValue) -> bool {
    match yaml_val {
        serde_yaml::Value::String(s) => json_val.as_str() == Some(s.as_str()),
        serde_yaml::Value::Bool(b) => json_val.as_bool() == Some(*b),
        serde_yaml::Value::Number(n) => {
            if let Some(json_n) = json_val.as_i64() {
                n.as_i64() == Some(json_n)
            } else if let Some(json_n) = json_val.as_u64() {
                n.as_u64() == Some(json_n)
            } else if let Some(json_n) = json_val.as_f64() {
                n.as_f64() == Some(json_n)
            } else {
                false
            }
        }
        _ => {
            match json_val {
                JsonValue::Null => matches!(yaml_val, serde_yaml::Value::Null),
                _ => false,
            }
        }
    }
}

pub fn evaluate_condition(condition: &Condition, ctx: &EvaluationContext) -> bool {
    match condition.field.as_str() {
        "method" => match_method_condition(condition, &ctx.method),
        "path" => match_path_condition(condition, &ctx.path),
        "client_ip" => match_ip_condition(condition, &ctx.client_ip),
        s if s.starts_with("header.") => {
            let header_name = &s[7..];
            match_header_condition(condition, &ctx.headers, header_name)
        }
        s if s.starts_with("body.") => {
            let field_path = &s[5..];
            match_body_condition(condition, &ctx.body_json, field_path)
        }
        _ => false,
    }
}

pub fn evaluate_node(node: &ConditionNode, ctx: &EvaluationContext) -> bool {
    match node {
        ConditionNode::Leaf(condition) => evaluate_condition(condition, ctx),
        ConditionNode::And { and } => and.iter().all(|n| evaluate_node(n, ctx)),
        ConditionNode::Or { or } => or.iter().any(|n| evaluate_node(n, ctx)),
    }
}

pub fn evaluate_request(rules: &[Rule], ctx: &EvaluationContext, rate_limiter: &RateLimiter) -> RuleResult {
    evaluate_request_detailed(rules, ctx, rate_limiter).result
}

pub fn evaluate_request_detailed(
    rules: &[Rule],
    ctx: &EvaluationContext,
    rate_limiter: &RateLimiter,
) -> RuleDecision {
    for rule in rules {
        if rule.conditions.is_empty() {
            continue;
        }

        let all_match = rule.conditions.iter().all(|c| evaluate_node(c, ctx));
        if !all_match {
            continue;
        }

        let is_dry = rule.dry_run.unwrap_or(false);

        match rule.action.as_str() {
            "deny" => {
                let status = rule.status.unwrap_or(403);
                let message = rule
                    .message
                    .clone()
                    .unwrap_or_else(|| "Forbidden by rule".to_string());
                if is_dry {
                    return RuleDecision {
                        result: RuleResult::Allow,
                        rule_name: Some(rule.name.clone()),
                        action: Some("deny".to_string()),
                        dry_run: true,
                    };
                }
                return RuleDecision {
                    result: RuleResult::Deny { status, message },
                    rule_name: Some(rule.name.clone()),
                    action: Some("deny".to_string()),
                    dry_run: false,
                };
            }
            "allow" => {
                return RuleDecision {
                    result: RuleResult::Allow,
                    rule_name: Some(rule.name.clone()),
                    action: Some("allow".to_string()),
                    dry_run: false,
                };
            }
            "require_role" => {
                let required = rule.role.as_deref().unwrap_or("admin");
                let user_role = ctx.user_role.as_deref().unwrap_or("");
                if user_role != "admin" && user_role != required {
                    let status = rule.status.unwrap_or(403);
                    let message = rule
                        .message
                        .clone()
                        .unwrap_or_else(|| format!("Role '{required}' required"));
                    if is_dry {
                        return RuleDecision {
                            result: RuleResult::Allow,
                            rule_name: Some(rule.name.clone()),
                            action: Some("require_role".to_string()),
                            dry_run: true,
                        };
                    }
                    return RuleDecision {
                        result: RuleResult::Deny { status, message },
                        rule_name: Some(rule.name.clone()),
                        action: Some("require_role".to_string()),
                        dry_run: false,
                    };
                }
            }
            "response_filter" => {
                continue;
            }
            "rate_limit" => {
                if let Some(ref rl_config) = rule.rate_limit {
                    let key = format!("{}:{}", rule.name, ctx.client_ip);
                    if !rate_limiter.check(&key, rl_config.requests, rl_config.period, rl_config.penalty) {
                        let status = rule.status.unwrap_or(429);
                        let message = rule
                            .message
                            .clone()
                            .unwrap_or_else(|| "Rate limit exceeded".to_string());
                        if is_dry {
                            return RuleDecision {
                                result: RuleResult::Allow,
                                rule_name: Some(rule.name.clone()),
                                action: Some("rate_limit".to_string()),
                                dry_run: true,
                            };
                        }
                        return RuleDecision {
                            result: RuleResult::Deny { status, message },
                            rule_name: Some(rule.name.clone()),
                            action: Some("rate_limit".to_string()),
                            dry_run: false,
                        };
                    }
                }
            }
            _ => {
                continue;
            }
        }
    }

    RuleDecision::allow()
}

pub fn collect_response_filters(
    rules: &[Rule],
    ctx: &EvaluationContext,
) -> Vec<ResponseFilterEntry> {
    let mut all_filters = Vec::new();
    for rule in rules {
        if rule.conditions.is_empty()
            || !rule.conditions.iter().all(|c| evaluate_node(c, ctx))
        {
            continue;
        }
        if let Some(ref filters) = rule.response_filter {
            all_filters.extend(filters.clone());
        }
    }
    all_filters
}

pub fn apply_response_filters(filters: &[ResponseFilterEntry], body: &[u8]) -> Vec<u8> {
    if filters.is_empty() {
        return body.to_vec();
    }

    let mut json: JsonValue = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return body.to_vec(),
    };

    for filter in filters {
        match filter.action.as_str() {
            "redact" => {
                if let Some(target) = json_get_mut(&mut json, &filter.field) {
                    *target = JsonValue::String("***REDACTED***".to_string());
                }
            }
            "remove" => {
                let segments: Vec<&str> = filter.field.split('.').collect();
                if segments.len() == 1 {
                    if let JsonValue::Object(ref mut map) = json {
                        map.remove(&filter.field);
                    }
                } else {
                    json_remove(&mut json, &filter.field);
                }
            }
            "replace" => {
                let replacement = filter.replacement.as_deref().unwrap_or("");
                if let Some(target) = json_get_mut(&mut json, &filter.field) {
                    *target = JsonValue::String(replacement.to_string());
                }
            }
            _ => {}
        }
    }

    serde_json::to_vec(&json).unwrap_or_else(|_| body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Condition, ConditionNode, RateLimitConfig, ResponseFilterEntry, Rule};
    use serde_json::json;
    use std::collections::HashMap;
    use std::thread;
    use std::time::Duration;

    fn make_ctx(path: &str, method: &str, ip: &str) -> EvaluationContext {
        EvaluationContext {
            path: path.to_string(),
            method: method.to_string(),
            headers: HashMap::new(),
            client_ip: ip.to_string(),
            body_json: None,
            user_role: None,
        }
    }

    fn make_condition(field: &str, operator: &str, value: Option<serde_yaml::Value>) -> Condition {
        Condition { field: field.to_string(), operator: operator.to_string(), value }
    }

    // --- Path conditions ---

    #[test]
    fn test_path_equals() {
        let c = make_condition("path", "equals", Some(serde_yaml::Value::String("/test".into())));
        assert!(evaluate_condition(&c, &make_ctx("/test", "GET", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/other", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_path_starts_with() {
        let c = make_condition("path", "starts_with", Some(serde_yaml::Value::String("/containers".into())));
        assert!(evaluate_condition(&c, &make_ctx("/containers/json", "GET", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/images/json", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_path_matches_regex() {
        let c = make_condition("path", "matches", Some(serde_yaml::Value::String(r"^/containers/[^/]+/exec$".into())));
        assert!(evaluate_condition(&c, &make_ctx("/containers/abc123/exec", "POST", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/containers/abc123/start", "POST", "127.0.0.1")));
    }

    #[test]
    fn test_path_in() {
        let c = Condition {
            field: "path".into(),
            operator: "in".into(),
            value: Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("/a".into()),
                serde_yaml::Value::String("/b".into()),
            ])),
        };
        assert!(evaluate_condition(&c, &make_ctx("/a", "GET", "127.0.0.1")));
        assert!(evaluate_condition(&c, &make_ctx("/b", "GET", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/c", "GET", "127.0.0.1")));
    }

    // --- Method conditions ---

    #[test]
    fn test_method_equals() {
        let c = make_condition("method", "equals", Some(serde_yaml::Value::String("POST".into())));
        assert!(evaluate_condition(&c, &make_ctx("/", "POST", "127.0.0.1")));
        assert!(evaluate_condition(&c, &make_ctx("/", "post", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_method_not_equals() {
        let c = make_condition("method", "not_equals", Some(serde_yaml::Value::String("GET".into())));
        assert!(evaluate_condition(&c, &make_ctx("/", "POST", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_method_in() {
        let c = Condition {
            field: "method".into(),
            operator: "in".into(),
            value: Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("POST".into()),
                serde_yaml::Value::String("PUT".into()),
            ])),
        };
        assert!(evaluate_condition(&c, &make_ctx("/", "POST", "127.0.0.1")));
        assert!(evaluate_condition(&c, &make_ctx("/", "put", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "127.0.0.1")));
    }

    // --- IP conditions ---

    #[test]
    fn test_ip_in_cidr() {
        let c = Condition {
            field: "client_ip".into(),
            operator: "in".into(),
            value: Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("10.0.0.0/8".into()),
                serde_yaml::Value::String("127.0.0.0/8".into()),
            ])),
        };
        assert!(evaluate_condition(&c, &make_ctx("/", "GET", "10.1.2.3")));
        assert!(evaluate_condition(&c, &make_ctx("/", "GET", "127.0.0.1")));
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "192.168.1.1")));
    }

    #[test]
    fn test_ip_not_in_cidr() {
        let c = Condition {
            field: "client_ip".into(),
            operator: "not_in".into(),
            value: Some(serde_yaml::Value::Sequence(vec![
                serde_yaml::Value::String("10.0.0.0/8".into()),
            ])),
        };
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "10.1.2.3")));
        assert!(evaluate_condition(&c, &make_ctx("/", "GET", "192.168.1.1")));
    }

    #[test]
    fn test_ip_equals() {
        let c = make_condition("client_ip", "equals", Some(serde_yaml::Value::String("1.2.3.4".into())));
        assert!(evaluate_condition(&c, &make_ctx("/", "GET", "1.2.3.4")));
        assert!(!evaluate_condition(&c, &make_ctx("/", "GET", "5.6.7.8")));
    }

    // --- Body conditions ---

    #[test]
    fn test_body_equals_bool() {
        let c = make_condition("body.HostConfig.Privileged", "equals", Some(serde_yaml::Value::Bool(true)));
        let mut ctx = make_ctx("/containers/create", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"HostConfig": {"Privileged": true}}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"HostConfig": {"Privileged": false}}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_body_equals_string() {
        let c = make_condition("body.HostConfig.NetworkMode", "equals", Some(serde_yaml::Value::String("host".into())));
        let mut ctx = make_ctx("/containers/create", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"HostConfig": {"NetworkMode": "host"}}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"HostConfig": {"NetworkMode": "bridge"}}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_body_exists() {
        let c = Condition { field: "body.HostConfig.Binds".into(), operator: "exists".into(), value: None };
        let mut ctx = make_ctx("/containers/create", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"HostConfig": {"Binds": ["/tmp:/tmp"]}}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"HostConfig": {}}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_body_not_exists() {
        let c = Condition { field: "body.HostConfig.Binds".into(), operator: "not_exists".into(), value: None };
        let mut ctx = make_ctx("/containers/create", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"HostConfig": {}}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"HostConfig": {"Binds": []}}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_body_contains() {
        let c = make_condition("body.Image", "contains", Some(serde_yaml::Value::String("nginx".into())));
        let mut ctx = make_ctx("/containers/create", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"Image": "nginx:latest"}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"Image": "alpine"}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_body_number_equals() {
        let c = make_condition("body.Count", "equals", Some(serde_yaml::Value::Number(serde_yaml::Number::from(42))));
        let mut ctx = make_ctx("/", "POST", "127.0.0.1");
        ctx.body_json = Some(json!({"Count": 42}));
        assert!(evaluate_condition(&c, &ctx));

        ctx.body_json = Some(json!({"Count": 99}));
        assert!(!evaluate_condition(&c, &ctx));
    }

    // --- Header conditions ---

    #[test]
    fn test_header_equals() {
        let c = make_condition("header.content-type", "equals", Some(serde_yaml::Value::String("application/json".into())));
        let mut ctx = make_ctx("/", "POST", "127.0.0.1");
        ctx.headers.insert("content-type".into(), "application/json".into());
        assert!(evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_header_case_insensitive() {
        let c = make_condition("header.x-custom", "equals", Some(serde_yaml::Value::String("hello".into())));
        let mut ctx = make_ctx("/", "GET", "127.0.0.1");
        ctx.headers.insert("X-Custom".into(), "hello".into());
        assert!(evaluate_condition(&c, &ctx));
    }

    #[test]
    fn test_header_exists() {
        let c = Condition { field: "header.authorization".into(), operator: "exists".into(), value: None };
        let mut ctx = make_ctx("/", "GET", "127.0.0.1");
        assert!(!evaluate_condition(&c, &ctx));
        ctx.headers.insert("authorization".into(), "Bearer x".into());
        assert!(evaluate_condition(&c, &ctx));
    }

    // --- Condition node evaluation ---

    #[test]
    fn test_or_node_matches_any() {
        let node = ConditionNode::Or {
            or: vec![
                ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/a".into())))),
                ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/b".into())))),
            ],
        };
        assert!(evaluate_node(&node, &make_ctx("/a", "GET", "127.0.0.1")));
        assert!(evaluate_node(&node, &make_ctx("/b", "GET", "127.0.0.1")));
        assert!(!evaluate_node(&node, &make_ctx("/c", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_and_node_matches_all() {
        let node = ConditionNode::And {
            and: vec![
                ConditionNode::Leaf(make_condition("path", "starts_with", Some(serde_yaml::Value::String("/volumes".into())))),
                ConditionNode::Leaf(make_condition("method", "not_equals", Some(serde_yaml::Value::String("GET".into())))),
            ],
        };
        assert!(evaluate_node(&node, &make_ctx("/volumes/create", "POST", "127.0.0.1")));
        assert!(!evaluate_node(&node, &make_ctx("/volumes", "GET", "127.0.0.1")));
    }

    #[test]
    fn test_nested_and_or() {
        let node = ConditionNode::And {
            and: vec![
                ConditionNode::Or {
                    or: vec![
                        ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/a".into())))),
                        ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/b".into())))),
                    ],
                },
                ConditionNode::Leaf(make_condition("method", "equals", Some(serde_yaml::Value::String("POST".into())))),
            ],
        };
        assert!(evaluate_node(&node, &make_ctx("/a", "POST", "127.0.0.1")));
        assert!(evaluate_node(&node, &make_ctx("/b", "POST", "127.0.0.1")));
        assert!(!evaluate_node(&node, &make_ctx("/a", "GET", "127.0.0.1")));
        assert!(!evaluate_node(&node, &make_ctx("/c", "POST", "127.0.0.1")));
    }

    // --- Rate limiter ---

    #[test]
    fn test_rate_limiter_allows_up_to_limit() {
        let rl = RateLimiter::new();
        for i in 0..5 {
            assert!(rl.check("test-ip", 5, 60, 60), "request {} should pass", i);
        }
    }

    #[test]
    fn test_rate_limiter_blocks_after_limit() {
        let rl = RateLimiter::new();
        for _ in 0..5 {
            assert!(rl.check("test-ip-2", 5, 60, 60));
        }
        assert!(!rl.check("test-ip-2", 5, 60, 60), "6th request should be blocked");
    }

    #[test]
    fn test_rate_limiter_penalty_active() {
        let rl = RateLimiter::new();
        for _ in 0..3 {
            assert!(rl.check("test-penalty", 3, 60, 60));
        }
        assert!(!rl.check("test-penalty", 3, 60, 60), "should be penalized");
        // still penalized immediately after
        assert!(!rl.check("test-penalty", 3, 60, 60));
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let rl = RateLimiter::new();
        rl.check("ip-a", 10, 60, 60);
        rl.check("ip-b", 10, 60, 60);
        // ip-a hasn't exceeded, ip-b hasn't either, both full -> cleanup removes them
        rl.cleanup();
        // After cleanup, they should be re-created fresh
        assert!(rl.check("ip-a", 10, 60, 60));
        assert!(rl.check("ip-b", 10, 60, 60));
    }

    #[test]
    fn test_rate_limiter_penalty_does_not_refill() {
        let rl = RateLimiter::new();
        for _ in 0..3 {
            assert!(rl.check("penalty-stick", 3, 60, 60));
        }
        assert!(!rl.check("penalty-stick", 3, 60, 60));
        // After a short wait (much less than penalty), still blocked
        thread::sleep(Duration::from_millis(100));
        assert!(!rl.check("penalty-stick", 3, 60, 60));
    }

    // --- Response filtering ---

    #[test]
    fn test_response_filter_redact() {
        let body = json!({"Config": {"Env": ["A=1", "B=2"], "Cmd": ["sh"]}});
        let filters = vec![ResponseFilterEntry {
            field: "Config.Env".into(),
            action: "redact".into(),
            replacement: None,
        }];
        let result = apply_response_filters(&filters, &serde_json::to_vec(&body).unwrap());
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(filtered["Config"]["Env"], "***REDACTED***");
        assert_eq!(filtered["Config"]["Cmd"][0], "sh");
    }

    #[test]
    fn test_response_filter_remove() {
        let body = json!({"Config": {"Env": ["A=1"], "Cmd": ["sh"]}});
        let filters = vec![ResponseFilterEntry {
            field: "Config.Env".into(),
            action: "remove".into(),
            replacement: None,
        }];
        let result = apply_response_filters(&filters, &serde_json::to_vec(&body).unwrap());
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(filtered["Config"].get("Env").is_none());
        assert_eq!(filtered["Config"]["Cmd"][0], "sh");
    }

    #[test]
    fn test_response_filter_replace() {
        let body = json!({"Name": "secret-container"});
        let filters = vec![ResponseFilterEntry {
            field: "Name".into(),
            action: "replace".into(),
            replacement: Some("hidden".into()),
        }];
        let result = apply_response_filters(&filters, &serde_json::to_vec(&body).unwrap());
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(filtered["Name"], "hidden");
    }

    #[test]
    fn test_response_filter_remove_top_level() {
        let body = json!({"Command": "ls", "Id": "abc"});
        let filters = vec![ResponseFilterEntry {
            field: "Command".into(),
            action: "remove".into(),
            replacement: None,
        }];
        let result = apply_response_filters(&filters, &serde_json::to_vec(&body).unwrap());
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert!(filtered.get("Command").is_none());
        assert_eq!(filtered["Id"], "abc");
    }

    #[test]
    fn test_response_filter_non_json_passthrough() {
        let body = b"not json";
        let filters = vec![ResponseFilterEntry {
            field: "anything".into(),
            action: "redact".into(),
            replacement: None,
        }];
        let result = apply_response_filters(&filters, body);
        assert_eq!(result, body);
    }

    #[test]
    fn test_response_filter_array_index() {
        let body = json!({"Items": [{"Name": "a"}, {"Name": "b"}]});
        let filters = vec![ResponseFilterEntry {
            field: "Items.0.Name".into(),
            action: "redact".into(),
            replacement: None,
        }];
        let result = apply_response_filters(&filters, &serde_json::to_vec(&body).unwrap());
        let filtered: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(filtered["Items"][0]["Name"], "***REDACTED***");
        assert_eq!(filtered["Items"][1]["Name"], "b");
    }

    // --- evaluate_request ---

    #[test]
    fn test_evaluate_request_deny() {
        let rules = vec![Rule {
            name: "block".into(),
            action: "deny".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/secret".into()))))],
            status: Some(403),
            message: Some("blocked".into()),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        let result = evaluate_request(&rules, &make_ctx("/secret", "GET", "127.0.0.1"), &rl);
        match result {
            RuleResult::Deny { status, message } => {
                assert_eq!(status, 403);
                assert_eq!(message, "blocked");
            }
            _ => panic!("expected Deny"),
        }
    }

    #[test]
    fn test_evaluate_request_allow_default() {
        let rules: Vec<Rule> = vec![];
        let rl = RateLimiter::new();
        let result = evaluate_request(&rules, &make_ctx("/anything", "GET", "127.0.0.1"), &rl);
        assert!(matches!(result, RuleResult::Allow));
    }

    #[test]
    fn test_evaluate_request_require_role_admin_passes() {
        let rules = vec![Rule {
            name: "admin-only".into(),
            action: "require_role".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/create".into()))))],
            role: Some("admin".into()),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        let mut ctx = make_ctx("/create", "POST", "127.0.0.1");
        ctx.user_role = Some("admin".into());
        let result = evaluate_request(&rules, &ctx, &rl);
        assert!(matches!(result, RuleResult::Allow));
    }

    #[test]
    fn test_evaluate_request_require_role_readonly_blocked() {
        let rules = vec![Rule {
            name: "admin-only".into(),
            action: "require_role".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/create".into()))))],
            role: Some("admin".into()),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        let mut ctx = make_ctx("/create", "POST", "127.0.0.1");
        ctx.user_role = Some("readonly".into());
        let result = evaluate_request(&rules, &ctx, &rl);
        assert!(matches!(result, RuleResult::Deny { .. }));
    }

    #[test]
    fn test_evaluate_request_rate_limit_exceeded() {
        let rules = vec![Rule {
            name: "rl".into(),
            action: "rate_limit".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "matches", Some(serde_yaml::Value::String("^/".into()))))],
            rate_limit: Some(RateLimitConfig { requests: 2, period: 60, penalty: 60 }),
            status: Some(429),
            message: Some("too fast".into()),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        let ctx = make_ctx("/test", "GET", "10.0.0.1");
        assert!(matches!(evaluate_request(&rules, &ctx, &rl), RuleResult::Allow));
        assert!(matches!(evaluate_request(&rules, &ctx, &rl), RuleResult::Allow));
        assert!(matches!(evaluate_request(&rules, &ctx, &rl), RuleResult::Deny { status: 429, .. }));
    }

    #[test]
    fn test_collect_response_filters() {
        let rules = vec![Rule {
            name: "filter".into(),
            action: "response_filter".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/json".into()))))],
            response_filter: Some(vec![
                ResponseFilterEntry { field: "Env".into(), action: "redact".into(), replacement: None },
            ]),
            ..Default::default()
        }];
        let filters = collect_response_filters(&rules, &make_ctx("/json", "GET", "127.0.0.1"));
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].field, "Env");
    }

    #[test]
    fn test_collect_response_filters_no_match() {
        let rules = vec![Rule {
            name: "filter".into(),
            action: "response_filter".into(),
            conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/json".into()))))],
            response_filter: Some(vec![
                ResponseFilterEntry { field: "Env".into(), action: "redact".into(), replacement: None },
            ]),
            ..Default::default()
        }];
        let filters = collect_response_filters(&rules, &make_ctx("/other", "GET", "127.0.0.1"));
        assert_eq!(filters.len(), 0);
    }

    #[test]
    fn test_allow_short_circuits() {
        let rules = vec![
            Rule {
                name: "allow".into(),
                action: "allow".into(),
                conditions: vec![ConditionNode::Leaf(make_condition("path", "equals", Some(serde_yaml::Value::String("/ping".into()))))],
                ..Default::default()
            },
            Rule {
                name: "block".into(),
                action: "deny".into(),
                conditions: vec![ConditionNode::Leaf(make_condition("path", "matches", Some(serde_yaml::Value::String("^/".into()))))],
                ..Default::default()
            },
        ];
        let rl = RateLimiter::new();
        let result = evaluate_request(&rules, &make_ctx("/ping", "GET", "127.0.0.1"), &rl);
        assert!(matches!(result, RuleResult::Allow));
    }

    #[test]
    fn test_auth_limiter_blocks_after_threshold() {
        let al = AuthLimiter::new();
        let key = "1.2.3.4";
        for _ in 0..3 {
            al.record_failure(key, 3, Duration::from_secs(60), Duration::from_secs(60));
        }
        assert!(al.is_blocked(key));
    }

    #[test]
    fn test_auth_limiter_success_clears_state() {
        let al = AuthLimiter::new();
        let key = "5.6.7.8";
        al.record_failure(key, 3, Duration::from_secs(60), Duration::from_secs(60));
        al.record_success(key);
        assert!(!al.is_blocked(key));
    }

    #[test]
    fn test_dry_run_returns_allow_with_metadata() {
        let rules = vec![Rule {
            name: "would-block".into(),
            action: "deny".into(),
            conditions: vec![ConditionNode::Leaf(make_condition(
                "path",
                "equals",
                Some(serde_yaml::Value::String("/x".into())),
            ))],
            dry_run: Some(true),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        let decision = evaluate_request_detailed(&rules, &make_ctx("/x", "GET", "1.1.1.1"), &rl);
        assert!(matches!(decision.result, RuleResult::Allow));
        assert!(decision.dry_run);
        assert_eq!(decision.rule_name.as_deref(), Some("would-block"));
        assert_eq!(decision.action.as_deref(), Some("deny"));
    }

    #[test]
    fn test_dry_run_rate_limit_does_not_block() {
        let rules = vec![Rule {
            name: "rl-dry".into(),
            action: "rate_limit".into(),
            conditions: vec![ConditionNode::Leaf(make_condition(
                "path",
                "matches",
                Some(serde_yaml::Value::String("^/".into())),
            ))],
            rate_limit: Some(crate::config::RateLimitConfig { requests: 1, period: 60, penalty: 60 }),
            dry_run: Some(true),
            ..Default::default()
        }];
        let rl = RateLimiter::new();
        for _ in 0..5 {
            let d = evaluate_request_detailed(&rules, &make_ctx("/x", "GET", "2.2.2.2"), &rl);
            assert!(matches!(d.result, RuleResult::Allow));
        }
    }

    #[test]
    fn test_auth_limiter_window_resets_failures() {
        let al = AuthLimiter::new();
        let key = "9.9.9.9";
        al.record_failure(key, 5, Duration::from_millis(50), Duration::from_secs(60));
        thread::sleep(Duration::from_millis(80));
        al.record_failure(key, 5, Duration::from_millis(50), Duration::from_secs(60));
        assert!(!al.is_blocked(key));
    }
}
