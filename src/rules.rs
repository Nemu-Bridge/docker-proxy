use crate::config::{Condition, ConditionNode, ResponseFilterEntry, Rule};
use regex::Regex;
use serde_json::Value as JsonValue;
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::Instant,
};

use ipnet::IpNet;

#[derive(Debug, Clone)]
pub enum RuleResult {
    Allow,
    Deny {
        status: u16,
        message: String,
    },
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
        let max_tokens = max_requests as f64;
        let refill_rate = max_tokens / period_secs as f64;
        let now = Instant::now();

        let mut buckets = self.buckets.lock().unwrap();
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
        let mut buckets = self.buckets.lock().unwrap();
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
    for rule in rules {
        if rule.conditions.is_empty() {
            continue;
        }

        let all_match = rule.conditions.iter().all(|c| evaluate_node(c, ctx));
        if !all_match {
            continue;
        }

        match rule.action.as_str() {
            "deny" => {
                let status = rule.status.unwrap_or(403);
                let message = rule
                    .message
                    .clone()
                    .unwrap_or_else(|| "Forbidden by rule".to_string());
                return RuleResult::Deny {
                    status,
                    message,
                };
            }
            "allow" => {
                return RuleResult::Allow;
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
                    return RuleResult::Deny {
                        status,
                        message,
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
                        return RuleResult::Deny {
                            status,
                            message,
                        };
                    }
                }
            }
            _ => {
                continue;
            }
        }
    }

    RuleResult::Allow
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
