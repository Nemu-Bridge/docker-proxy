use docker_proxy::config::{yaml_value_to_string, Condition, ConditionNode, ProxyConfig, Rule};
use docker_proxy::metrics::Metrics;
use docker_proxy::rules::{
    evaluate_request, evaluate_request_detailed, AuthLimiter, EvaluationContext, RateLimiter,
    RuleResult,
};
use docker_proxy::tls;
use docker_proxy::upgrade::is_upgrade_request;
use hyper::header::{HeaderMap, HeaderValue};
use regex::Regex;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

fn make_condition(field: &str, operator: &str, value: Option<serde_yaml::Value>) -> Condition {
    let mut condition = Condition {
        compiled_regex: None,
        field: field.to_string(),
        operator: operator.to_string(),
        value,
    };
    if matches!(condition.operator.as_str(), "matches" | "not_matches") {
        if let Some(ref v) = condition.value {
            if let Some(s) = yaml_value_to_string(v) {
                condition.compiled_regex = Regex::new(&s).ok();
            }
        }
    }
    condition
}

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

#[test]
fn integration_deny_secrets_allow_containers() {
    let rules = vec![Rule {
        name: "block-secrets".into(),
        action: "deny".into(),
        conditions: vec![ConditionNode::Leaf(make_condition(
            "path",
            "starts_with",
            Some(serde_yaml::Value::String("/secrets".into())),
        ))],
        message: Some("secrets blocked".into()),
        status: Some(403),
        ..Default::default()
    }];

    let rl = RateLimiter::new();

    let result = evaluate_request(&rules, &make_ctx("/secrets", "GET", "10.0.0.1"), &rl);
    assert!(matches!(result, RuleResult::Deny { status: 403, .. }));

    let result = evaluate_request(
        &rules,
        &make_ctx("/containers/json", "GET", "10.0.0.1"),
        &rl,
    );
    assert!(matches!(result, RuleResult::Allow));
}

#[test]
fn integration_role_admin_overrides_readonly() {
    let rules = vec![Rule {
        name: "admin-only".into(),
        action: "require_role".into(),
        conditions: vec![ConditionNode::Leaf(make_condition(
            "method",
            "equals",
            Some(serde_yaml::Value::String("DELETE".into())),
        ))],
        role: Some("admin".into()),
        message: Some("admin required".into()),
        ..Default::default()
    }];

    let rl = RateLimiter::new();

    let mut ctx = make_ctx("/containers/test", "DELETE", "10.0.0.1");
    ctx.user_role = Some("admin".into());
    assert!(matches!(
        evaluate_request(&rules, &ctx, &rl),
        RuleResult::Allow
    ));

    ctx.user_role = Some("readonly".into());
    assert!(matches!(
        evaluate_request(&rules, &ctx, &rl),
        RuleResult::Deny { .. }
    ));

    ctx.user_role = None;
    assert!(matches!(
        evaluate_request(&rules, &ctx, &rl),
        RuleResult::Deny { .. }
    ));
}

#[test]
fn integration_rate_limit_per_ip_isolation() {
    let rules = vec![Rule {
        name: "rl".into(),
        action: "rate_limit".into(),
        conditions: vec![ConditionNode::Leaf(make_condition(
            "path",
            "matches",
            Some(serde_yaml::Value::String("^/".into())),
        ))],
        rate_limit: Some(docker_proxy::config::RateLimitConfig {
            requests: 3,
            period: 60,
            penalty: 60,
        }),
        status: Some(429),
        ..Default::default()
    }];

    let rl = RateLimiter::new();

    // IP 1 uses all 3 requests
    for _ in 0..3 {
        assert!(matches!(
            evaluate_request(&rules, &make_ctx("/test", "GET", "10.0.0.1"), &rl),
            RuleResult::Allow
        ));
    }
    // IP 1 is now rate limited
    assert!(matches!(
        evaluate_request(&rules, &make_ctx("/test", "GET", "10.0.0.1"), &rl),
        RuleResult::Deny { status: 429, .. }
    ));

    // IP 2 still has full quota
    assert!(matches!(
        evaluate_request(&rules, &make_ctx("/test", "GET", "10.0.0.2"), &rl),
        RuleResult::Allow
    ));
}

#[test]
fn integration_parse_production_config() {
    let yaml = include_str!("../examples/config-production.yaml");
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).expect("production config should parse");
    assert!(cfg.auth.is_some());
    assert!(cfg.rules.is_some());
    assert!(cfg.rules.unwrap().len() > 10);
}

#[test]
fn integration_parse_minimal_config() {
    let yaml = include_str!("../examples/config-minimal.yaml");
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).expect("minimal config should parse");
    assert_eq!(
        cfg.auth.as_ref().unwrap().auth_type.as_deref(),
        Some("none")
    );
}

#[test]
fn integration_parse_readonly_config() {
    let yaml = include_str!("../examples/config-readonly.yaml");
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).expect("readonly config should parse");
    let rules = cfg.rules.unwrap();
    assert_eq!(rules.len(), 2);
}

#[test]
fn integration_parse_tls_example() {
    let yaml = include_str!("../examples/config-tls.yaml");
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).expect("tls example must parse");
    let tls_cfg = cfg.global.as_ref().unwrap().tls.as_ref().unwrap();
    assert!(tls_cfg.cert.ends_with("server.crt"));
    assert!(tls_cfg.key.ends_with("server.key"));
    assert!(cfg.global.as_ref().unwrap().metrics.is_some());
}

#[test]
fn integration_parse_mtls_example() {
    let yaml = include_str!("../examples/config-mtls.yaml");
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).expect("mtls example must parse");
    let auth = cfg.auth.as_ref().unwrap();
    assert_eq!(auth.auth_type.as_deref(), Some("mtls"));
    let mtls = auth.mtls.as_ref().unwrap();
    let map = mtls.cert_role_map.as_ref().unwrap();
    assert!(map
        .iter()
        .any(|m| m.cn == "admin.ops.example.com" && m.role == "admin"));
    assert_eq!(mtls.default_role.as_deref(), Some("user"));
    let dry_run_rule = cfg
        .rules
        .as_ref()
        .unwrap()
        .iter()
        .find(|r| r.name == "watch-new-image-pulls")
        .expect("dry-run rule must exist");
    assert_eq!(dry_run_rule.dry_run, Some(true));
}

#[test]
fn integration_priority_promotes_high_value_rule() {
    let yaml = r#"
rules:
  - name: low
    priority: 1
    action: deny
    conditions:
      - field: path
        operator: equals
        value: /x
  - name: high
    priority: 100
    action: allow
    conditions:
      - field: path
        operator: equals
        value: /x
"#;
    let mut cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    cfg.sort_rules_by_priority();
    let rules = cfg.rules.as_ref().unwrap();
    assert_eq!(rules[0].name, "high");
    let rl = RateLimiter::new();
    let ctx = EvaluationContext {
        path: "/x".into(),
        method: "GET".into(),
        headers: HashMap::new(),
        client_ip: "1.1.1.1".into(),
        body_json: None,
        user_role: None,
    };
    let result = evaluate_request(rules, &ctx, &rl);
    assert!(matches!(result, RuleResult::Allow));
}

#[test]
fn integration_dry_run_audit_flow() {
    let rules = vec![Rule {
        name: "would-deny".into(),
        action: "deny".into(),
        conditions: vec![ConditionNode::Leaf(make_condition(
            "path",
            "equals",
            Some(serde_yaml::Value::String("/danger".into())),
        ))],
        dry_run: Some(true),
        ..Default::default()
    }];
    let rl = RateLimiter::new();
    let decision = evaluate_request_detailed(&rules, &make_ctx("/danger", "POST", "5.5.5.5"), &rl);
    assert!(matches!(decision.result, RuleResult::Allow));
    assert!(decision.dry_run);
    assert_eq!(decision.rule_name.as_deref(), Some("would-deny"));
}

#[test]
fn integration_metrics_render_includes_all_counters() {
    let m = Metrics::new();
    m.requests_total.fetch_add(5, Ordering::Relaxed);
    m.requests_denied.fetch_add(2, Ordering::Relaxed);
    m.requests_allowed.fetch_add(3, Ordering::Relaxed);
    m.auth_failures_total.fetch_add(1, Ordering::Relaxed);
    m.upgrade_total.fetch_add(1, Ordering::Relaxed);
    m.request_timeouts_total.fetch_add(1, Ordering::Relaxed);
    m.observe_upstream_latency_ms(40);
    m.record_rule_deny("block-secrets", false);

    let out = m.render_prometheus();
    for key in [
        "docker_proxy_requests_total",
        "docker_proxy_requests_denied_total",
        "docker_proxy_requests_allowed_total",
        "docker_proxy_auth_failures_total",
        "docker_proxy_upgrade_total",
        "docker_proxy_request_timeouts_total",
        "docker_proxy_upstream_latency_ms_count",
        "rule=\"block-secrets\"",
    ] {
        assert!(out.contains(key), "metrics output missing {key}: {out}");
    }
}

#[test]
fn integration_mtls_role_resolution_full_path() {
    let id = tls::CertIdentity {
        common_name: Some("svc-7.readonly.ops.example.com".into()),
        sans: vec!["svc-7.readonly.ops.example.com".into()],
    };
    let mtls = docker_proxy::config::MtlsConfig {
        cert_role_map: Some(vec![docker_proxy::config::CertRoleMapping {
            cn: "*.readonly.ops.example.com".into(),
            role: "readonly".into(),
        }]),
        default_role: Some("user".into()),
    };
    assert_eq!(
        tls::resolve_mtls_role(&id, Some(&mtls)).as_deref(),
        Some("readonly")
    );
}

#[test]
fn integration_build_tls_server_config_from_real_cert() {
    use std::io::Write;
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("self-signed cert generation");
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("server.crt");
    let key_path = dir.path().join("server.key");
    std::fs::File::create(&cert_path)
        .unwrap()
        .write_all(cert.cert.pem().as_bytes())
        .unwrap();
    std::fs::File::create(&key_path)
        .unwrap()
        .write_all(cert.key_pair.serialize_pem().as_bytes())
        .unwrap();
    tls::install_default_crypto_provider();
    let tls_cfg = docker_proxy::config::TlsConfig {
        cert: cert_path.to_string_lossy().to_string(),
        key: key_path.to_string_lossy().to_string(),
        client_ca: None,
        require_client_cert: None,
    };
    let sc = tls::build_server_config(&tls_cfg).expect("server config must build");
    assert!(Arc::strong_count(&sc) >= 1);
}

#[test]
fn integration_upgrade_detection() {
    let mut h = HeaderMap::new();
    h.insert("connection", HeaderValue::from_static("Upgrade"));
    h.insert("upgrade", HeaderValue::from_static("tcp"));
    assert!(is_upgrade_request(&h));

    let mut h2 = HeaderMap::new();
    h2.insert("connection", HeaderValue::from_static("close"));
    h2.insert("upgrade", HeaderValue::from_static("tcp"));
    assert!(!is_upgrade_request(&h2));
}

#[test]
fn integration_auth_limiter_locks_out_brute_force() {
    let al = AuthLimiter::new();
    let key = "10.20.30.40";
    for _ in 0..10 {
        al.record_failure(key, 10, Duration::from_secs(60), Duration::from_secs(60));
    }
    assert!(al.is_blocked(key));

    let other = "10.20.30.41";
    assert!(!al.is_blocked(other));
}
