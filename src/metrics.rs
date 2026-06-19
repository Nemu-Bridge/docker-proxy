use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

const LATENCY_BUCKETS_MS: &[u64] = &[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
const LATENCY_BUCKET_COUNT: usize = 12;

pub struct Metrics {
    pub requests_total: AtomicU64,
    pub requests_allowed: AtomicU64,
    pub requests_denied: AtomicU64,
    pub requests_dry_run: AtomicU64,
    pub auth_failures_total: AtomicU64,
    pub auth_lockouts_total: AtomicU64,
    pub rate_limited_total: AtomicU64,
    pub upstream_errors_total: AtomicU64,
    pub upstream_timeouts_total: AtomicU64,
    pub body_too_large_total: AtomicU64,
    pub bad_request_total: AtomicU64,
    pub request_timeouts_total: AtomicU64,
    pub upgrade_total: AtomicU64,
    by_rule: Mutex<HashMap<String, RuleCounters>>,
    latency: LatencyHistogram,
}

#[derive(Default)]
struct RuleCounters {
    denied: u64,
    dry_run: u64,
}

struct LatencyHistogram {
    buckets: [AtomicU64; LATENCY_BUCKET_COUNT],
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl LatencyHistogram {
    const fn new() -> Self {
        LatencyHistogram {
            buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, ms: u64) {
        self.sum_ms.fetch_add(ms, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        let mut placed_idx = LATENCY_BUCKET_COUNT - 1;
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if ms <= *bound {
                placed_idx = i;
                break;
            }
        }
        self.buckets[placed_idx].fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            requests_total: AtomicU64::new(0),
            requests_allowed: AtomicU64::new(0),
            requests_denied: AtomicU64::new(0),
            requests_dry_run: AtomicU64::new(0),
            auth_failures_total: AtomicU64::new(0),
            auth_lockouts_total: AtomicU64::new(0),
            rate_limited_total: AtomicU64::new(0),
            upstream_errors_total: AtomicU64::new(0),
            upstream_timeouts_total: AtomicU64::new(0),
            body_too_large_total: AtomicU64::new(0),
            bad_request_total: AtomicU64::new(0),
            request_timeouts_total: AtomicU64::new(0),
            upgrade_total: AtomicU64::new(0),
            by_rule: Mutex::new(HashMap::new()),
            latency: LatencyHistogram::new(),
        }
    }

    pub fn record_rule_deny(&self, rule_name: &str, dry_run: bool) {
        let mut g = self.by_rule.lock().unwrap_or_else(|p| p.into_inner());
        let e = g.entry(rule_name.to_string()).or_default();
        if dry_run {
            e.dry_run = e.dry_run.saturating_add(1);
        } else {
            e.denied = e.denied.saturating_add(1);
        }
    }

    pub fn observe_upstream_latency_ms(&self, ms: u64) {
        self.latency.observe(ms);
    }

    pub fn render_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str("# HELP docker_proxy_requests_total Total HTTP requests received\n");
        out.push_str("# TYPE docker_proxy_requests_total counter\n");
        out.push_str(&format!(
            "docker_proxy_requests_total {}\n",
            self.requests_total.load(Ordering::Relaxed)
        ));
        for (name, label, atomic) in [
            (
                "docker_proxy_requests_allowed_total",
                "allowed",
                &self.requests_allowed,
            ),
            (
                "docker_proxy_requests_denied_total",
                "denied",
                &self.requests_denied,
            ),
            (
                "docker_proxy_requests_dry_run_total",
                "dry_run",
                &self.requests_dry_run,
            ),
        ] {
            out.push_str(&format!("# HELP {name} Requests with outcome '{label}'\n"));
            out.push_str(&format!("# TYPE {name} counter\n"));
            out.push_str(&format!("{name} {}\n", atomic.load(Ordering::Relaxed)));
        }

        for (name, help, atomic) in [
            (
                "docker_proxy_auth_failures_total",
                "Failed auth attempts",
                &self.auth_failures_total,
            ),
            (
                "docker_proxy_auth_lockouts_total",
                "IP auth lockouts triggered",
                &self.auth_lockouts_total,
            ),
            (
                "docker_proxy_rate_limited_total",
                "Requests blocked by rate limit",
                &self.rate_limited_total,
            ),
            (
                "docker_proxy_upstream_errors_total",
                "Upstream docker errors",
                &self.upstream_errors_total,
            ),
            (
                "docker_proxy_upstream_timeouts_total",
                "Upstream docker timeouts",
                &self.upstream_timeouts_total,
            ),
            (
                "docker_proxy_body_too_large_total",
                "Requests rejected for body size",
                &self.body_too_large_total,
            ),
            (
                "docker_proxy_bad_request_total",
                "Requests rejected as malformed",
                &self.bad_request_total,
            ),
            (
                "docker_proxy_request_timeouts_total",
                "Client request read timeouts",
                &self.request_timeouts_total,
            ),
            (
                "docker_proxy_upgrade_total",
                "HTTP upgrade (exec/attach) requests proxied",
                &self.upgrade_total,
            ),
        ] {
            out.push_str(&format!("# HELP {name} {help}\n"));
            out.push_str(&format!("# TYPE {name} counter\n"));
            out.push_str(&format!("{name} {}\n", atomic.load(Ordering::Relaxed)));
        }

        let by_rule = self.by_rule.lock().unwrap_or_else(|p| p.into_inner());
        out.push_str("# HELP docker_proxy_rule_decisions_total Decisions per rule\n");
        out.push_str("# TYPE docker_proxy_rule_decisions_total counter\n");
        for (rule, c) in by_rule.iter() {
            let escaped = escape_label(rule);
            out.push_str(&format!(
                "docker_proxy_rule_decisions_total{{rule=\"{}\",mode=\"enforced\"}} {}\n",
                escaped, c.denied
            ));
            out.push_str(&format!(
                "docker_proxy_rule_decisions_total{{rule=\"{}\",mode=\"dry_run\"}} {}\n",
                escaped, c.dry_run
            ));
        }
        drop(by_rule);

        out.push_str(
            "# HELP docker_proxy_upstream_latency_ms Latency to docker upstream in milliseconds\n",
        );
        out.push_str("# TYPE docker_proxy_upstream_latency_ms histogram\n");
        let bucket_snapshots: [u64; LATENCY_BUCKET_COUNT] =
            std::array::from_fn(|i| self.latency.buckets[i].load(Ordering::Relaxed));
        let mut cumulative = 0u64;
        for (i, bound) in LATENCY_BUCKETS_MS.iter().enumerate() {
            cumulative = cumulative.saturating_add(bucket_snapshots[i]);
            out.push_str(&format!(
                "docker_proxy_upstream_latency_ms_bucket{{le=\"{}\"}} {}\n",
                bound, cumulative
            ));
        }
        cumulative = cumulative.saturating_add(bucket_snapshots[LATENCY_BUCKET_COUNT - 1]);
        out.push_str(&format!(
            "docker_proxy_upstream_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            cumulative
        ));
        out.push_str(&format!(
            "docker_proxy_upstream_latency_ms_sum {}\n",
            self.latency.sum_ms.load(Ordering::Relaxed)
        ));
        out.push_str(&format!(
            "docker_proxy_upstream_latency_ms_count {}\n",
            self.latency.count.load(Ordering::Relaxed)
        ));

        out
    }
}

fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_renders_prometheus_format() {
        let m = Metrics::new();
        m.requests_total.fetch_add(3, Ordering::Relaxed);
        m.requests_denied.fetch_add(1, Ordering::Relaxed);
        m.request_timeouts_total.fetch_add(1, Ordering::Relaxed);
        m.record_rule_deny("block-secrets", false);
        m.record_rule_deny("watch-rule", true);
        m.observe_upstream_latency_ms(15);
        m.observe_upstream_latency_ms(700);
        let out = m.render_prometheus();
        assert!(out.contains("docker_proxy_requests_total 3"));
        assert!(out.contains("docker_proxy_requests_denied_total 1"));
        assert!(out.contains("docker_proxy_request_timeouts_total 1"));
        assert!(out.contains("rule=\"block-secrets\""));
        assert!(out.contains("mode=\"dry_run\""));
        assert!(out.contains("docker_proxy_upstream_latency_ms_count 2"));
    }

    #[test]
    fn test_escape_label_quotes_and_backslashes() {
        let s = escape_label("hello \"world\"\\foo");
        assert_eq!(s, "hello \\\"world\\\"\\\\foo");
    }
}
