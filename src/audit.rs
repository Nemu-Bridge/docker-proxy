use chrono::Utc;
use serde::Serialize;
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub timestamp: String,
    pub event: &'static str,
    pub peer_ip: String,
    pub method: String,
    pub path: String,
    pub user_agent: String,
    pub user_role: Option<String>,
    pub identity: Option<String>,
    pub rule_name: Option<String>,
    pub rule_action: Option<String>,
    pub status: u16,
    pub dry_run: bool,
    pub message: Option<String>,
}

impl AuditEvent {
    pub fn new(
        event: &'static str,
        peer_ip: IpAddr,
        method: &str,
        path: &str,
        user_agent: &str,
    ) -> Self {
        AuditEvent {
            timestamp: Utc::now().to_rfc3339(),
            event,
            peer_ip: peer_ip.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            user_agent: user_agent.to_string(),
            user_role: None,
            identity: None,
            rule_name: None,
            rule_action: None,
            status: 0,
            dry_run: false,
            message: None,
        }
    }
}

#[derive(Clone)]
pub struct AuditSink {
    tx: Option<mpsc::Sender<AuditEvent>>,
}

impl AuditSink {
    pub fn disabled() -> Self {
        AuditSink { tx: None }
    }

    pub fn spawn(path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::channel::<AuditEvent>(4096);
        tokio::spawn(async move {
            let file = match OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    error!("audit log open failed at {}: {e}", path.display());
                    return;
                }
            };
            let mut writer = file;
            while let Some(ev) = rx.recv().await {
                if let Err(e) = write_event(&mut writer, &ev).await {
                    error!("audit log write failed: {e}");
                }
            }
        });
        AuditSink { tx: Some(tx) }
    }

    pub fn send(&self, event: AuditEvent) {
        if let Some(ref tx) = self.tx {
            if let Err(e) = tx.try_send(event) {
                match e {
                    mpsc::error::TrySendError::Full(_) => {
                        warn!("audit log channel full — dropping event");
                    }
                    mpsc::error::TrySendError::Closed(_) => {}
                }
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.tx.is_some()
    }
}

async fn write_event(writer: &mut File, ev: &AuditEvent) -> std::io::Result<()> {
    let mut line = serde_json::to_string(ev)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    writer.write_all(line.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_event_serializes_to_json() {
        let mut ev = AuditEvent::new(
            "deny",
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            "GET",
            "/secrets",
            "curl/8",
        );
        ev.rule_name = Some("block-secrets".into());
        ev.rule_action = Some("deny".into());
        ev.status = 403;
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"event\":\"deny\""));
        assert!(json.contains("\"rule_name\":\"block-secrets\""));
        assert!(json.contains("\"path\":\"/secrets\""));
    }

    #[test]
    fn test_disabled_sink_no_op() {
        let sink = AuditSink::disabled();
        assert!(!sink.is_enabled());
        let ev = AuditEvent::new(
            "deny",
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            "GET",
            "/x",
            "test",
        );
        sink.send(ev);
    }
}
