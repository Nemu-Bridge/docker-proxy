use crate::config::{MtlsConfig, TlsConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use x509_parser::prelude::*;

pub struct CertIdentity {
    pub common_name: Option<String>,
    pub sans: Vec<String>,
}

pub fn install_default_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn build_server_config(tls: &TlsConfig) -> Result<Arc<ServerConfig>, String> {
    let certs = load_certs(Path::new(&tls.cert))?;
    let key = load_private_key(Path::new(&tls.key))?;

    let builder = ServerConfig::builder();
    let server_config = match (
        tls.client_ca.as_deref(),
        tls.require_client_cert.unwrap_or(false),
    ) {
        (Some(ca_path), require) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(Path::new(ca_path))? {
                roots
                    .add(cert)
                    .map_err(|e| format!("client CA add failed: {e}"))?;
            }
            let roots = Arc::new(roots);
            let verifier_builder = if require {
                WebPkiClientVerifier::builder(roots)
            } else {
                WebPkiClientVerifier::builder(roots).allow_unauthenticated()
            };
            let verifier = verifier_builder
                .build()
                .map_err(|e| format!("client verifier build failed: {e}"))?;
            builder
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| format!("server cert install failed: {e}"))?
        }
        (None, _) => builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("server cert install failed: {e}"))?,
    };

    Ok(Arc::new(server_config))
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| format!("open {} failed: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut out = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        let der = item.map_err(|e| format!("parse cert failed: {e}"))?;
        out.push(der);
    }
    if out.is_empty() {
        return Err(format!("no certificates found in {}", path.display()));
    }
    Ok(out)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| format!("open {} failed: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("parse key failed: {e}"))?
        .ok_or_else(|| format!("no private key found in {}", path.display()))?;
    Ok(key)
}

pub fn extract_identity(cert_der: &[u8]) -> Option<CertIdentity> {
    let (_, parsed) = X509Certificate::from_der(cert_der).ok()?;

    let common_name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok().map(|s| s.to_string()));

    let mut sans: Vec<String> = Vec::new();
    if let Ok(Some(san_ext)) = parsed.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(s) => sans.push((*s).to_string()),
                GeneralName::URI(s) => sans.push((*s).to_string()),
                GeneralName::RFC822Name(s) => sans.push((*s).to_string()),
                _ => {}
            }
        }
    }

    Some(CertIdentity { common_name, sans })
}

pub fn resolve_mtls_role(identity: &CertIdentity, mtls: Option<&MtlsConfig>) -> Option<String> {
    let candidates: Vec<&str> = identity
        .common_name
        .iter()
        .map(|s| s.as_str())
        .chain(identity.sans.iter().map(|s| s.as_str()))
        .collect();

    if let Some(cfg) = mtls {
        if let Some(ref map) = cfg.cert_role_map {
            for cand in &candidates {
                for entry in map {
                    if cn_match(&entry.cn, cand) {
                        return Some(entry.role.clone());
                    }
                }
            }
        }
    }

    mtls.and_then(|m| m.default_role.clone())
}

fn cn_match(pattern: &str, value: &str) -> bool {
    if pattern == value {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix("*.") {
        if let Some(dot) = value.find('.') {
            return &value[dot + 1..] == rest;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CertRoleMapping;

    #[test]
    fn test_cn_match_exact() {
        assert!(cn_match("admin.example.com", "admin.example.com"));
        assert!(!cn_match("admin.example.com", "user.example.com"));
    }

    #[test]
    fn test_cn_match_wildcard() {
        assert!(cn_match(
            "*.readonly.example.com",
            "host1.readonly.example.com"
        ));
        assert!(!cn_match("*.readonly.example.com", "readonly.example.com"));
        assert!(!cn_match("*.readonly.example.com", "host1.example.com"));
    }

    #[test]
    fn test_resolve_role_map_first() {
        let id = CertIdentity {
            common_name: Some("admin.example.com".into()),
            sans: vec![],
        };
        let mtls = MtlsConfig {
            cert_role_map: Some(vec![CertRoleMapping {
                cn: "admin.example.com".into(),
                role: "admin".into(),
            }]),
            default_role: None,
        };
        assert_eq!(
            resolve_mtls_role(&id, Some(&mtls)).as_deref(),
            Some("admin")
        );
    }

    #[test]
    fn test_resolve_role_does_not_fall_back_to_cn() {
        let id = CertIdentity {
            common_name: Some("dev.example.com".into()),
            sans: vec![],
        };
        let mtls = MtlsConfig {
            cert_role_map: Some(vec![CertRoleMapping {
                cn: "admin.example.com".into(),
                role: "admin".into(),
            }]),
            default_role: None,
        };
        assert_eq!(resolve_mtls_role(&id, Some(&mtls)).as_deref(), None);
    }

    #[test]
    fn test_resolve_role_san_wildcard_then_default() {
        let id = CertIdentity {
            common_name: None,
            sans: vec!["host1.readonly.example.com".into()],
        };
        let mtls = MtlsConfig {
            cert_role_map: Some(vec![CertRoleMapping {
                cn: "*.readonly.example.com".into(),
                role: "readonly".into(),
            }]),
            default_role: Some("user".into()),
        };
        assert_eq!(
            resolve_mtls_role(&id, Some(&mtls)).as_deref(),
            Some("readonly")
        );

        let id_empty = CertIdentity {
            common_name: None,
            sans: vec![],
        };
        assert_eq!(
            resolve_mtls_role(&id_empty, Some(&mtls)).as_deref(),
            Some("user")
        );
    }
}
