use hyper::header::{HeaderMap, HeaderValue, CONNECTION, UPGRADE};

pub fn is_upgrade_request(headers: &HeaderMap) -> bool {
    let connection_has_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .any(|v| header_has_token(v, "upgrade"));
    let has_upgrade_header = headers.get(UPGRADE).is_some();
    connection_has_upgrade && has_upgrade_header
}

pub fn header_has_token(value: &HeaderValue, token: &str) -> bool {
    let s = match value.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    s.split(',')
        .map(|t| t.trim())
        .any(|t| t.eq_ignore_ascii_case(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderMap, HeaderValue};

    #[test]
    fn test_detects_upgrade_request() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("upgrade"));
        h.insert("upgrade", HeaderValue::from_static("tcp"));
        assert!(is_upgrade_request(&h));
    }

    #[test]
    fn test_no_upgrade_without_connection_token() {
        let mut h = HeaderMap::new();
        h.insert("upgrade", HeaderValue::from_static("tcp"));
        assert!(!is_upgrade_request(&h));
    }

    #[test]
    fn test_connection_with_multiple_tokens() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("keep-alive, Upgrade"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        assert!(is_upgrade_request(&h));
    }

    #[test]
    fn test_header_token_case_insensitive() {
        let v = HeaderValue::from_static("Keep-Alive, UPGRADE");
        assert!(header_has_token(&v, "upgrade"));
        assert!(header_has_token(&v, "keep-alive"));
        assert!(!header_has_token(&v, "close"));
    }
}
