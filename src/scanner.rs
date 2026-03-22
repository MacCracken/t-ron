//! Payload scanner — injection detection in tool parameters.

use regex::Regex;
use std::sync::LazyLock;

static SQL_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(\b(union|select|insert|update|delete|drop|alter|exec|execute)\b.*\b(from|into|table|where|set)\b|--|;.*\b(drop|delete|update)\b)").unwrap()
});

static SHELL_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[;&|`$]\s*(rm|cat|curl|wget|nc|bash|sh|python|perl|ruby|chmod|chown)\b").unwrap()
});

static TEMPLATE_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\{\{.*\}\}|\$\{.*\}|<%.*%>").unwrap()
});

static PATH_TRAVERSAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\.\./|\.\.\\|%2e%2e").unwrap()
});

pub struct PayloadScanner;

impl PayloadScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a JSON value for injection patterns. Returns threat description if found.
    pub fn scan(&self, params: &serde_json::Value) -> Option<String> {
        let text = params.to_string();
        self.scan_text(&text)
    }

    fn scan_text(&self, text: &str) -> Option<String> {
        if SQL_INJECTION.is_match(text) {
            return Some("SQL injection pattern".to_string());
        }
        if SHELL_INJECTION.is_match(text) {
            return Some("shell injection pattern".to_string());
        }
        if TEMPLATE_INJECTION.is_match(text) {
            return Some("template injection pattern".to_string());
        }
        if PATH_TRAVERSAL.is_match(text) {
            return Some("path traversal pattern".to_string());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_sql_injection() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"query": "SELECT * FROM users WHERE id=1 UNION SELECT * FROM passwords"});
        assert!(scanner.scan(&params).unwrap().contains("SQL"));
    }

    #[test]
    fn detect_shell_injection() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"cmd": "hello; rm -rf /"});
        assert!(scanner.scan(&params).unwrap().contains("shell"));
    }

    #[test]
    fn detect_path_traversal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"path": "../../../etc/passwd"});
        assert!(scanner.scan(&params).unwrap().contains("path traversal"));
    }

    #[test]
    fn clean_params_pass() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"name": "hello world", "count": 42});
        assert!(scanner.scan(&params).is_none());
    }

    #[test]
    fn detect_template_injection() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"input": "{{config.items()}}"});
        assert!(scanner.scan(&params).unwrap().contains("template"));
    }
}
