//! # T-Ron — MCP Security Monitor
//!
//! T-Ron (the security program that fights the MCP) provides real-time
//! monitoring, auditing, and threat detection for MCP tool calls across
//! the AGNOS ecosystem.
//!
//! ## Architecture
//!
//! ```text
//! Agent → bote (MCP protocol) → t-ron (security gate) → tool handler
//!                                  ├── policy check
//!                                  ├── rate limiting
//!                                  ├── payload scanning
//!                                  ├── pattern analysis
//!                                  └── audit logging (libro)
//! ```

pub mod audit;
pub mod gate;
pub mod middleware;
pub mod pattern;
pub mod policy;
pub mod query;
pub mod rate;
pub mod scanner;
pub mod score;
pub mod tools;

mod error;
pub use error::TRonError;

use std::path::PathBuf;
use std::sync::Arc;

/// Top-level MCP security monitor.
pub struct TRon {
    policy: Arc<policy::PolicyEngine>,
    rate_limiter: Arc<rate::RateLimiter>,
    pattern: Arc<pattern::PatternAnalyzer>,
    audit: Arc<audit::AuditLogger>,
    config: TRonConfig,
    /// Stored policy file path for reload support.
    policy_path: std::sync::Mutex<Option<PathBuf>>,
}

/// Configuration for t-ron.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TRonConfig {
    /// Default action for unknown agents.
    pub default_unknown_agent: DefaultAction,
    /// Default action for unknown tools.
    pub default_unknown_tool: DefaultAction,
    /// Maximum parameter size in bytes.
    pub max_param_size_bytes: usize,
    /// Enable payload scanning.
    pub scan_payloads: bool,
    /// Enable pattern analysis.
    pub analyze_patterns: bool,
}

/// Default action for unmatched requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum DefaultAction {
    Allow,
    Deny,
    Flag,
}

impl Default for TRonConfig {
    fn default() -> Self {
        Self {
            default_unknown_agent: DefaultAction::Deny,
            default_unknown_tool: DefaultAction::Deny,
            max_param_size_bytes: 65536,
            scan_payloads: true,
            analyze_patterns: true,
        }
    }
}

impl TRon {
    /// Create a new t-ron security monitor.
    #[must_use]
    pub fn new(config: TRonConfig) -> Self {
        Self {
            policy: Arc::new(policy::PolicyEngine::new()),
            rate_limiter: Arc::new(rate::RateLimiter::new()),
            pattern: Arc::new(pattern::PatternAnalyzer::new()),
            audit: Arc::new(audit::AuditLogger::new()),
            config,
            policy_path: std::sync::Mutex::new(None),
        }
    }

    /// Check if a tool call is permitted.
    pub async fn check(&self, call: &gate::ToolCall) -> gate::Verdict {
        // 1. Check param size (counting writer avoids allocating the serialized string)
        let param_size = {
            let mut counter = ByteCounter(0);
            // serde_json::to_writer on Value with a non-failing writer is infallible
            let _ = serde_json::to_writer(&mut counter, &call.params);
            counter.0
        };
        if param_size > self.config.max_param_size_bytes {
            let verdict = gate::Verdict::Deny {
                reason: format!(
                    "parameter size {} exceeds limit {}",
                    param_size, self.config.max_param_size_bytes
                ),
                code: gate::DenyCode::ParameterTooLarge,
            };
            self.audit.log(call, &verdict).await;
            return verdict;
        }

        // 2. Check policy (ACL)
        match self.policy.check(&call.agent_id, &call.tool_name) {
            policy::PolicyResult::Allow => {}
            policy::PolicyResult::Deny(reason) => {
                let verdict = gate::Verdict::Deny {
                    reason,
                    code: gate::DenyCode::Unauthorized,
                };
                self.audit.log(call, &verdict).await;
                return verdict;
            }
            policy::PolicyResult::UnknownAgent => {
                if let Some(v) = default_action_verdict(
                    self.config.default_unknown_agent,
                    "unknown agent".to_string(),
                ) {
                    self.audit.log(call, &v).await;
                    return v;
                }
            }
            policy::PolicyResult::UnknownTool => {
                if let Some(v) = default_action_verdict(
                    self.config.default_unknown_tool,
                    format!(
                        "tool '{}' not in policy for agent '{}'",
                        call.tool_name, call.agent_id
                    ),
                ) {
                    self.audit.log(call, &v).await;
                    return v;
                }
            }
        }

        // 3. Rate limit check
        if !self.rate_limiter.check(&call.agent_id, &call.tool_name) {
            let verdict = gate::Verdict::Deny {
                reason: "rate limit exceeded".to_string(),
                code: gate::DenyCode::RateLimited,
            };
            self.audit.log(call, &verdict).await;
            return verdict;
        }

        // 4. Payload scanning
        if self.config.scan_payloads
            && let Some(threat) = scanner::scan(&call.params)
        {
            let verdict = gate::Verdict::Deny {
                reason: format!("injection detected: {threat}"),
                code: gate::DenyCode::InjectionDetected,
            };
            self.audit.log(call, &verdict).await;
            return verdict;
        }

        // 5. Pattern analysis
        if self.config.analyze_patterns {
            self.pattern.record(call);
            if let Some(anomaly) = self.pattern.check_anomaly(&call.agent_id) {
                let verdict = gate::Verdict::Flag {
                    reason: format!("anomalous pattern: {anomaly}"),
                };
                self.audit.log(call, &verdict).await;
                return verdict;
            }
        }

        // All checks passed
        let verdict = gate::Verdict::Allow;
        self.audit.log(call, &verdict).await;
        verdict
    }

    /// Load policy from TOML string and apply rate limits.
    pub fn load_policy(&self, toml_str: &str) -> Result<(), TRonError> {
        self.policy.load_toml(toml_str)?;
        self.apply_rate_limits();
        Ok(())
    }

    /// Load policy from a file and store the path for hot-reload.
    pub fn load_policy_file(&self, path: impl Into<PathBuf>) -> Result<(), TRonError> {
        let path = path.into();
        let content = std::fs::read_to_string(&path)?;
        self.load_policy(&content)?;
        *self.policy_path.lock().unwrap_or_else(|p| p.into_inner()) = Some(path);
        Ok(())
    }

    /// Reload policy from the previously loaded file path.
    ///
    /// Designed for SIGHUP handlers — call this when the process receives a
    /// reload signal. Returns an error if no file was previously loaded.
    pub fn reload_policy(&self) -> Result<(), TRonError> {
        let path = self
            .policy_path
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match path {
            Some(p) => {
                tracing::info!(path = %p.display(), "reloading policy from file");
                let content = std::fs::read_to_string(&p)?;
                self.load_policy(&content)
            }
            None => Err(TRonError::Policy(
                "no policy file path set — use load_policy_file first".into(),
            )),
        }
    }

    /// Apply per-agent rate limits from the loaded policy config.
    fn apply_rate_limits(&self) {
        let config = self.policy.config();
        for (agent_id, agent_policy) in &config.agent {
            if let Some(ref rl) = agent_policy.rate_limit {
                tracing::debug!(
                    agent = agent_id,
                    cpm = rl.calls_per_minute,
                    "applying rate limit from policy"
                );
                self.rate_limiter.set_rate(agent_id, rl.calls_per_minute);
            }
        }
    }

    /// Get the query API (for T.Ron personality in SecureYeoman).
    #[must_use]
    pub fn query(&self) -> query::TRonQuery {
        query::TRonQuery {
            audit: self.audit.clone(),
        }
    }

    /// Get a shared reference to the policy engine (for tool handlers).
    #[must_use]
    pub fn policy_arc(&self) -> Arc<policy::PolicyEngine> {
        self.policy.clone()
    }
}

/// Counts bytes written without allocating a buffer.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Convert a `DefaultAction` + reason into a verdict, or `None` for `Allow`.
fn default_action_verdict(action: DefaultAction, reason: String) -> Option<gate::Verdict> {
    match action {
        DefaultAction::Deny => Some(gate::Verdict::Deny {
            reason,
            code: gate::DenyCode::Unauthorized,
        }),
        DefaultAction::Flag => Some(gate::Verdict::Flag { reason }),
        DefaultAction::Allow => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = TRonConfig::default();
        assert_eq!(config.default_unknown_agent, DefaultAction::Deny);
        assert_eq!(config.max_param_size_bytes, 65536);
        assert!(config.scan_payloads);
    }

    #[tokio::test]
    async fn deny_unknown_agent() {
        let tron = TRon::new(TRonConfig::default());
        let call = gate::ToolCall {
            agent_id: "unknown-agent".to_string(),
            tool_name: "some_tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(matches!(verdict, gate::Verdict::Deny { .. }));
    }

    #[tokio::test]
    async fn deny_oversized_params() {
        let config = TRonConfig {
            max_param_size_bytes: 10,
            default_unknown_agent: DefaultAction::Allow,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({"data": "this is way more than 10 bytes of parameter data"}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(matches!(
            verdict,
            gate::Verdict::Deny {
                code: gate::DenyCode::ParameterTooLarge,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn allow_known_agent_known_tool() {
        let tron = TRon::new(TRonConfig::default());
        tron.load_policy(
            r#"
[agent."web-agent"]
allow = ["tarang_*"]
"#,
        )
        .unwrap();
        let call = gate::ToolCall {
            agent_id: "web-agent".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({"path": "/test"}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(verdict.is_allowed());
        assert!(!verdict.is_denied());
    }

    #[tokio::test]
    async fn flag_unknown_agent() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Flag,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "mystery".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(matches!(verdict, gate::Verdict::Flag { .. }));
        assert!(verdict.is_allowed()); // Flags are allowed
    }

    #[tokio::test]
    async fn deny_unknown_tool_for_known_agent() {
        let tron = TRon::new(TRonConfig::default());
        tron.load_policy(
            r#"
[agent."limited"]
allow = ["tarang_*"]
"#,
        )
        .unwrap();
        let call = gate::ToolCall {
            agent_id: "limited".to_string(),
            tool_name: "aegis_scan".to_string(), // Not in allow list
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(verdict.is_denied());
    }

    #[tokio::test]
    async fn flag_unknown_tool() {
        let config = TRonConfig {
            default_unknown_tool: DefaultAction::Flag,
            ..Default::default()
        };
        let tron = TRon::new(config);
        tron.load_policy(
            r#"
[agent."agent-1"]
allow = ["tarang_*"]
"#,
        )
        .unwrap();
        let call = gate::ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "rasa_edit".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(matches!(verdict, gate::Verdict::Flag { .. }));
    }

    #[tokio::test]
    async fn allow_unknown_agent_passthrough() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "whoever".to_string(),
            tool_name: "whatever".to_string(),
            params: serde_json::json!({"safe": true}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(verdict.is_allowed());
    }

    #[tokio::test]
    async fn deny_injection_through_pipeline() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({"q": "1 UNION SELECT * FROM passwords"}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(matches!(
            verdict,
            gate::Verdict::Deny {
                code: gate::DenyCode::InjectionDetected,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn scan_payloads_disabled_bypass() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({"q": "1 UNION SELECT * FROM passwords"}),
            timestamp: chrono::Utc::now(),
        };
        // With scanning disabled, injection payload should pass
        let verdict = tron.check(&call).await;
        assert!(verdict.is_allowed());
    }

    #[tokio::test]
    async fn analyze_patterns_disabled_bypass() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            analyze_patterns: false,
            ..Default::default()
        };
        let tron = TRon::new(config);
        // Even with 20 distinct tools, no anomaly should be flagged
        for i in 0..20 {
            let call = gate::ToolCall {
                agent_id: "agent".to_string(),
                tool_name: format!("tool_{i}"),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            let verdict = tron.check(&call).await;
            assert!(verdict.is_allowed());
        }
    }

    #[tokio::test]
    async fn rate_limit_through_pipeline() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..60 {
            let v = tron.check(&call).await;
            assert!(v.is_allowed());
        }
        // 61st should be rate limited
        let v = tron.check(&call).await;
        assert!(matches!(
            v,
            gate::Verdict::Deny {
                code: gate::DenyCode::RateLimited,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn policy_deny_through_pipeline() {
        let tron = TRon::new(TRonConfig::default());
        tron.load_policy(
            r#"
[agent."restricted"]
allow = ["tarang_*"]
deny = ["tarang_delete"]
"#,
        )
        .unwrap();
        let call = gate::ToolCall {
            agent_id: "restricted".to_string(),
            tool_name: "tarang_delete".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(verdict.is_denied());
    }

    #[tokio::test]
    async fn load_policy_error() {
        let tron = TRon::new(TRonConfig::default());
        assert!(tron.load_policy("not valid toml {{{").is_err());
    }

    #[tokio::test]
    async fn param_size_boundary() {
        // Exactly at the limit should pass
        let config = TRonConfig {
            max_param_size_bytes: 2, // Tiny limit: "{}" is 2 bytes
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}), // serializes to "{}" = 2 bytes
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call).await;
        assert!(verdict.is_allowed());

        // One byte over should deny
        let call_over = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({"a":1}), // serializes to {"a":1} = 7 bytes
            timestamp: chrono::Utc::now(),
        };
        let verdict = tron.check(&call_over).await;
        assert!(matches!(
            verdict,
            gate::Verdict::Deny {
                code: gate::DenyCode::ParameterTooLarge,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn audit_logged_for_every_verdict() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        };
        let tron = TRon::new(config);
        let call = gate::ToolCall {
            agent_id: "agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        tron.check(&call).await;
        tron.check(&call).await;

        let query = tron.query();
        assert_eq!(query.total_events().await, 2);
    }

    #[tokio::test]
    async fn rate_limit_from_policy() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        };
        let tron = TRon::new(config);
        tron.load_policy(
            r#"
[agent."limited"]
allow = ["*"]
[agent."limited".rate_limit]
calls_per_minute = 5
"#,
        )
        .unwrap();

        let call = gate::ToolCall {
            agent_id: "limited".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..5 {
            assert!(tron.check(&call).await.is_allowed());
        }
        // 6th call should be rate limited
        assert!(matches!(
            tron.check(&call).await,
            gate::Verdict::Deny {
                code: gate::DenyCode::RateLimited,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn load_policy_file_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t-ron.toml");
        std::fs::write(
            &path,
            r#"
[agent."file-agent"]
allow = ["tarang_*"]
"#,
        )
        .unwrap();

        let tron = TRon::new(TRonConfig::default());
        tron.load_policy_file(&path).unwrap();

        let call = gate::ToolCall {
            agent_id: "file-agent".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        assert!(tron.check(&call).await.is_allowed());

        // Update the file and reload
        std::fs::write(
            &path,
            r#"
[agent."file-agent"]
allow = ["rasa_*"]
deny = ["tarang_*"]
"#,
        )
        .unwrap();

        tron.reload_policy().unwrap();
        // tarang_probe should now be denied
        assert!(tron.check(&call).await.is_denied());
    }

    #[test]
    fn reload_without_file_errors() {
        let tron = TRon::new(TRonConfig::default());
        assert!(tron.reload_policy().is_err());
    }
}
