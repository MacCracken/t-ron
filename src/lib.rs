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

use std::sync::Arc;

/// Top-level MCP security monitor.
pub struct TRon {
    policy: Arc<policy::PolicyEngine>,
    rate_limiter: Arc<rate::RateLimiter>,
    scanner: Arc<scanner::PayloadScanner>,
    pattern: Arc<pattern::PatternAnalyzer>,
    audit: Arc<audit::AuditLogger>,
    config: TRonConfig,
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
    pub fn new(config: TRonConfig) -> Self {
        Self {
            policy: Arc::new(policy::PolicyEngine::new()),
            rate_limiter: Arc::new(rate::RateLimiter::new()),
            scanner: Arc::new(scanner::PayloadScanner::new()),
            pattern: Arc::new(pattern::PatternAnalyzer::new()),
            audit: Arc::new(audit::AuditLogger::new()),
            config,
        }
    }

    /// Check if a tool call is permitted.
    pub async fn check(&self, call: &gate::ToolCall) -> gate::Verdict {
        // 1. Check param size
        let param_str = call.params.to_string();
        if param_str.len() > self.config.max_param_size_bytes {
            let verdict = gate::Verdict::Deny {
                reason: format!(
                    "parameter size {} exceeds limit {}",
                    param_str.len(),
                    self.config.max_param_size_bytes
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
            && let Some(threat) = self.scanner.scan(&call.params)
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
            self.pattern.record(call).await;
            if let Some(anomaly) = self.pattern.check_anomaly(&call.agent_id).await {
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

    /// Load policy from TOML string.
    pub fn load_policy(&self, toml_str: &str) -> Result<(), TRonError> {
        self.policy.load_toml(toml_str)
    }

    /// Get the query API (for T.Ron personality in SecureYeoman).
    pub fn query(&self) -> query::TRonQuery {
        query::TRonQuery {
            audit: self.audit.clone(),
        }
    }

    /// Get a shared reference to the policy engine (for tool handlers).
    pub fn policy_arc(&self) -> Arc<policy::PolicyEngine> {
        self.policy.clone()
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
}
