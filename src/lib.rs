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
pub mod pattern;
pub mod policy;
pub mod query;
pub mod rate;
pub mod scanner;
pub mod score;

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
            policy::PolicyResult::UnknownAgent => match self.config.default_unknown_agent {
                DefaultAction::Deny => {
                    let verdict = gate::Verdict::Deny {
                        reason: "unknown agent".to_string(),
                        code: gate::DenyCode::Unauthorized,
                    };
                    self.audit.log(call, &verdict).await;
                    return verdict;
                }
                DefaultAction::Flag => {
                    let verdict = gate::Verdict::Flag {
                        reason: "unknown agent".to_string(),
                    };
                    self.audit.log(call, &verdict).await;
                    return verdict;
                }
                DefaultAction::Allow => {}
            },
            policy::PolicyResult::UnknownTool => match self.config.default_unknown_tool {
                DefaultAction::Deny => {
                    let verdict = gate::Verdict::Deny {
                        reason: format!(
                            "tool '{}' not in policy for agent '{}'",
                            call.tool_name, call.agent_id
                        ),
                        code: gate::DenyCode::Unauthorized,
                    };
                    self.audit.log(call, &verdict).await;
                    return verdict;
                }
                DefaultAction::Flag => {
                    let verdict = gate::Verdict::Flag {
                        reason: format!(
                            "tool '{}' not in policy for agent '{}'",
                            call.tool_name, call.agent_id
                        ),
                    };
                    self.audit.log(call, &verdict).await;
                    return verdict;
                }
                DefaultAction::Allow => {}
            },
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
}
