//! Tool policy engine — per-agent ACLs.

use crate::TRonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

pub enum PolicyResult {
    Allow,
    Deny(String),
    Unknown,
}

/// Per-agent tool policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    pub calls_per_minute: u64,
}

/// Policy configuration loaded from TOML.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub agent: HashMap<String, AgentPolicy>,
}

pub struct PolicyEngine {
    config: RwLock<PolicyConfig>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(PolicyConfig::default()),
        }
    }

    /// Load policy from TOML string.
    pub fn load_toml(&self, toml_str: &str) -> Result<(), TRonError> {
        let config: PolicyConfig = toml::from_str(toml_str)
            .map_err(|e| TRonError::PolicyConfig(e.to_string()))?;
        *self.config.write().unwrap() = config;
        Ok(())
    }

    /// Check if an agent is allowed to call a tool.
    pub fn check(&self, agent_id: &str, tool_name: &str) -> PolicyResult {
        let config = self.config.read().unwrap();

        let policy = match config.agent.get(agent_id) {
            Some(p) => p,
            None => return PolicyResult::Unknown,
        };

        // Check deny list first (deny wins over allow)
        for pattern in &policy.deny {
            if matches_glob(pattern, tool_name) {
                return PolicyResult::Deny(format!("tool '{tool_name}' denied by policy for agent '{agent_id}'"));
            }
        }

        // Check allow list
        for pattern in &policy.allow {
            if matches_glob(pattern, tool_name) {
                return PolicyResult::Allow;
            }
        }

        // No match — treat as unknown
        PolicyResult::Unknown
    }

    /// Grant an agent access to tools matching a pattern.
    pub fn grant(&self, agent_id: &str, pattern: &str) {
        let mut config = self.config.write().unwrap();
        let policy = config.agent.entry(agent_id.to_string()).or_insert_with(|| AgentPolicy {
            allow: vec![],
            deny: vec![],
            rate_limit: None,
        });
        policy.allow.push(pattern.to_string());
    }

    /// Revoke an agent's access to tools matching a pattern.
    pub fn revoke(&self, agent_id: &str, pattern: &str) {
        let mut config = self.config.write().unwrap();
        let policy = config.agent.entry(agent_id.to_string()).or_insert_with(|| AgentPolicy {
            allow: vec![],
            deny: vec![],
            rate_limit: None,
        });
        policy.deny.push(pattern.to_string());
    }
}

/// Simple glob matching: "tarang_*" matches "tarang_probe".
fn matches_glob(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        pattern == name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_wildcard() {
        assert!(matches_glob("*", "anything"));
        assert!(matches_glob("tarang_*", "tarang_probe"));
        assert!(matches_glob("tarang_*", "tarang_analyze"));
        assert!(!matches_glob("tarang_*", "rasa_edit"));
        assert!(matches_glob("aegis_quarantine", "aegis_quarantine"));
        assert!(!matches_glob("aegis_quarantine", "aegis_scan"));
    }

    #[test]
    fn policy_deny_wins() {
        let engine = PolicyEngine::new();
        engine.grant("agent-1", "tarang_*");
        engine.revoke("agent-1", "tarang_delete");

        assert!(matches!(engine.check("agent-1", "tarang_probe"), PolicyResult::Allow));
        assert!(matches!(engine.check("agent-1", "tarang_delete"), PolicyResult::Deny(_)));
    }

    #[test]
    fn unknown_agent() {
        let engine = PolicyEngine::new();
        assert!(matches!(engine.check("nobody", "any_tool"), PolicyResult::Unknown));
    }

    #[test]
    fn load_toml_policy() {
        let engine = PolicyEngine::new();
        let toml = r#"
[agent."web-agent"]
allow = ["tarang_*", "rasa_*"]
deny = ["aegis_*"]
"#;
        engine.load_toml(toml).unwrap();
        assert!(matches!(engine.check("web-agent", "tarang_probe"), PolicyResult::Allow));
        assert!(matches!(engine.check("web-agent", "aegis_scan"), PolicyResult::Deny(_)));
    }
}
