//! Tool policy engine — per-agent ACLs.

use crate::TRonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;

#[non_exhaustive]
pub enum PolicyResult {
    Allow,
    Deny(String),
    /// Agent has no policy entry at all.
    UnknownAgent,
    /// Agent exists but tool didn't match any allow/deny pattern.
    UnknownTool,
}

/// Per-agent tool policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPolicy {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    // TODO: wire into RateLimiter — parsed but not yet enforced
    // #[serde(default)]
    // pub rate_limit: Option<RateLimitPolicy>,
}

// TODO: wire into RateLimiter — parsed but not yet enforced
// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub struct RateLimitPolicy {
//     pub calls_per_minute: u64,
// }

/// Policy configuration loaded from TOML.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub agent: HashMap<String, AgentPolicy>,
}

pub struct PolicyEngine {
    config: RwLock<PolicyConfig>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(PolicyConfig::default()),
        }
    }

    /// Load policy from TOML string.
    pub fn load_toml(&self, toml_str: &str) -> Result<(), TRonError> {
        let config: PolicyConfig =
            toml::from_str(toml_str).map_err(|e| TRonError::PolicyConfig(e.to_string()))?;
        let mut guard = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = config;
        tracing::info!("policy reloaded");
        Ok(())
    }

    /// Check if an agent is allowed to call a tool.
    #[must_use]
    pub fn check(&self, agent_id: &str, tool_name: &str) -> PolicyResult {
        let config = self
            .config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let policy = match config.agent.get(agent_id) {
            Some(p) => p,
            None => return PolicyResult::UnknownAgent,
        };

        // Check deny list first (deny wins over allow)
        for pattern in &policy.deny {
            if matches_glob(pattern, tool_name) {
                return PolicyResult::Deny(format!(
                    "tool '{tool_name}' denied by policy for agent '{agent_id}'"
                ));
            }
        }

        // Check allow list
        for pattern in &policy.allow {
            if matches_glob(pattern, tool_name) {
                return PolicyResult::Allow;
            }
        }

        // Agent exists but tool not in any list
        PolicyResult::UnknownTool
    }

    /// Grant an agent access to tools matching a pattern.
    pub fn grant(&self, agent_id: &str, pattern: &str) {
        let mut config = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let policy = config
            .agent
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentPolicy {
                allow: vec![],
                deny: vec![],
            });
        policy.allow.push(pattern.to_string());
    }

    /// Revoke an agent's access to tools matching a pattern.
    pub fn revoke(&self, agent_id: &str, pattern: &str) {
        let mut config = self
            .config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let policy = config
            .agent
            .entry(agent_id.to_string())
            .or_insert_with(|| AgentPolicy {
                allow: vec![],
                deny: vec![],
            });
        policy.deny.push(pattern.to_string());
    }
}

/// Simple glob matching: "tarang_*" matches "tarang_probe".
#[inline]
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

        assert!(matches!(
            engine.check("agent-1", "tarang_probe"),
            PolicyResult::Allow
        ));
        assert!(matches!(
            engine.check("agent-1", "tarang_delete"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn unknown_agent() {
        let engine = PolicyEngine::new();
        assert!(matches!(
            engine.check("nobody", "any_tool"),
            PolicyResult::UnknownAgent
        ));
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
        assert!(matches!(
            engine.check("web-agent", "tarang_probe"),
            PolicyResult::Allow
        ));
        assert!(matches!(
            engine.check("web-agent", "aegis_scan"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn unknown_tool_for_known_agent() {
        let engine = PolicyEngine::new();
        engine.grant("agent-1", "tarang_*");
        // Agent exists but tool doesn't match any pattern
        assert!(matches!(
            engine.check("agent-1", "rasa_edit"),
            PolicyResult::UnknownTool
        ));
    }

    #[test]
    fn malformed_toml_error() {
        let engine = PolicyEngine::new();
        let result = engine.load_toml("this is not valid toml {{{}}}");
        assert!(result.is_err());
    }

    #[test]
    fn deny_only_policy() {
        let engine = PolicyEngine::new();
        let toml = r#"
[agent."lockdown"]
deny = ["*"]
"#;
        engine.load_toml(toml).unwrap();
        assert!(matches!(
            engine.check("lockdown", "anything"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn allow_only_policy() {
        let engine = PolicyEngine::new();
        let toml = r#"
[agent."open"]
allow = ["*"]
"#;
        engine.load_toml(toml).unwrap();
        assert!(matches!(
            engine.check("open", "anything"),
            PolicyResult::Allow
        ));
    }

    #[test]
    fn reload_policy_replaces_previous() {
        let engine = PolicyEngine::new();
        engine.grant("agent-1", "tarang_*");
        assert!(matches!(
            engine.check("agent-1", "tarang_probe"),
            PolicyResult::Allow
        ));

        // Reload with empty policy — agent-1 no longer exists
        engine.load_toml("").unwrap();
        assert!(matches!(
            engine.check("agent-1", "tarang_probe"),
            PolicyResult::UnknownAgent
        ));
    }

    #[test]
    fn multiple_agents_in_policy() {
        let engine = PolicyEngine::new();
        let toml = r#"
[agent."reader"]
allow = ["tarang_*"]

[agent."admin"]
allow = ["*"]
deny = ["ark_remove"]
"#;
        engine.load_toml(toml).unwrap();
        assert!(matches!(
            engine.check("reader", "tarang_probe"),
            PolicyResult::Allow
        ));
        assert!(matches!(
            engine.check("reader", "aegis_scan"),
            PolicyResult::UnknownTool
        ));
        assert!(matches!(
            engine.check("admin", "aegis_scan"),
            PolicyResult::Allow
        ));
        assert!(matches!(
            engine.check("admin", "ark_remove"),
            PolicyResult::Deny(_)
        ));
    }

    #[test]
    fn empty_pattern_no_match() {
        assert!(!matches_glob("", "anything"));
        assert!(matches_glob("", ""));
    }

    #[test]
    fn glob_star_suffix_only() {
        // Leading star is not supported — treated as literal
        assert!(!matches_glob("*_delete", "tarang_delete"));
    }
}
