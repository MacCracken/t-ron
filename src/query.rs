//! Query API — what T.Ron personality in SecureYeoman queries.

use crate::audit::{AuditLogger, SecurityEvent};
use crate::score::RiskScorer;
use std::sync::Arc;

/// Query interface for the T.Ron SecureYeoman personality.
pub struct TRonQuery {
    pub(crate) audit: Arc<AuditLogger>,
}

impl TRonQuery {
    /// Recent security events.
    pub async fn recent_events(&self, limit: usize) -> Vec<SecurityEvent> {
        self.audit.recent(limit).await
    }

    /// Per-agent risk score (0.0 = trusted, 1.0 = hostile).
    pub async fn agent_risk_score(&self, agent_id: &str) -> f64 {
        RiskScorer::score(&self.audit, agent_id).await
    }

    /// Total events logged.
    pub async fn total_events(&self) -> usize {
        self.audit.total_count().await
    }

    /// Total denied calls.
    pub async fn total_denials(&self) -> usize {
        self.audit.deny_count().await
    }

    /// Audit trail for a specific agent.
    pub async fn agent_audit(&self, agent_id: &str, limit: usize) -> Vec<SecurityEvent> {
        self.audit.agent_events(agent_id, limit).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{DefaultAction, TRon, TRonConfig};

    fn permissive_config() -> TRonConfig {
        TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn query_api_initial_state() {
        let tron = TRon::new(TRonConfig::default());
        let query = tron.query();
        assert_eq!(query.total_events().await, 0);
        assert_eq!(query.total_denials().await, 0);
        assert!(query.recent_events(10).await.is_empty());
    }

    #[tokio::test]
    async fn query_after_checks() {
        let tron = TRon::new(permissive_config());
        let query = tron.query();

        // Run some calls through the pipeline
        let call = crate::gate::ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..5 {
            tron.check(&call).await;
        }

        assert_eq!(query.total_events().await, 5);
        assert_eq!(query.total_denials().await, 0);

        let events = query.recent_events(3).await;
        assert_eq!(events.len(), 3);
    }

    #[tokio::test]
    async fn query_risk_score_after_denials() {
        let tron = TRon::new(TRonConfig::default());
        let query = tron.query();

        // Unknown agent will be denied
        let call = crate::gate::ToolCall {
            agent_id: "bad-agent".to_string(),
            tool_name: "anything".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..5 {
            let v = tron.check(&call).await;
            assert!(v.is_denied());
        }

        assert_eq!(query.total_denials().await, 5);
        assert_eq!(query.agent_risk_score("bad-agent").await, 1.0);
        assert_eq!(query.agent_risk_score("nobody").await, 0.0);
    }

    #[tokio::test]
    async fn query_agent_audit_trail() {
        let tron = TRon::new(TRonConfig::default());
        let query = tron.query();

        // Generate events for two agents
        let call_a = crate::gate::ToolCall {
            agent_id: "agent-a".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let call_b = crate::gate::ToolCall {
            agent_id: "agent-b".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..3 {
            tron.check(&call_a).await;
        }
        for _ in 0..7 {
            tron.check(&call_b).await;
        }

        let trail_a = query.agent_audit("agent-a", 100).await;
        let trail_b = query.agent_audit("agent-b", 100).await;
        assert_eq!(trail_a.len(), 3);
        assert_eq!(trail_b.len(), 7);

        // Limit works
        assert_eq!(query.agent_audit("agent-b", 2).await.len(), 2);
    }
}
