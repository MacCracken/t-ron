//! Agent risk scoring — rolling threat score per agent.

use crate::audit::AuditLogger;
use crate::gate::VerdictKind;

/// Per-agent risk score (0.0 = trusted, 1.0 = hostile).
pub struct RiskScorer;

impl RiskScorer {
    /// Calculate risk score based on recent audit events.
    pub async fn score(audit: &AuditLogger, agent_id: &str) -> f64 {
        let events = audit.agent_events(agent_id, 100).await;
        if events.is_empty() {
            return 0.0;
        }

        let total = events.len() as f64;
        let denials = events
            .iter()
            .filter(|e| e.verdict == VerdictKind::Deny)
            .count() as f64;
        let flags = events
            .iter()
            .filter(|e| e.verdict == VerdictKind::Flag)
            .count() as f64;

        // Weighted score: denials are 2x flags
        let raw = (denials * 2.0 + flags) / (total * 2.0);
        raw.min(1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::{DenyCode, ToolCall, Verdict};

    #[tokio::test]
    async fn clean_agent_zero_risk() {
        let audit = AuditLogger::new();
        let call = ToolCall {
            agent_id: "good-agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..10 {
            audit.log(&call, &Verdict::Allow).await;
        }
        let score = RiskScorer::score(&audit, "good-agent").await;
        assert_eq!(score, 0.0);
    }

    #[tokio::test]
    async fn all_denied_max_risk() {
        let audit = AuditLogger::new();
        let call = ToolCall {
            agent_id: "bad-agent".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..10 {
            audit
                .log(
                    &call,
                    &Verdict::Deny {
                        reason: "nope".into(),
                        code: DenyCode::Unauthorized,
                    },
                )
                .await;
        }
        let score = RiskScorer::score(&audit, "bad-agent").await;
        assert_eq!(score, 1.0);
    }
}
