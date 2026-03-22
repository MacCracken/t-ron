//! Query API — what T.Ron personality in SecureYeoman queries.

use crate::audit::{AuditLogger, SecurityEvent};
use crate::pattern::PatternAnalyzer;
use crate::policy::PolicyEngine;
use crate::score::RiskScorer;
use std::sync::Arc;

/// Query interface for the T.Ron SecureYeoman personality.
#[allow(dead_code)]
pub struct TRonQuery {
    pub(crate) audit: Arc<AuditLogger>,
    pub(crate) pattern: Arc<PatternAnalyzer>,
    pub(crate) policy: Arc<PolicyEngine>,
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
    use super::*;
    use crate::TRon;
    use crate::TRonConfig;

    #[tokio::test]
    async fn query_api() {
        let tron = TRon::new(TRonConfig::default());
        let query = tron.query();
        assert_eq!(query.total_events().await, 0);
        assert_eq!(query.total_denials().await, 0);
    }
}
