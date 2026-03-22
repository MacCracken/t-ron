//! Audit logger — logs every tool call verdict.

use crate::gate::{ToolCall, Verdict, VerdictKind};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use tokio::sync::RwLock;

/// Maximum audit events kept in memory.
const MAX_EVENTS: usize = 10_000;

/// A logged security event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent_id: String,
    pub tool_name: String,
    pub verdict: VerdictKind,
    pub reason: Option<String>,
}

pub struct AuditLogger {
    events: RwLock<VecDeque<SecurityEvent>>,
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(VecDeque::new()),
        }
    }

    /// Log a tool call verdict.
    pub async fn log(&self, call: &ToolCall, verdict: &Verdict) {
        let reason = match verdict {
            Verdict::Allow => None,
            Verdict::Deny { reason, .. } => Some(reason.clone()),
            Verdict::Flag { reason } => Some(reason.clone()),
        };

        let event = SecurityEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            agent_id: call.agent_id.clone(),
            tool_name: call.tool_name.clone(),
            verdict: verdict.kind(),
            reason,
        };

        // TODO: Also write to libro chain
        let mut events = self.events.write().await;
        events.push_back(event);
        if events.len() > MAX_EVENTS {
            events.pop_front();
        }
    }

    /// Get recent events.
    pub async fn recent(&self, limit: usize) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        events.iter().rev().take(limit).cloned().collect()
    }

    /// Get events for a specific agent.
    pub async fn agent_events(&self, agent_id: &str, limit: usize) -> Vec<SecurityEvent> {
        let events = self.events.read().await;
        events
            .iter()
            .rev()
            .filter(|e| e.agent_id == agent_id)
            .take(limit)
            .cloned()
            .collect()
    }

    /// Count denied calls.
    pub async fn deny_count(&self) -> usize {
        self.events
            .read()
            .await
            .iter()
            .filter(|e| e.verdict == VerdictKind::Deny)
            .count()
    }

    /// Total event count.
    pub async fn total_count(&self) -> usize {
        self.events.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_and_retrieve() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "test_tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };

        logger.log(&call, &Verdict::Allow).await;
        logger
            .log(
                &call,
                &Verdict::Deny {
                    reason: "nope".into(),
                    code: crate::gate::DenyCode::Unauthorized,
                },
            )
            .await;

        assert_eq!(logger.total_count().await, 2);
        assert_eq!(logger.deny_count().await, 1);

        let recent = logger.recent(10).await;
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].verdict, VerdictKind::Deny); // Most recent first
    }

    #[tokio::test]
    async fn log_flag_verdict() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "test_tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger
            .log(
                &call,
                &Verdict::Flag {
                    reason: "suspicious".into(),
                },
            )
            .await;

        let events = logger.recent(1).await;
        assert_eq!(events[0].verdict, VerdictKind::Flag);
        assert_eq!(events[0].reason.as_deref(), Some("suspicious"));
        // Flags are not denials
        assert_eq!(logger.deny_count().await, 0);
    }

    #[tokio::test]
    async fn agent_events_filtering() {
        let logger = AuditLogger::new();
        let call_a = ToolCall {
            agent_id: "agent-a".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        let call_b = ToolCall {
            agent_id: "agent-b".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };

        for _ in 0..5 {
            logger.log(&call_a, &Verdict::Allow).await;
        }
        for _ in 0..3 {
            logger.log(&call_b, &Verdict::Allow).await;
        }

        assert_eq!(logger.agent_events("agent-a", 100).await.len(), 5);
        assert_eq!(logger.agent_events("agent-b", 100).await.len(), 3);
        assert_eq!(logger.agent_events("nobody", 100).await.len(), 0);
    }

    #[tokio::test]
    async fn agent_events_respects_limit() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..10 {
            logger.log(&call, &Verdict::Allow).await;
        }
        assert_eq!(logger.agent_events("agent-1", 3).await.len(), 3);
    }

    #[tokio::test]
    async fn recent_limit_larger_than_count() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger.log(&call, &Verdict::Allow).await;
        // Ask for 100 but only 1 exists
        assert_eq!(logger.recent(100).await.len(), 1);
    }

    #[tokio::test]
    async fn empty_log_queries() {
        let logger = AuditLogger::new();
        assert_eq!(logger.total_count().await, 0);
        assert_eq!(logger.deny_count().await, 0);
        assert!(logger.recent(10).await.is_empty());
        assert!(logger.agent_events("nobody", 10).await.is_empty());
    }

    #[tokio::test]
    async fn max_events_eviction() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };

        // Log MAX_EVENTS + 100 events
        for _ in 0..(MAX_EVENTS + 100) {
            logger.log(&call, &Verdict::Allow).await;
        }
        assert_eq!(logger.total_count().await, MAX_EVENTS);
    }

    #[tokio::test]
    async fn event_has_unique_id() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger.log(&call, &Verdict::Allow).await;
        logger.log(&call, &Verdict::Allow).await;

        let events = logger.recent(2).await;
        assert_ne!(events[0].id, events[1].id);
    }
}
