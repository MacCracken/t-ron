//! Audit logger — logs every tool call verdict.
//!
//! Dual-writes to an in-memory ring buffer (fast operational queries) and a
//! libro audit chain (tamper-proof cryptographic hash chain).

use crate::gate::{ToolCall, Verdict, VerdictKind};
use libro::{AuditChain, EventSeverity};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::RwLock;

/// Maximum audit events kept in the operational ring buffer.
const MAX_EVENTS: usize = 10_000;

/// A logged security event (operational view).
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
    /// Fast ring buffer for operational queries (risk scoring, recent events).
    events: RwLock<VecDeque<SecurityEvent>>,
    /// Cryptographic hash chain for tamper-proof audit trail.
    chain: Mutex<AuditChain>,
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
            chain: Mutex::new(AuditChain::new()),
        }
    }

    /// Log a tool call verdict to both the ring buffer and the libro chain.
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
            reason: reason.clone(),
        };

        // Write to libro chain (sync lock, fast — no await points)
        {
            let severity = match verdict.kind() {
                VerdictKind::Allow => EventSeverity::Info,
                VerdictKind::Flag => EventSeverity::Warning,
                VerdictKind::Deny => EventSeverity::Security,
            };
            let action = match verdict.kind() {
                VerdictKind::Allow => "tool_call.allow",
                VerdictKind::Flag => "tool_call.flag",
                VerdictKind::Deny => "tool_call.deny",
            };
            let mut details = serde_json::json!({
                "tool_name": call.tool_name,
            });
            if let Some(ref r) = reason {
                details["reason"] = serde_json::Value::String(r.clone());
            }
            if let Verdict::Deny { code, .. } = verdict {
                details["deny_code"] = serde_json::Value::String(code.as_str().to_owned());
            }
            let mut chain = self.chain.lock().expect("chain lock poisoned");
            chain.append_with_agent(severity, "t-ron", action, details, &call.agent_id);
        }

        // Write to operational ring buffer
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

    /// Verify the libro audit chain integrity.
    pub fn verify_chain(&self) -> libro::Result<()> {
        let chain = self.chain.lock().expect("chain lock poisoned");
        chain.verify()
    }

    /// Get a structured review/summary of the audit chain.
    pub fn chain_review(&self) -> libro::ChainReview {
        let chain = self.chain.lock().expect("chain lock poisoned");
        chain.review()
    }

    /// Number of entries in the libro chain (may differ from ring buffer
    /// if ring buffer has evicted old entries).
    pub fn chain_len(&self) -> usize {
        self.chain.lock().expect("chain lock poisoned").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::DenyCode;

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

    #[tokio::test]
    async fn chain_written_on_log() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger.log(&call, &Verdict::Allow).await;
        logger
            .log(
                &call,
                &Verdict::Deny {
                    reason: "blocked".into(),
                    code: DenyCode::Unauthorized,
                },
            )
            .await;

        assert_eq!(logger.chain_len(), 2);
        assert!(logger.verify_chain().is_ok());
    }

    #[tokio::test]
    async fn chain_integrity_after_many_writes() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        for _ in 0..100 {
            logger.log(&call, &Verdict::Allow).await;
        }
        assert_eq!(logger.chain_len(), 100);
        assert!(logger.verify_chain().is_ok());
    }

    #[tokio::test]
    async fn chain_has_agent_id() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "web-agent".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger.log(&call, &Verdict::Allow).await;

        let chain = logger.chain.lock().unwrap();
        let entry = &chain.entries()[0];
        assert_eq!(entry.agent_id(), Some("web-agent"));
        assert_eq!(entry.source(), "t-ron");
        assert_eq!(entry.action(), "tool_call.allow");
    }

    #[tokio::test]
    async fn chain_deny_has_details() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "bad-agent".to_string(),
            tool_name: "aegis_scan".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger
            .log(
                &call,
                &Verdict::Deny {
                    reason: "rate limit exceeded".into(),
                    code: DenyCode::RateLimited,
                },
            )
            .await;

        let chain = logger.chain.lock().unwrap();
        let entry = &chain.entries()[0];
        assert_eq!(entry.action(), "tool_call.deny");
        assert_eq!(entry.severity(), EventSeverity::Security);
        let details = entry.details();
        assert_eq!(details["tool_name"], "aegis_scan");
        assert_eq!(details["reason"], "rate limit exceeded");
        assert_eq!(details["deny_code"], "rate_limited");
    }

    #[tokio::test]
    async fn chain_review_works() {
        let logger = AuditLogger::new();
        let call = ToolCall {
            agent_id: "agent-1".to_string(),
            tool_name: "tool".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        logger.log(&call, &Verdict::Allow).await;

        let review = logger.chain_review();
        assert_eq!(review.entry_count, 1);
    }
}
