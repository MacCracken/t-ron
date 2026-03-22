//! Pattern analyzer — anomaly detection on tool call sequences.

use crate::gate::ToolCall;
use dashmap::DashMap;
use std::collections::VecDeque;

/// Maximum call history retained per agent.
const MAX_HISTORY: usize = 100;

/// Tracks call patterns per agent for anomaly detection.
pub struct PatternAnalyzer {
    /// agent_id -> recent tool calls (ring buffer of last N)
    history: DashMap<String, VecDeque<String>>,
}

impl Default for PatternAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self {
            history: DashMap::new(),
        }
    }

    /// Record a tool call.
    pub async fn record(&self, call: &ToolCall) {
        let mut entry = self.history.entry(call.agent_id.clone()).or_default();
        entry.push_back(call.tool_name.clone());
        if entry.len() > MAX_HISTORY {
            entry.pop_front();
        }
    }

    /// Check for anomalous patterns. Returns description if anomaly detected.
    pub async fn check_anomaly(&self, agent_id: &str) -> Option<String> {
        let history = self.history.get(agent_id)?;

        // Check for tool enumeration (calling many distinct tools rapidly)
        if history.len() >= 20 {
            let last_20: std::collections::HashSet<&str> =
                history.iter().rev().take(20).map(|s| s.as_str()).collect();
            if last_20.len() >= 15 {
                return Some("tool enumeration: 15+ distinct tools in last 20 calls".to_string());
            }
        }

        // Check for privilege escalation: rapid switch from benign to sensitive tools
        let sensitive_prefixes = ["aegis_", "phylax_", "ark_install", "ark_remove"];
        if history.len() >= 5 {
            let recent: Vec<&str> = history.iter().rev().take(5).map(|s| s.as_str()).collect();
            let is_sensitive = |t: &str| sensitive_prefixes.iter().any(|p| t.starts_with(p));
            let sensitive_count = recent.iter().filter(|t| is_sensitive(t)).count();
            // Flag if 3+ of last 5 calls target sensitive tools and there's at least one
            // benign call mixed in (pure sensitive usage is normal for admin agents)
            if sensitive_count >= 3 && sensitive_count < recent.len() {
                return Some(
                    "privilege escalation: sensitive tool burst after benign calls".to_string(),
                );
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::ToolCall;

    #[tokio::test]
    async fn no_anomaly_normal_usage() {
        let analyzer = PatternAnalyzer::new();
        for _i in 0..10 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: "tarang_probe".to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        assert!(analyzer.check_anomaly("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn detect_tool_enumeration() {
        let analyzer = PatternAnalyzer::new();
        for i in 0..20 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: format!("tool_{i}"),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        let anomaly = analyzer.check_anomaly("agent-1").await;
        assert!(anomaly.is_some());
        assert!(anomaly.unwrap().contains("enumeration"));
    }

    #[tokio::test]
    async fn no_anomaly_for_unknown_agent() {
        let analyzer = PatternAnalyzer::new();
        assert!(analyzer.check_anomaly("nobody").await.is_none());
    }

    #[tokio::test]
    async fn enumeration_boundary_14_distinct_no_flag() {
        let analyzer = PatternAnalyzer::new();
        // 14 distinct tools in 20 calls — below the 15 threshold
        for i in 0..14 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: format!("tool_{i}"),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        // Pad to 20 calls with duplicates
        for _ in 0..6 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: "tool_0".to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        assert!(analyzer.check_anomaly("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn detect_privilege_escalation() {
        let analyzer = PatternAnalyzer::new();
        // 2 benign calls then 3 sensitive — triggers escalation (3+ of 5, mixed)
        for name in [
            "tarang_probe",
            "rasa_edit",
            "aegis_scan",
            "phylax_alert",
            "aegis_quarantine",
        ] {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: name.to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        let anomaly = analyzer.check_anomaly("agent-1").await;
        assert!(anomaly.is_some());
        assert!(anomaly.unwrap().contains("escalation"));
    }

    #[tokio::test]
    async fn pure_sensitive_no_escalation() {
        let analyzer = PatternAnalyzer::new();
        // All 5 calls are sensitive — should NOT flag (normal for admin agents)
        for name in [
            "aegis_scan",
            "aegis_quarantine",
            "phylax_alert",
            "aegis_report",
            "phylax_sweep",
        ] {
            let call = ToolCall {
                agent_id: "admin".to_string(),
                tool_name: name.to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        assert!(analyzer.check_anomaly("admin").await.is_none());
    }

    #[tokio::test]
    async fn ring_buffer_overflow() {
        let analyzer = PatternAnalyzer::new();
        // Record 110 calls — should keep only last 100
        for i in 0..110 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: format!("tool_{}", i % 5),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        let history = analyzer.history.get("agent-1").unwrap();
        assert_eq!(history.len(), MAX_HISTORY);
    }

    #[tokio::test]
    async fn separate_agent_histories() {
        let analyzer = PatternAnalyzer::new();
        for i in 0..20 {
            let call = ToolCall {
                agent_id: "agent-a".to_string(),
                tool_name: format!("tool_{i}"),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call).await;
        }
        // agent-b has clean history
        let call = ToolCall {
            agent_id: "agent-b".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        analyzer.record(&call).await;
        assert!(analyzer.check_anomaly("agent-a").await.is_some());
        assert!(analyzer.check_anomaly("agent-b").await.is_none());
    }
}
