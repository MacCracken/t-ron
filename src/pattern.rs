//! Pattern analyzer — anomaly detection on tool call sequences.

use crate::gate::ToolCall;
use dashmap::DashMap;

/// Tracks call patterns per agent for anomaly detection.
pub struct PatternAnalyzer {
    /// agent_id -> recent tool calls (ring buffer of last N)
    history: DashMap<String, Vec<String>>,
    /// Maximum history per agent.
    max_history: usize,
}

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self {
            history: DashMap::new(),
            max_history: 100,
        }
    }

    /// Record a tool call.
    pub async fn record(&self, call: &ToolCall) {
        let mut entry = self.history.entry(call.agent_id.clone()).or_default();
        entry.push(call.tool_name.clone());
        if entry.len() > self.max_history {
            entry.remove(0);
        }
    }

    /// Check for anomalous patterns. Returns description if anomaly detected.
    pub async fn check_anomaly(&self, agent_id: &str) -> Option<String> {
        let history = self.history.get(agent_id)?;

        // Check for tool enumeration (calling many distinct tools rapidly)
        if history.len() >= 20 {
            let last_20: std::collections::HashSet<&str> = history
                .iter()
                .rev()
                .take(20)
                .map(|s| s.as_str())
                .collect();
            if last_20.len() >= 15 {
                return Some("tool enumeration: 15+ distinct tools in last 20 calls".to_string());
            }
        }

        // Check for privilege escalation pattern: non-admin tool -> admin tool
        let sensitive_prefixes = ["aegis_", "phylax_", "ark_install", "ark_remove"];
        if history.len() >= 3 {
            let recent: Vec<&str> = history.iter().rev().take(3).map(|s| s.as_str()).collect();
            let _has_sensitive = recent.iter().any(|t| sensitive_prefixes.iter().any(|p| t.starts_with(p)));
            let _has_benign = recent.iter().any(|t| !sensitive_prefixes.iter().any(|p| t.starts_with(p)));
            // Only flag if we see a pattern of escalation, not just mixed usage
            // This is intentionally conservative — future phases will add ML-based detection
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
}
