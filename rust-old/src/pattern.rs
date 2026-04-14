//! Pattern analyzer — anomaly detection on tool call sequences.

use crate::gate::ToolCall;
use chrono::Timelike;
use dashmap::DashMap;
use std::collections::VecDeque;

/// Maximum call history retained per agent.
const MAX_HISTORY: usize = 100;

/// Minimum total calls before time-of-day anomaly detection activates.
const MIN_HISTORY_FOR_TIME_ANOMALY: u32 = 50;

/// Minimum fraction of total calls for an hour to be considered "active".
const ACTIVE_HOUR_THRESHOLD: f64 = 0.02;

/// Tracks call patterns per agent for anomaly detection.
pub struct PatternAnalyzer {
    /// agent_id -> recent tool calls (ring buffer of last N)
    history: DashMap<String, VecDeque<String>>,
    /// agent_id -> call count per hour-of-day (0..23)
    hour_histograms: DashMap<String, [u32; 24]>,
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
            hour_histograms: DashMap::new(),
        }
    }

    /// Record a tool call.
    pub fn record(&self, call: &ToolCall) {
        let mut entry = self.history.entry(call.agent_id.clone()).or_default();
        entry.push_back(call.tool_name.clone());
        if entry.len() > MAX_HISTORY {
            entry.pop_front();
        }

        // Update hour-of-day histogram
        let hour = call.timestamp.hour() as usize;
        let mut hist = self
            .hour_histograms
            .entry(call.agent_id.clone())
            .or_insert([0u32; 24]);
        hist[hour] = hist[hour].saturating_add(1);
    }

    /// Check for anomalous patterns. Returns description if anomaly detected.
    #[must_use]
    pub fn check_anomaly(&self, agent_id: &str) -> Option<String> {
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

        // Check for off-hours activity
        let current_hour = chrono::Utc::now().hour();
        if let Some(anomaly) = self.check_time_anomaly(agent_id, current_hour) {
            return Some(anomaly);
        }

        None
    }

    /// Check if a call at `current_hour` is outside the agent's established
    /// activity pattern. Returns `None` until the agent has enough history.
    #[must_use]
    fn check_time_anomaly(&self, agent_id: &str, current_hour: u32) -> Option<String> {
        let hist = self.hour_histograms.get(agent_id)?;
        let total: u32 = hist.iter().sum();
        if total < MIN_HISTORY_FOR_TIME_ANOMALY {
            return None;
        }

        // Build the "active window": hours where calls >= ACTIVE_HOUR_THRESHOLD of total
        let threshold = (total as f64 * ACTIVE_HOUR_THRESHOLD) as u32;
        let active_hours: u32 = hist.iter().filter(|&&c| c >= threshold.max(1)).count() as u32;

        // If agent is active in all 24 hours, no off-hours to detect
        if active_hours >= 24 {
            return None;
        }

        let hour_count = hist[current_hour as usize];
        if hour_count < threshold.max(1) {
            return Some(format!(
                "off-hours activity: hour {} is outside established pattern ({} of {} active hours)",
                current_hour, active_hours, 24
            ));
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
            analyzer.record(&call);
        }
        assert!(analyzer.check_anomaly("agent-1").is_none());
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
            analyzer.record(&call);
        }
        let anomaly = analyzer.check_anomaly("agent-1");
        assert!(anomaly.is_some());
        assert!(anomaly.unwrap().contains("enumeration"));
    }

    #[tokio::test]
    async fn no_anomaly_for_unknown_agent() {
        let analyzer = PatternAnalyzer::new();
        assert!(analyzer.check_anomaly("nobody").is_none());
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
            analyzer.record(&call);
        }
        // Pad to 20 calls with duplicates
        for _ in 0..6 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: "tool_0".to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call);
        }
        assert!(analyzer.check_anomaly("agent-1").is_none());
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
            analyzer.record(&call);
        }
        let anomaly = analyzer.check_anomaly("agent-1");
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
            analyzer.record(&call);
        }
        assert!(analyzer.check_anomaly("admin").is_none());
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
            analyzer.record(&call);
        }
        let history = analyzer.history.get("agent-1").unwrap();
        assert_eq!(history.len(), MAX_HISTORY);
    }

    #[tokio::test]
    async fn no_time_anomaly_new_agent() {
        let analyzer = PatternAnalyzer::new();
        // Only 10 calls — below MIN_HISTORY_FOR_TIME_ANOMALY threshold
        for _ in 0..10 {
            let call = ToolCall {
                agent_id: "new-agent".to_string(),
                tool_name: "tarang_probe".to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::Utc::now(),
            };
            analyzer.record(&call);
        }
        // Should not flag — insufficient history
        assert!(analyzer.check_time_anomaly("new-agent", 3).is_none());
    }

    #[tokio::test]
    async fn no_time_anomaly_within_pattern() {
        let analyzer = PatternAnalyzer::new();
        // 60 calls all at hour 10
        for _ in 0..60 {
            let call = ToolCall {
                agent_id: "agent-1".to_string(),
                tool_name: "tarang_probe".to_string(),
                params: serde_json::json!({}),
                timestamp: chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 4, 1, 10, 0, 0)
                    .unwrap(),
            };
            analyzer.record(&call);
        }
        // Checking at hour 10 — within pattern
        assert!(analyzer.check_time_anomaly("agent-1", 10).is_none());
    }

    #[tokio::test]
    async fn detect_time_anomaly_off_hours() {
        let analyzer = PatternAnalyzer::new();
        // 60 calls all during business hours (9-17)
        for h in 9..17 {
            for _ in 0..8 {
                let call = ToolCall {
                    agent_id: "agent-1".to_string(),
                    tool_name: "tarang_probe".to_string(),
                    params: serde_json::json!({}),
                    timestamp: chrono::TimeZone::with_ymd_and_hms(
                        &chrono::Utc,
                        2026,
                        4,
                        1,
                        h,
                        0,
                        0,
                    )
                    .unwrap(),
                };
                analyzer.record(&call);
            }
        }
        // Checking at hour 3 — outside pattern
        let anomaly = analyzer.check_time_anomaly("agent-1", 3);
        assert!(anomaly.is_some());
        assert!(anomaly.unwrap().contains("off-hours"));
    }

    #[tokio::test]
    async fn time_anomaly_uniform_no_flag() {
        let analyzer = PatternAnalyzer::new();
        // 72 calls evenly across all 24 hours (3 per hour)
        for h in 0..24 {
            for _ in 0..3 {
                let call = ToolCall {
                    agent_id: "agent-1".to_string(),
                    tool_name: "tarang_probe".to_string(),
                    params: serde_json::json!({}),
                    timestamp: chrono::TimeZone::with_ymd_and_hms(
                        &chrono::Utc,
                        2026,
                        4,
                        1,
                        h,
                        0,
                        0,
                    )
                    .unwrap(),
                };
                analyzer.record(&call);
            }
        }
        // Uniform distribution — no hour should flag
        for h in 0..24 {
            assert!(
                analyzer.check_time_anomaly("agent-1", h).is_none(),
                "hour {h} should not flag"
            );
        }
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
            analyzer.record(&call);
        }
        // agent-b has clean history
        let call = ToolCall {
            agent_id: "agent-b".to_string(),
            tool_name: "tarang_probe".to_string(),
            params: serde_json::json!({}),
            timestamp: chrono::Utc::now(),
        };
        analyzer.record(&call);
        assert!(analyzer.check_anomaly("agent-a").is_some());
        assert!(analyzer.check_anomaly("agent-b").is_none());
    }
}
