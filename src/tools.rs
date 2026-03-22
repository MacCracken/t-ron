//! MCP tools — t-ron's own tools registered with bote for security queries.
//!
//! These tools are designed for the T.Ron personality in SecureYeoman:
//! - `tron_status` — overall security status
//! - `tron_risk` — per-agent risk score
//! - `tron_audit` — recent audit events
//! - `tron_policy` — current policy summary

use crate::query::TRonQuery;
use bote::dispatch::ToolHandler;
use bote::registry::{ToolDef, ToolSchema};
use std::collections::HashMap;
use std::sync::Arc;

/// Tool definitions for t-ron's MCP tools.
pub fn tool_defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "tron_status".into(),
            description: "Get overall security status: total events, denials, and system health."
                .into(),
            input_schema: ToolSchema {
                schema_type: "object".into(),
                properties: HashMap::new(),
                required: vec![],
            },
        },
        ToolDef {
            name: "tron_risk".into(),
            description:
                "Get risk score for an agent (0.0 = trusted, 1.0 = hostile). Requires agent_id."
                    .into(),
            input_schema: ToolSchema {
                schema_type: "object".into(),
                properties: HashMap::from([(
                    "agent_id".into(),
                    serde_json::json!({"type": "string", "description": "Agent to score"}),
                )]),
                required: vec!["agent_id".into()],
            },
        },
        ToolDef {
            name: "tron_audit".into(),
            description:
                "Get recent security events. Optional agent_id filter and limit (default 20)."
                    .into(),
            input_schema: ToolSchema {
                schema_type: "object".into(),
                properties: HashMap::from([
                    (
                        "agent_id".into(),
                        serde_json::json!({"type": "string", "description": "Filter by agent"}),
                    ),
                    (
                        "limit".into(),
                        serde_json::json!({"type": "integer", "description": "Max events to return", "default": 20}),
                    ),
                ]),
                required: vec![],
            },
        },
        ToolDef {
            name: "tron_policy".into(),
            description: "Load or reload policy from a TOML string.".into(),
            input_schema: ToolSchema {
                schema_type: "object".into(),
                properties: HashMap::from([(
                    "toml".into(),
                    serde_json::json!({"type": "string", "description": "Policy TOML content"}),
                )]),
                required: vec!["toml".into()],
            },
        },
    ]
}

/// Create handler for `tron_status`.
pub fn status_handler(query: TRonQuery) -> ToolHandler {
    let query = Arc::new(tokio::sync::Mutex::new(query));
    Arc::new(move |_params| {
        let query = query.clone();
        // Use block_on since bote handlers are sync.
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let q = query.lock().await;
            let total = q.total_events().await;
            let denials = q.total_denials().await;
            serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&serde_json::json!({
                        "total_events": total,
                        "total_denials": denials,
                        "denial_rate": if total > 0 { denials as f64 / total as f64 } else { 0.0 },
                        "status": if denials == 0 { "clean" } else { "active" }
                    })).unwrap()
                }]
            })
        })
    })
}

/// Create handler for `tron_risk`.
pub fn risk_handler(query: TRonQuery) -> ToolHandler {
    let query = Arc::new(tokio::sync::Mutex::new(query));
    Arc::new(move |params| {
        let query = query.clone();
        let agent_id = params
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let q = query.lock().await;
            let score = q.agent_risk_score(&agent_id).await;
            let level = match score {
                s if s >= 0.8 => "critical",
                s if s >= 0.5 => "high",
                s if s >= 0.2 => "medium",
                _ => "low",
            };
            serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&serde_json::json!({
                        "agent_id": agent_id,
                        "risk_score": score,
                        "risk_level": level
                    })).unwrap()
                }]
            })
        })
    })
}

/// Create handler for `tron_audit`.
pub fn audit_handler(query: TRonQuery) -> ToolHandler {
    let query = Arc::new(tokio::sync::Mutex::new(query));
    Arc::new(move |params| {
        let query = query.clone();
        let agent_id = params
            .get("agent_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async {
            let q = query.lock().await;
            let events = if let Some(ref aid) = agent_id {
                q.agent_audit(aid, limit).await
            } else {
                q.recent_events(limit).await
            };
            serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&events).unwrap()
                }]
            })
        })
    })
}

/// Create handler for `tron_policy`.
pub fn policy_handler(tron: &crate::TRon) -> ToolHandler {
    // policy_handler needs access to TRon to call load_policy.
    // Since load_policy takes &self and PolicyEngine uses RwLock internally,
    // we can share TRon behind an Arc. But TRon isn't Clone, so the caller
    // must provide a reference and we'll wrap the policy engine directly.
    // For now, take a clone of the policy Arc.
    let policy = tron.policy_arc();
    Arc::new(move |params| {
        let toml_str = params.get("toml").and_then(|v| v.as_str()).unwrap_or("");
        match policy.load_toml(toml_str) {
            Ok(()) => serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": "policy reloaded successfully"
                }]
            }),
            Err(e) => serde_json::json!({
                "content": [{
                    "type": "text",
                    "text": format!("policy error: {e}")
                }],
                "isError": true
            }),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_defs_all_present() {
        let defs = tool_defs();
        assert_eq!(defs.len(), 4);
        let names: Vec<&str> = defs.iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"tron_status"));
        assert!(names.contains(&"tron_risk"));
        assert!(names.contains(&"tron_audit"));
        assert!(names.contains(&"tron_policy"));
    }

    #[test]
    fn tool_defs_schemas_valid() {
        for def in tool_defs() {
            assert_eq!(def.input_schema.schema_type, "object");
            assert!(!def.description.is_empty());
        }
    }
}
