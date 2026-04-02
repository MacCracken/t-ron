//! Security middleware — wraps bote's Dispatcher with t-ron's security gate.
//!
//! Intercepts `tools/call` requests, runs the full check pipeline (policy, rate
//! limiting, payload scanning, pattern analysis), and blocks denied calls before
//! they reach the tool handler.

use crate::TRon;
use crate::gate::{DenyCode, ToolCall, Verdict};
use bote::Dispatcher;
use bote::protocol::{JsonRpcRequest, JsonRpcResponse};

/// JSON-RPC error code for security denials (server-defined range).
const SECURITY_DENIED: i32 = -32001;

/// Security gate wrapping a bote Dispatcher.
///
/// Every `tools/call` passes through t-ron's check pipeline before reaching the
/// inner dispatcher. Non-tool methods (initialize, tools/list) pass through
/// unmodified.
pub struct SecurityGate {
    tron: TRon,
    inner: Dispatcher,
}

impl SecurityGate {
    /// Create a new security gate.
    #[must_use]
    pub fn new(tron: TRon, dispatcher: Dispatcher) -> Self {
        Self {
            tron,
            inner: dispatcher,
        }
    }

    /// Access the inner dispatcher (e.g. for registering handlers).
    #[must_use]
    pub fn dispatcher_mut(&mut self) -> &mut Dispatcher {
        &mut self.inner
    }

    /// Access the inner dispatcher immutably.
    #[must_use]
    pub fn dispatcher(&self) -> &Dispatcher {
        &self.inner
    }

    /// Access the t-ron security monitor.
    #[must_use]
    pub fn tron(&self) -> &TRon {
        &self.tron
    }

    /// Register t-ron's tool handlers with the inner dispatcher.
    ///
    /// **Important:** The tool *definitions* must be registered in the
    /// `ToolRegistry` before creating the `Dispatcher`. Use
    /// [`tools::tool_defs()`](crate::tools::tool_defs) to get the definitions
    /// and register them alongside your application's tools. This method only
    /// wires up the handler functions.
    pub fn register_tool_handlers(&mut self) {
        use crate::tools;
        let query = self.tron.query();
        self.inner
            .handle("tron_status", tools::status_handler(query.clone()));
        self.inner
            .handle("tron_risk", tools::risk_handler(query.clone()));
        self.inner.handle("tron_audit", tools::audit_handler(query));
        self.inner
            .handle("tron_policy", tools::policy_handler(&self.tron));
    }

    /// Dispatch a JSON-RPC request with security checks.
    ///
    /// `agent_id` identifies the calling agent — this is the identity t-ron
    /// checks against its policy engine. Callers are responsible for
    /// authenticating the agent and providing a trusted ID.
    pub async fn dispatch(
        &self,
        request: &JsonRpcRequest,
        agent_id: &str,
    ) -> Option<JsonRpcResponse> {
        if request.method == "tools/call"
            && let Some(denied) = self.check_tool_call(request, agent_id).await
        {
            return Some(denied);
        }
        self.inner.dispatch(request)
    }

    /// Dispatch with streaming support and security checks.
    pub async fn dispatch_streaming(
        &self,
        request: &JsonRpcRequest,
        agent_id: &str,
    ) -> bote::DispatchOutcome {
        if request.method == "tools/call"
            && let Some(denied) = self.check_tool_call(request, agent_id).await
        {
            return bote::DispatchOutcome::Immediate(Some(denied));
        }
        self.inner.dispatch_streaming(request)
    }

    /// Run the security check pipeline for a tools/call request.
    /// Returns `Some(error_response)` if denied, `None` if allowed.
    async fn check_tool_call(
        &self,
        request: &JsonRpcRequest,
        agent_id: &str,
    ) -> Option<JsonRpcResponse> {
        let id = request.id.clone().unwrap_or(serde_json::Value::Null);
        let tool_name = match request.params.get("name").and_then(|v| v.as_str()) {
            Some(name) if !name.is_empty() => name,
            _ => {
                return Some(Self::deny_response(
                    id,
                    "missing or empty tool name in tools/call",
                    DenyCode::Unauthorized,
                ));
            }
        };
        let arguments = request
            .params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        let call = ToolCall {
            agent_id: agent_id.to_string(),
            tool_name: tool_name.to_string(),
            params: arguments,
            timestamp: chrono::Utc::now(),
        };

        let verdict = self.tron.check(&call).await;
        match verdict {
            Verdict::Deny { reason, code } => {
                tracing::warn!(
                    agent = agent_id,
                    tool = tool_name,
                    code = ?code,
                    "security gate denied tool call: {reason}"
                );
                Some(Self::deny_response(id, &reason, code))
            }
            Verdict::Flag { reason } => {
                tracing::info!(
                    agent = agent_id,
                    tool = tool_name,
                    "security gate flagged tool call: {reason}"
                );
                // Flags are allowed through — they're informational.
                None
            }
            Verdict::Allow => None,
        }
    }

    /// Build a JSON-RPC error response for a denied call.
    fn deny_response(id: serde_json::Value, reason: &str, code: DenyCode) -> JsonRpcResponse {
        JsonRpcResponse::error(id, SECURITY_DENIED, format!("security: {reason} [{code}]"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefaultAction, TRonConfig};
    use bote::registry::{ToolDef, ToolRegistry, ToolSchema};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_gate(config: TRonConfig) -> SecurityGate {
        let tron = TRon::new(config);
        let mut reg = ToolRegistry::new();
        reg.register(ToolDef::new(
            "echo",
            "Echo input",
            ToolSchema::new("object", HashMap::new(), vec![]),
        ));
        let mut dispatcher = Dispatcher::new(reg);
        dispatcher.handle(
            "echo",
            Arc::new(|params| {
                serde_json::json!({"content": [{"type": "text", "text": params.to_string()}]})
            }),
        );
        SecurityGate::new(tron, dispatcher)
    }

    fn tool_call_request(tool_name: &str, arguments: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest::new(1, "tools/call")
            .with_params(serde_json::json!({"name": tool_name, "arguments": arguments}))
    }

    #[tokio::test]
    async fn deny_unknown_agent() {
        let gate = make_gate(TRonConfig::default());
        let req = tool_call_request("echo", serde_json::json!({}));
        let resp = gate.dispatch(&req, "nobody").await.unwrap();
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, SECURITY_DENIED);
        assert!(err.message.contains("unauthorized"));
    }

    #[tokio::test]
    async fn allow_known_agent() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request("echo", serde_json::json!({"msg": "hello"}));
        let resp = gate.dispatch(&req, "agent-1").await.unwrap();
        assert!(resp.error.is_none());
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn allow_with_policy() {
        let gate = make_gate(TRonConfig::default());
        gate.tron()
            .load_policy(
                r#"
[agent."web-agent"]
allow = ["echo"]
"#,
            )
            .unwrap();
        let req = tool_call_request("echo", serde_json::json!({}));
        let resp = gate.dispatch(&req, "web-agent").await.unwrap();
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn deny_by_policy() {
        let gate = make_gate(TRonConfig::default());
        gate.tron()
            .load_policy(
                r#"
[agent."restricted"]
allow = ["tarang_*"]
deny = ["echo"]
"#,
            )
            .unwrap();
        let req = tool_call_request("echo", serde_json::json!({}));
        let resp = gate.dispatch(&req, "restricted").await.unwrap();
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn deny_injection() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request(
            "echo",
            serde_json::json!({"q": "1 UNION SELECT * FROM passwords"}),
        );
        let resp = gate.dispatch(&req, "agent").await.unwrap();
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert!(err.message.contains("injection_detected"));
    }

    #[tokio::test]
    async fn non_tool_call_passes_through() {
        let gate = make_gate(TRonConfig::default());
        // initialize should pass through regardless of agent
        let req = JsonRpcRequest::new(1, "initialize");
        let resp = gate.dispatch(&req, "unknown-agent").await.unwrap();
        assert!(resp.result.is_some());
    }

    #[tokio::test]
    async fn tools_list_passes_through() {
        let gate = make_gate(TRonConfig::default());
        let req = JsonRpcRequest::new(1, "tools/list");
        let resp = gate.dispatch(&req, "unknown-agent").await.unwrap();
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
    }

    #[tokio::test]
    async fn rate_limit_through_gate() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request("echo", serde_json::json!({}));
        for _ in 0..60 {
            let resp = gate.dispatch(&req, "agent").await.unwrap();
            assert!(resp.error.is_none());
        }
        // 61st should be rate limited
        let resp = gate.dispatch(&req, "agent").await.unwrap();
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("rate_limited"));
    }

    #[tokio::test]
    async fn streaming_dispatch_denied() {
        let gate = make_gate(TRonConfig::default());
        let req = tool_call_request("echo", serde_json::json!({}));
        match gate.dispatch_streaming(&req, "nobody").await {
            bote::DispatchOutcome::Immediate(Some(resp)) => {
                assert!(resp.error.is_some());
            }
            _ => panic!("expected Immediate(Some) for denied call"),
        }
    }

    #[tokio::test]
    async fn streaming_dispatch_allowed() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request("echo", serde_json::json!({}));
        match gate.dispatch_streaming(&req, "agent").await {
            bote::DispatchOutcome::Immediate(Some(resp)) => {
                assert!(resp.error.is_none());
            }
            _ => panic!("expected Immediate(Some) for allowed sync tool"),
        }
    }

    #[tokio::test]
    async fn audit_logged_through_gate() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            scan_payloads: false,
            analyze_patterns: false,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request("echo", serde_json::json!({}));
        gate.dispatch(&req, "agent-1").await;

        let query = gate.tron().query();
        assert_eq!(query.total_events().await, 1);
    }

    #[tokio::test]
    async fn deny_missing_tool_name() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let gate = make_gate(config);
        // tools/call with no "name" field
        let req =
            JsonRpcRequest::new(1, "tools/call").with_params(serde_json::json!({"arguments": {}}));
        let resp = gate.dispatch(&req, "agent").await.unwrap();
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("missing"));
    }

    #[tokio::test]
    async fn deny_empty_tool_name() {
        let config = TRonConfig {
            default_unknown_agent: DefaultAction::Allow,
            default_unknown_tool: DefaultAction::Allow,
            ..Default::default()
        };
        let gate = make_gate(config);
        let req = tool_call_request("", serde_json::json!({}));
        let resp = gate.dispatch(&req, "agent").await.unwrap();
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("missing"));
    }

    #[tokio::test]
    async fn deny_response_format() {
        let resp = SecurityGate::deny_response(
            serde_json::json!(42),
            "rate limit exceeded",
            DenyCode::RateLimited,
        );
        assert_eq!(resp.id, serde_json::json!(42));
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        assert_eq!(err.code, SECURITY_DENIED);
        assert!(err.message.contains("rate_limited"));
        assert!(err.message.contains("rate limit exceeded"));
    }
}
