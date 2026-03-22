# Integration Guide

## Embedding t-ron in a bote Application

### 1. Add Dependencies

```toml
[dependencies]
t-ron = "0.22"
bote = "0.22"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### 2. Create the Security Gate

```rust
use t_ron::{TRon, TRonConfig, DefaultAction, middleware::SecurityGate, tools};
use bote::{Dispatcher, registry::{ToolRegistry, ToolDef, ToolSchema}};
use std::collections::HashMap;

// Configure t-ron
let config = TRonConfig {
    default_unknown_agent: DefaultAction::Deny,
    default_unknown_tool: DefaultAction::Deny,
    max_param_size_bytes: 65536,
    scan_payloads: true,
    analyze_patterns: true,
};
let tron = TRon::new(config);

// Load policy
tron.load_policy(r#"
[agent."web-agent"]
allow = ["my_tool_*"]
deny = ["my_tool_admin_*"]
"#).expect("invalid policy");

// Build tool registry with t-ron's tools + your app tools
let mut registry = ToolRegistry::new();
for def in tools::tool_defs() {
    registry.register(def);
}
registry.register(ToolDef {
    name: "my_tool_echo".into(),
    description: "Echo input".into(),
    input_schema: ToolSchema {
        schema_type: "object".into(),
        properties: HashMap::new(),
        required: vec![],
    },
});

// Create gate
let dispatcher = Dispatcher::new(registry);
let mut gate = SecurityGate::new(tron, dispatcher);

// Register t-ron's tool handlers
gate.register_tool_handlers();

// Register your app tool handlers
gate.dispatcher_mut().handle("my_tool_echo", /* handler */);
```

### 3. Dispatch Requests

```rust
// agent_id comes from your authentication layer
let agent_id = "web-agent";

// Dispatch with security checks
let response = gate.dispatch(&request, agent_id).await;

// Or with streaming support
let outcome = gate.dispatch_streaming(&request, agent_id).await;
```

### 4. Query Security State

```rust
let query = gate.tron().query();

// Risk score
let risk = query.agent_risk_score("web-agent").await;

// Recent events
let events = query.recent_events(20).await;

// Verify audit chain integrity
query.verify_chain().expect("chain tampered!");

// Chain summary
let review = query.chain_review();
println!("Total entries: {}", review.entry_count);
```

## Policy Configuration

Policies are TOML with per-agent allow/deny lists using glob patterns:

```toml
[agent."reader"]
allow = ["tarang_*", "rasa_read"]

[agent."admin"]
allow = ["*"]
deny = ["ark_remove"]

[agent."restricted"]
allow = ["tarang_probe"]
deny = ["*"]  # deny-all except tarang_probe
```

Rules:
- **Deny wins** — if a tool matches both allow and deny, it is denied
- **Glob suffix only** — `tarang_*` matches `tarang_probe`, `tarang_analyze`, etc.
- **Exact match** — `tarang_probe` matches only `tarang_probe`
- **Wildcard** — `*` matches everything
- **Unknown tool** — if an agent exists but the tool matches neither allow nor deny, the `default_unknown_tool` config applies

## DefaultAction Options

| Value | Behavior |
|-------|----------|
| `Deny` | Block the call, return JSON-RPC error |
| `Flag` | Allow the call through, log a warning |
| `Allow` | Allow the call, log normally |

## JSON-RPC Error Responses

Denied calls return a JSON-RPC error with code `-32001` and a message containing the deny code:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32001,
    "message": "security: unknown agent [unauthorized]"
  }
}
```

Deny codes: `unauthorized`, `rate_limited`, `injection_detected`, `tool_disabled`, `anomaly_detected`, `parameter_too_large`.
