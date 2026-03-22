# Testing Guide

## Running Tests

```bash
# All tests
cargo test

# With output
cargo test -- --nocapture

# Specific module
cargo test audit::tests
cargo test middleware::tests
cargo test scanner::tests
```

## Test Categories

| Module | Tests | Coverage |
|--------|-------|----------|
| `gate` | 6 | Verdict semantics, serde roundtrips, DenyCode variants |
| `policy` | 10 | Glob matching, deny-wins, TOML loading, reload, multi-agent |
| `rate` | 6 | Token bucket, separate buckets, set_rate clamping, refill |
| `scanner` | 18 | SQL/shell/template/path injection, nested JSON, short-circuit |
| `pattern` | 7 | Tool enumeration, privilege escalation, ring buffer, per-agent |
| `audit` | 13 | Ring buffer, libro chain writes, chain integrity, agent filtering |
| `score` | 6 | Zero/max risk, flags, mixed verdicts, single events |
| `query` | 5 | Initial state, after checks, risk scores, agent trails, chain verification |
| `middleware` | 15 | Gate deny/allow, policy, injection, rate limit, streaming, tool name validation |
| `tools` | 2 | Tool definitions present, schemas valid |
| `lib` | 16 | Full pipeline integration tests |

**Total: 109 tests**

## Makefile Targets

```bash
make check    # fmt + clippy + test
make fmt      # cargo fmt --check
make clippy   # clippy with -D warnings
make test     # cargo test
make audit    # cargo audit
make deny     # cargo deny check
make build    # release build
make doc      # cargo doc
```

## Writing Tests

### Testing Policy

```rust
let tron = TRon::new(TRonConfig::default());
tron.load_policy(r#"
[agent."test-agent"]
allow = ["my_tool"]
deny = ["dangerous_*"]
"#).unwrap();

let call = gate::ToolCall {
    agent_id: "test-agent".to_string(),
    tool_name: "my_tool".to_string(),
    params: serde_json::json!({}),
    timestamp: chrono::Utc::now(),
};
let verdict = tron.check(&call).await;
assert!(verdict.is_allowed());
```

### Testing Through SecurityGate

```rust
// Use the test helper in middleware::tests
fn make_gate(config: TRonConfig) -> SecurityGate { /* ... */ }
fn tool_call_request(tool_name: &str, args: Value) -> JsonRpcRequest { /* ... */ }

let gate = make_gate(TRonConfig::default());
let req = tool_call_request("echo", json!({}));
let resp = gate.dispatch(&req, "agent-id").await;
```

### Verifying Chain Integrity

```rust
let logger = AuditLogger::new();
// ... log events ...
assert!(logger.verify_chain().is_ok());
assert_eq!(logger.chain_len(), expected_count);
```
