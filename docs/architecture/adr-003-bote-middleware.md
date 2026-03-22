# ADR-003: SecurityGate as bote Middleware

## Status

Accepted

## Context

t-ron needs to intercept MCP tool calls before they reach tool handlers. Two approaches:

1. **Pre-dispatch hook** — bote provides a hook point; t-ron registers a callback
2. **Wrapper pattern** — t-ron wraps bote's `Dispatcher` and intercepts `tools/call` requests

## Decision

t-ron uses the **wrapper pattern** via `SecurityGate`:

```rust
pub struct SecurityGate {
    tron: TRon,
    inner: Dispatcher,
}
```

`SecurityGate::dispatch()` checks `tools/call` requests against the security pipeline, returning a JSON-RPC error response for denied calls. All other methods (`initialize`, `tools/list`) pass through unmodified.

## Consequences

- **Pro**: Full control over the dispatch lifecycle — can inspect request, build ToolCall, check verdict, format error response
- **Pro**: No coupling to bote's internal hook API — works with any bote version that exposes `Dispatcher`
- **Pro**: Streaming support via `dispatch_streaming()` with same security checks
- **Pro**: t-ron's own MCP tools (`tron_status`, etc.) registered on the inner dispatcher, themselves subject to security checks
- **Con**: Caller must use `SecurityGate` instead of `Dispatcher` directly — opt-in, not transparent

## Design Notes

- `agent_id` is a parameter to `dispatch()`, not extracted from the request. The caller (transport layer) is responsible for authenticating the agent. t-ron trusts the provided ID.
- Tool name validation happens at the gate level — malformed `tools/call` requests with missing or empty tool names are rejected before reaching the security pipeline.
- bote tool handlers are `Fn(&Value) -> Value` (sync). t-ron's tool handlers use `tokio::runtime::Handle::current().block_on()` to bridge async audit queries into the sync handler context.
