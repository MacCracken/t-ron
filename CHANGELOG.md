# Changelog

All notable changes to t-ron are documented here.

## [0.1.0] — 2026-03-22

### Added
- Core security gate types: `ToolCall`, `Verdict`, `DenyCode`
- Policy engine with per-agent ACLs, glob pattern matching, deny-wins semantics, TOML config
- Token bucket rate limiter (per-agent, per-tool, default 60 calls/minute)
- Payload scanner: SQL injection, shell injection, template injection, path traversal detection
- Pattern analyzer: tool enumeration and privilege escalation anomaly detection
- Risk scorer: rolling per-agent threat score (0.0–1.0) weighted by denials and flags
- Audit logger: UUID-tagged events with ring buffer (10k max)
- T.Ron query API for SecureYeoman personality
- `SecurityGate` middleware wrapping bote `Dispatcher` with pre-dispatch security checks
- MCP tools: `tron_status`, `tron_risk`, `tron_audit`, `tron_policy`
- Streaming dispatch support via `dispatch_streaming()`
- JSON-RPC error responses (code -32001) with deny code labels for blocked calls

### Fixed
- Path traversal scanner now case-insensitive for URL-encoded sequences (`%2E%2E` was bypassing detection)
- `set_rate` now clamps current tokens to new max (lowered rate limits take effect immediately)
- `SecurityGate` rejects `tools/call` requests with missing or empty tool name
- `tron_policy` tool rejects empty TOML input instead of silently wiping all policy
- `tron_audit` tool caps limit at 1000 to prevent unbounded responses
