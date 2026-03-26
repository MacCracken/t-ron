# Changelog

All notable changes to t-ron are documented here.

## [0.26.3] — 2026-03-26

### Added
- `load_policy_file(path)` — load policy from a TOML file and store the path for hot-reload
- `reload_policy()` — re-read the stored policy file (designed for SIGHUP handlers)
- `RateLimitPolicy` in per-agent TOML config — `calls_per_minute` now wired into the rate limiter
- Per-agent rate overrides stored in `RateLimiter` — new buckets respect policy rates from creation
- `PolicyEngine::config()` — read snapshot of current policy config
- Benchmark suite (`benches/pipeline.rs`) — 10 criterion benchmarks covering the full pipeline
- `scripts/bench-history.sh` — CSV benchmark history tracking

### Changed
- `scanner::scan()` returns `Option<&'static str>` instead of `Option<String>` (avoids allocation per threat)
- `RiskScorer::score()` uses single-pass fold instead of two iterator passes
- `TRon::check()` uses zero-alloc `ByteCounter` for param size check instead of `to_string()`
- `RateLimiter::bucket_key()` uses `write!` with pre-sized `String` instead of `format!`
- All lock acquisitions use `unwrap_or_else(|p| p.into_inner())` — no more panics on lock poisoning

### Fixed
- Added `#[non_exhaustive]` to all public enums (`Verdict`, `VerdictKind`, `DenyCode`, `DefaultAction`, `PolicyResult`, `TRonError`)
- Added `#[must_use]` to all pure functions and constructors
- Added `#[inline]` to hot-path functions
- Removed `expect()` panics from library code (was violating no-panic policy)

## [0.22.4] — 2026-03-22

### Added
- libro audit chain integration: every security event is dual-written to an in-memory ring buffer (fast queries) and a libro cryptographic hash chain (tamper-proof audit trail)
- `AuditLogger::verify_chain()` — verify libro chain integrity
- `AuditLogger::chain_review()` — structured chain summary
- `AuditLogger::chain_len()` — libro chain entry count
- `TRonQuery::verify_chain()`, `chain_review()`, `chain_len()` — chain access from query API
- Verdict-to-libro mapping: Allow→Info, Flag→Warning, Deny→Security; source `"t-ron"`, actions `tool_call.{allow,deny,flag}`
- `DenyCode::as_str()` and `Display` impl — canonical deny code labels consolidated in one place

### Fixed
- Payload scanner now enforces max recursion depth (64) to prevent stack overflow on deeply nested JSON
- Removed duplicated deny code label functions from `audit.rs` and `middleware.rs` (now uses `DenyCode::as_str()`)
- Extracted `default_action_verdict()` helper to reduce duplication in `TRon::check()` policy handling

## [0.22.3] — 2026-03-22

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
- Removed unnecessary `tokio::sync::Mutex` from tool handlers (`TRonQuery` is already `Send+Sync` via `Arc` internals)
- Commented out `RateLimitPolicy` in policy config (was parsed from TOML but silently ignored by rate limiter)
