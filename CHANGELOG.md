# Changelog

All notable changes to t-ron are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/) and [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-04-14

### Changed — **Cyrius port**
This release is a ground-up rewrite from Rust 0.90.0 to [Cyrius](https://github.com/MacCracken/cyrius). The Rust sources are archived in `rust-old/` for reference. External dependencies — `tokio`, `dashmap`, `thiserror`, `serde_json`, `regex`, `chrono`, `uuid`, `ed25519-dalek`, `chacha20poly1305` — are gone; everything is either stdlib or sourced from other ported AGNOS crates (libro, sigil) or bote.

- **Language**: Rust → Cyrius 4.5.0 (pinned via `.cyrius-toolchain`)
- **Build**: `cargo build` → `cyrius build src/main.cyr build/t-ron`
- **Async → sync**: the check pipeline is synchronous; concurrency guarantees move to the embedding dispatcher layer
- **Risk score**: f64 `0.0..=1.0` → integer basis points `0..=1000` (divide by 1000 for the original scale)
- **Sizes**: 6 611 Rust LOC → 2 436 Cyrius LOC across 14 modules (~46 % reduction)
- **Binary**: 320 KB x86_64 (no runtime, no libc, static ELF)

### Added
- `cyrius.toml` with pinned deps: `libro` 1.0.3, `bote` 1.9.2
- `tests/t-ron.tcyr` — 62 test groups, 245 assertions covering the full pipeline
- `tests/t-ron.bcyr` — 5 benchmarks (policy_check, scanner variants, audit_log, full check)
- `scripts/bench-history.sh` — appends `cyrius bench` output to `bench-history.csv`
- `.cyrius-toolchain` pin for reproducible builds
- `.github/workflows/ci.yml`, `release.yml` — CI installs Cyrius toolchain from release tarballs

### Fixed
- Vendored patch to libro 1.0.3 `_cjh_hash_object`: upstream passed a cstring to `json_get` (which wants a `Str`), causing SEGV on any non-empty details JSON. See [memory note](.claude/memory/libro_1_0_3_bug.md) — drop the patch when libro ships a newer tag.

### Pending (waiting on dependencies)
- `llm_scan.cyr` — integration with the (already-ported) hoosh Cyrius crate, blocked on bote's final WebSocket release
- `signing.cyr` — sigil Ed25519 policy signature verification
- `signal.cyr` — SIGHUP hot-reload via signalfd
- `safety/` submodule — AI guardrails (5 Rust files, ~1 500 LOC)
- `export_encrypted` on `AuditLogger` — ChaCha20-Poly1305 audit export

### Benchmarks (x86_64, Cyrius 4.5.0, 2026-04-14)
| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | **727 ns** | 681 ns | 100 000 |
| `scanner_clean_text` | 3 µs | 3 µs | 100 000 |
| `scanner_sql_detect` | 1 µs | 1 µs | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | 44 µs | 40 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **54 µs** | 37 µs | 1 000 |

## [0.90.0] — 2026-04-12 (Rust, final release before Cyrius port)

### Added
- Cross-agent correlation detector (`correlation.cyr`): flags ≥ N distinct agents targeting the same tool inside a time window
- `TRonConfig::enable_correlation` feature flag
- Correlation alert wired into the `check()` pipeline as a `Flag` verdict

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
