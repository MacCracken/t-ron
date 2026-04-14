# Changelog

All notable changes to t-ron are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/) and [Semantic
Versioning](https://semver.org/).

## [2.0.0] — 2026-04-14 · Cyrius port complete

### Breaking

- **Language**: Rust → [Cyrius](https://github.com/MacCracken/cyrius) 4.8.1 (pinned via `.cyrius-toolchain`).
- **Build**: `cargo build` → `cyrius build src/main.cyr build/t-ron`.
- **Async → sync**: the check pipeline is synchronous; concurrency guarantees move to the embedding dispatcher layer.
- **Risk / confidence scores**: `f64 [0.0, 1.0]` → integer basis points `i64 [0, 1000]`. Callers divide by 1000 for the original scale.
- **External runtime deps removed**: `tokio`, `dashmap`, `thiserror`, `serde_json`, `regex`, `chrono`, `uuid`, `ed25519-dalek`, `chacha20poly1305` are gone. Only libro + bote + sigil remain (all Cyrius). See [ADR-004](docs/architecture/adr-004-cyrius-port.md).
- **Audit-export wire format changed**: ChaCha20-Poly1305 → ChaCha20 + Ed25519 AEAD. Old Rust-format envelopes are not cross-readable. See [ADR-005](docs/architecture/adr-005-chacha20-ed25519-aead.md).

### Added

- Full Cyrius port: 16 modules in `src/*.cyr` covering the complete Rust 0.90.0 surface area.
- `cyrius.toml` with pinned deps: `libro` 1.0.3, `bote` **2.4.0** (+ sigil from Cyrius stdlib).
- `src/crypto_chacha20.cyr` — RFC 7539 ChaCha20 stream cipher, verified against the §2.4.2 test vector.
- `src/signing.cyr` — Ed25519 policy signature verification via sigil. `PolicyVerifier` holds trusted public keys; detached `.sig` files alongside the policy; `tron_verify_and_load_policy` gates the existing load path.
- `src/signal.cyr` — SIGHUP policy hot-reload via non-blocking `signalfd`. Consumer-polled API (`sighup_init` / `sighup_drain_and_reload` / `sighup_close`). `tron_load_policy_file` + `tron_reload_policy` round out the file-backed policy path.
- `src/llm_scan.cyr` — optional LLM-assisted prompt injection detection targeting hoosh 2.0 HTTP `/infer`. Self-contained via stdlib `net.cyr`.
- `src/safety.cyr` — full AGNOS safety submodule: `SafetySeverity` / `SafetyEnforcement` / `ActionType` / `SafetyRuleType` enums; `SafetyRule` / `SafetyPolicy` / `SafetyAction` / `SafetyVerdict` / `SafetyViolation` structs; 6-pattern `PromptInjectionDetector` with Unicode zero-width + directional-override normalization; `SafetyCircuitBreaker` (Closed → Open → HalfOpen sliding window); `SafetyEngine` with priority-ordered policy evaluation and per-agent basis-point score; 5 default AGNOS policies in `safety_default_policies()`. See [ADR-006](docs/architecture/adr-006-safety-submodule.md).
- `audit.cyr::audit_export_json` / `audit_export_encrypted` / `audit_decrypt_export` — plain-JSON ring-buffer dump plus ChaCha20 + Ed25519 AEAD envelope. Wire format: `nonce (12) ‖ signature (64) ‖ ciphertext (N)`.
- `tests/t-ron.tcyr` (299 assertions) + `tests/t-ron-crypto.tcyr` (30) + `tests/t-ron-safety.tcyr` (48) = **377 tests, 0 failures**.
- `scripts/bench-history.sh` — appends `cyrius bench` output to `bench-history.csv`.
- `.cyrius-toolchain` pins the compiler tag for reproducible builds.
- `.github/workflows/ci.yml` + `release.yml` — CI installs Cyrius from the release tarball.
- `docs/architecture/overview.md` + ADRs 001-006, `docs/development/roadmap.md` + `threat-model.md`, `docs/guides/integration.md` + `testing.md`, `docs/examples/01..04-*.cyr`, `docs/sources.md`, `docs/benchmarks-rust-v-cyrius.md`.

### Security — CVE-class audit

Full audit pass recorded at [`docs/audit/2026-04-14.md`](docs/audit/2026-04-14.md). **10 fixes** landed with regression tests:

- **F2** libro `uuid_v4` now fails-closed on `/dev/urandom` short read (was silent predictability risk).
- **F3** Identifier hardening: `tron_is_safe_identifier` rejects control chars, `0x1F`, `0x7F`, non-ASCII, and empty/oversized `agent_id`/`tool_name` at pipeline entry — closes rate-bucket collision + overlong-UTF-8 bypass.
- **F4a** MySQL versioned comments `/*!…*/` flagged as SQL evasion.
- **F4b** Null-byte keyword splitters (`uni\x00on`) flagged.
- **F4c** Overlong UTF-8 path traversal (`0xC0 0xAE 0xC0 0xAE`) flagged.
- **F4d** Shell `${IFS}` / `$9` / `{a,b,c}` filler now consumed before matching shell-bin names.
- **F5** Double-encoded path traversal `%252e%252e` and fully-hex `%25%32%45%25%32%45` flagged.
- **F6** Template scanner extended with `{%…%}` (Jinja), `<#…>` (FreeMarker), `#{…}` (ERB/Ruby) delimiters.
- **F7** Template `{{…}}` close scan: O(N²) → O(N). Unclosed opens no longer enable a ReDoS-analog.
- **F11** Empty `agent_id` rejection (subsumed by F3).

No performance regression (all benchmarks within noise).

### Benchmarks (x86_64, Cyrius 4.8.1, 2026-04-14)

| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | **719 ns** | 691 ns | 100 000 |
| `scanner_clean_text` | 4 µs | 3 µs | 100 000 |
| `scanner_sql_detect` | 1 µs | 1 µs | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | 41 µs | 39 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **52 µs** | 38 µs | 1 000 |

### Size

- **Binary**: Cyrius `build/t-ron` = **375 KB static x86_64 ELF** (no runtime, no libc, no dynamic loader).
- **Rust comparison**: `libt_ron.rlib` 2.59 MB + 193 MB transitive dep closure. See [`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md).
- **LOC**: 10 221 Rust → 6 637 Cyrius (−35 %), src-only 6 611 → 4 546 (−31 %).

### Fixed (upstream patches carried in-tree)

- Vendored patch to `lib/libro_entry.cyr::_cjh_hash_object` — upstream libro 1.0.3 passed a cstring to `json_get` (which wants a `Str`), causing SEGV on any non-empty details JSON. See memory note; drop the patch when libro ships a newer tag.

### Pending

- Description-hash pinning in bote registry (audit follow-up F1). Lives upstream; t-ron integrates once bote exposes the primitive.

## [0.90.0] — 2026-04-12 · Rust, final release before Cyrius port

### Added
- Cross-agent correlation detector: flags ≥ N distinct agents targeting the same tool inside a time window.
- `TRonConfig::enable_correlation` feature flag.
- Correlation alert wired into the `check()` pipeline as a `Flag` verdict.

## [0.26.3] — 2026-03-26

### Added
- `load_policy_file(path)` — load policy from a TOML file and store the path for hot-reload.
- `reload_policy()` — re-read the stored policy file (designed for SIGHUP handlers).
- `RateLimitPolicy` in per-agent TOML config — `calls_per_minute` wired into the rate limiter.
- Per-agent rate overrides stored in `RateLimiter` — new buckets respect policy rates from creation.
- `PolicyEngine::config()` — read snapshot of current policy config.
- Benchmark suite (`benches/pipeline.rs`) — 10 criterion benchmarks covering the full pipeline.
- `scripts/bench-history.sh` — CSV benchmark history tracking.

### Changed
- `scanner::scan()` returns `Option<&'static str>` (avoids allocation per threat).
- `RiskScorer::score()` uses single-pass fold instead of two iterator passes.
- `TRon::check()` uses zero-alloc `ByteCounter` for param size check instead of `to_string()`.
- `RateLimiter::bucket_key()` uses `write!` with pre-sized `String` instead of `format!`.
- All lock acquisitions use `unwrap_or_else(|p| p.into_inner())` — no more panics on lock poisoning.

### Fixed
- Added `#[non_exhaustive]` to all public enums.
- Added `#[must_use]` to all pure functions and constructors.
- Added `#[inline]` to hot-path functions.
- Removed `expect()` panics from library code.

## [0.22.4] — 2026-03-22

### Added
- libro audit chain integration: every security event is dual-written to an in-memory ring buffer (fast queries) and a libro cryptographic hash chain (tamper-proof audit trail).
- `AuditLogger::verify_chain()`, `chain_review()`, `chain_len()`.
- `TRonQuery::verify_chain()`, `chain_review()`, `chain_len()` — chain access from query API.
- Verdict-to-libro mapping: Allow → Info, Flag → Warning, Deny → Security. Source `"t-ron"`, actions `tool_call.{allow,deny,flag}`.
- `DenyCode::as_str()` and `Display` impl — canonical deny code labels consolidated.

### Fixed
- Payload scanner enforces max recursion depth (64) to prevent stack overflow on deeply nested JSON.
- Removed duplicated deny-code label functions from `audit.rs` and `middleware.rs`.
- Extracted `default_action_verdict()` helper.

## [0.22.3] — 2026-03-22

### Added
- Core gate types: `ToolCall`, `Verdict`, `DenyCode`.
- Policy engine with per-agent ACLs, glob pattern matching, deny-wins semantics, TOML config.
- Token bucket rate limiter (per-agent, per-tool, default 60 calls/minute).
- Payload scanner: SQL injection, shell injection, template injection, path traversal detection.
- Pattern analyzer: tool enumeration and privilege escalation detection.
- Risk scorer: rolling per-agent threat score (0.0–1.0) weighted by denials and flags.
- Audit logger: UUID-tagged events with ring buffer (10k max).
- T.Ron query API for SecureYeoman personality.
- `SecurityGate` middleware wrapping bote `Dispatcher` with pre-dispatch security checks.
- MCP tools: `tron_status`, `tron_risk`, `tron_audit`, `tron_policy`.
- Streaming dispatch support via `dispatch_streaming()`.
- JSON-RPC error responses (code -32001) with deny code labels.
