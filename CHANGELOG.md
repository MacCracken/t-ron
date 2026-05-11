# Changelog

All notable changes to t-ron are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/) and [Semantic
Versioning](https://semver.org/).

### Conventions

Adopted in **2.1.0** — the **`## [Unreleased]`** section below
accumulates entries during the patch cycle. When a release ships,
the `## [Unreleased]` header is renamed to `## [VERSION] — DATE —
headline` and a fresh, empty `## [Unreleased]` is seeded at the
top. Mirrors bote 2.7.0's flow.

## [Unreleased]

> Note: docs-only changes don't earn a version bump in t-ron;
> they accumulate here until the next release-worthy patch (code,
> CI, release-flow, dep-pin, manifest, tests) ships and the notes
> ride along.

### Changed (docs)

- **`CONTRIBUTING.md`** rewritten Cyrius-era. Drops the Rust-era
  `cargo` / `make` / MSRV 1.89 / `src/lib.rs` references.
  New sections: Prerequisites (cyrius toolchain only); Common
  Commands table (`cyrius deps` / `cyrius build` / `cyrius test`
  / `cyrius bench` / `cyrius distlib` / `CYRIUS_STATS` /
  `CYRIUS_DCE` / `CYRIUS_NO_WARN_SHADOW_LIB`); Release
  Discipline (docs-only commits don't earn a version bump);
  Adding a New Security Check (`[lib] modules` + main.cyr include
  order + 3-file test split + `dist/t-ron.cyr` regen); Code
  Style (cyrius equivalents for `#[non_exhaustive]` /
  `#[must_use]` / `#[inline]`, `ct_eq_bytes_lens` for
  constant-time compares, bote 2.0 handler ABI). Mirrors bote
  2.7.1's CONTRIBUTING rewrite.
- **`CLAUDE.md`** Rust-era discipline items re-cast for cyrius.
  Project Identity now reflects the Cyrius port (cyrius 5.10.34
  pin, `VERSION` + `${file:VERSION}` as single source of truth);
  cleanliness check uses `cyrius deps --verify` /
  `cyrius distlib` / `CYRIUS_STATS=1` / `git diff --exit-code
  dist/t-ron.cyr` rather than `cargo fmt` / `cargo clippy`;
  `#[non_exhaustive]` / `#[must_use]` / `#[inline]` re-cast as
  the cyrius-equivalent disciplines; `unwrap()`/`panic!()` DO-NOT
  entries reframed as "no unguarded `syscall(60, ...)` or
  out-of-bounds in library code"; new Release Discipline section
  formalizes the docs-no-version-bump rule; added Bote handler
  ABI and `src/_libro_compat.cyr` notes.
- No code, CI, release-flow, dep-pin, manifest, or test change.
  Emitted binary byte-identical; `dist/t-ron.cyr` unchanged.

## [2.1.2] — 2026-05-10 · CI capacity gate

Third patch of the **2.1.x modernization arc**. Wires the
compile-time resource gate modeled on bote 2.6.4: `CYRIUS_STATS=1`
at build time, parse the `cyrius stats:` tail of stdout, fail CI
when `fn_table` or `identifiers` cross 95%. No source change; no
SecurityGate behaviour change; emitted binary byte-identical.

### Added

- **`.github/workflows/ci.yml`** — two new steps:
  - **Build** step now passes `CYRIUS_STATS=1` and tees stdout to
    `build/build.log` so the capacity report is captured for the
    next step.
  - **Capacity gate** step parses the `cyrius stats:` block,
    computes utilisation percentages, fails CI at ≥95% on
    `fn_table` or `identifiers`.

### Current utilisation (cyrius 5.10.34, 2026-05-10)

| Counter | Used | Cap | % |
|---|---:|---:|---:|
| `fn_table` | 3 076 | 4 096 | 75 % |
| `identifiers` | 91 014 | 131 072 | 69 % |
| `var_table` | 1 615 | 8 192 | 20 % |
| `fixup_table` | 9 689 | 262 144 | 4 % |
| `string_data` | 28 103 | 2 097 152 | 1 % |
| `code_size` | 1 013 096 | 1 048 576 | **97 %** |

`fn_table` and `identifiers` have headroom; the gate is here to
catch future regression.

### Watch — code_size headroom

`code_size` (the cyrius compile-time code-buffer cap, distinct
from the post-DCE emitted binary size) is at **97 %** — the
most-constrained dimension. It is intentionally **not** gated at
95 % today because that would ship an immediately-firing gate.
The gate surfaces it as a `::warning::` for visibility. Response
paths (ordered by preference):

1. Upstream cyrius cap raise (the cap has moved before —
   identifier buffer 32 KB → 128 KB at 4.6.2, fn_table
   2048 → 4096 at 4.7.1).
2. Feature-gate `src/llm_scan.cyr` / `src/safety.cyr` /
   `src/signing.cyr` behind `#ifdef` markers so consumers that
   don't need them shed the code-emit cost.
3. Split an opt-in compile unit (mirrors bote's `libro_tools.cyr`
   pattern at 2.6.4).

Tracked under the 2.1.x arc; specific patch number assigned when
the response path is chosen.

### Regenerated

- `dist/t-ron.cyr` — header now stamps `# Version: 2.1.2`. Bytes
  otherwise unchanged from 2.1.1; CI freshness gate verifies.

## [2.1.1] — 2026-05-10 · `dist/t-ron.cyr` consumer bundle

Second patch of the **2.1.x modernization arc**. Lands the
single-file consumer distribution bundle (`dist/t-ron.cyr` via
`cyrius distlib`) that the named consumers — daimon, phylax, bote
middleware — pull through `[deps.t-ron]`. Mirrors libro 2.6.3 and
bote 2.6.3.

No SecurityGate behaviour change; the bundle is the same code
that `src/main.cyr` already includes, concatenated in the
`[lib] modules` declaration order.

### Added

- **`dist/t-ron.cyr`** — 4 512 lines / 157 KB, deterministically
  produced by `cyrius distlib` from the 19 files listed in
  `cyrius.cyml [lib] modules` (1 compat shim + 18 src/ modules).
  Bundle header stamps `# Version: 2.1.1` from VERSION.
- **`DEPS-PATTERN.md`** at repo root — the distribution contract
  for downstream consumers. Mirrors libro's pattern doc:
  what's-in / what's-not-in the bundle, the canonical wire-up
  (`[deps.t-ron] modules = ["dist/t-ron.cyr"]`), pre-release
  verification checklist, and a reference to bote/libro for
  drift checks.
- **`.github/workflows/ci.yml`** — `dist/t-ron.cyr is up-to-date`
  step. Regenerates the bundle on every push and fails CI if the
  committed copy no longer matches src/. Catches the "I edited a
  module but forgot to run `cyrius distlib`" mistake before any
  consumer pulls a stale tag.
- **`.github/workflows/release.yml`** — three new pieces:
  - `Regenerate dist bundle` step before any asset upload —
    ensures the tag carries a fresh `dist/t-ron.cyr`.
  - `Verify dist bundle matches committed copy` step — refuses
    the release if the bundle would change.
  - `t-ron-<tag>.cyr` added to the release-asset upload list +
    SHA256SUMS line, alongside `t-ron-<tag>-src.tar.gz`,
    `t-ron-<tag>-x86_64-linux`, and `cyrius.lock`.

### Performance

No change. The bundle is the same `[lib]` source preprocessed in
a different shape; the emitted binary is byte-identical.

## [2.1.0] — 2026-05-10 · Toolchain + dep floor

First patch of the **2.1.x modernization arc**. Catches t-ron up
to the first-party Cyrius floor: cyrius 5.10.34 (was 4.8.4), libro
2.6.2 (was 1.0.3), bote 2.7.1 (was 2.5.1). Lands the bote 2.0
handler-ABI observance that 2.0.0 missed, modernizes the manifest
layout (`cyrius.cyml` + `${file:VERSION}` interpolation), and
ships `cyrius.lock` + the versioned-toolchain CI installer. 2.1.x
continues with deferred items — see `docs/development/roadmap.md`.

No MCP-surface change; the SecurityGate wire format and the four
introspection tools (`tron_status` / `tron_risk` / `tron_audit` /
`tron_policy`) are byte-identical at the JSON-RPC boundary.

### Breaking

- **bote 2.0 handler ABI now observed end-to-end.** Tool handlers
  changed signature from `fn h(args)` → `fn h(args, claims)` per
  bote's 2.0 dispatcher (`fncall2(fp, args, claims)`). t-ron's
  four handlers (`tron_status_handler`, `tron_risk_handler`,
  `tron_audit_handler`, `tron_policy_handler`) ignore `claims`
  in 2.1.0; gating them on caller identity is a 2.2.x candidate
  once the agnosticos claims schema firms up.
  `security_gate_dispatch` now forwards `claims = 0` to bote's
  `dispatcher_dispatch(d, request, claims)` — explicit "no auth
  context" mode, documented at bote `src/dispatch.cyr:380`.
  Consumers using `security_gate_dispatch(g, req, agent_id)`
  retain the same 3-arg surface; the bote-ABI change is internal.
- **Manifest renamed**: `cyrius.toml` → `cyrius.cyml`. Body
  changes: `version = "${file:VERSION}"` (single-source-of-truth
  via VERSION file), new `[lib] modules = […]` enumerating all
  src/ files in include order (the `cyrius distlib` contract;
  shipping a `dist/t-ron.cyr` consumer bundle is a later 2.1.x
  candidate), `repository` field added, libro/bote dep `tag` +
  `modules` lists refreshed.
- **Vendored libro patch retired.** The 2.0.0 in-tree patch to
  `lib/libro_entry.cyr::_cjh_hash_object` (cstring vs Str arg
  to `json_get`) is no longer in the source tree — libro 2.6.2's
  dist bundle carries the upstream fix.

### Added

- **`src/_libro_compat.cyr`** — one-symbol shim that maps libro
  2.6.2's `ct_eq(a, a_len, b, b_len)` to cyrius stdlib's
  `ct_eq_bytes_lens` (renamed in cyrius 5.9.20 paired with sigil
  3.0.2). bote sidesteps this because its only `chain_verify`
  caller is in opt-in `libro_tools.cyr`; t-ron's audit module
  hits `chain_verify` on every `audit_log`, so the symbol has
  to resolve. Drops when libro retags with the new name.
- **`cyrius.lock`** committed — 15 deps, SHA-256 hashes for every
  resolved `lib/<dep>.cyr`. CI's `cyrius deps --verify` gate now
  asserts byte-identity on every push.
- **`.gitignore`** entry for `/lib/` — first-party convention
  (cyrius deps populates lib/ from the lockfile pin; the contract
  is the hash, not the bytes on disk).
- **`.github/workflows/ci.yml`** — modernized installer matching
  bote / libro / agnosys 5.10.x: release tarball (binaries +
  deps cache) + source archive (stdlib snapshot) + versioned
  `~/.cyrius/versions/<V>/` layout + symlinked `~/.cyrius/{bin,lib}`.
  New gates: toolchain pin read from `cyrius.cyml` (not
  `.cyrius-toolchain`), `cyrius deps --verify` (soft-skip if
  lockfile absent), manifest-completeness check (every src/
  `include` in main.cyr ⊆ `[lib] modules`), 3-suite test matrix
  (`t-ron` / `-crypto` / `-safety`), benchmark capture as
  artifact, `CYRIUS_DCE: "1"` + `CYRIUS_NO_WARN_SHADOW_LIB: "1"`.
  Docs-job verifies `${file:VERSION}` interpolation literal and
  VERSION ↔ CHANGELOG agreement.
- **`.github/workflows/release.yml`** — same installer plus
  semver-shape tag check (accepts both `v2.1.0` and `2.1.0`),
  source-archive + linux-x86_64 binary + cyrius.lock + SHA256SUMS
  in the release-asset bundle. Per-version changelog extraction
  feeds the GitHub release body.
- **`## [Unreleased]`** changelog flow adopted (bote 2.7.0
  convention).
- **`docs/doc-health.md`** — living ledger classifying every doc
  in the tree (Fresh / Stale / Read-through-outstanding /
  No-version-tied / Historical / ADR), refreshed in place as docs
  are touched. Mirrors libro's pattern.
- **`docs/development/roadmap.md`** rewritten — Shipped table
  through 2.1.0; 2.1.x modernization arc table; forward items
  deferred to 2.2.x+ (audit-tool authorization plumbed on the new
  `claims` arg; agnoshi intents; Phase 2 advanced detection;
  Phase 2A capability-source policy / L3 agent-injection defense;
  Phase 3 hardening with policy-signing + encrypted-export marked
  ✅-already-shipped at 2.0.0).
- **`docs/examples/01..03-*.cyr`** updated for the 2.1.0 dep
  surface — swap the eight per-module `lib/libro_*.cyr` includes
  for `lib/libro.cyr` + `lib/ct.cyr` + the `src/_libro_compat.cyr`
  shim. All four examples verified end-to-end:
  `01-minimal-gate` (allow + deny paths), `02-signed-policy`
  (Ed25519 sign + verify_and_load round-trip),
  `03-audit-export` (ChaCha20 + Ed25519 AEAD envelope round-trip,
  456-byte envelope), `04-safety-check` (default-policy load +
  forbidden-action match). `04` needed no include change — the
  safety module is self-contained.

### Changed

- `.cyrius-toolchain` → `5.10.34` (kept as a local-dev convenience;
  CI now reads the pin from `cyrius.cyml`).
- **`cyrius.cyml [deps].stdlib`** trimmed — `sigil` and `sakshi`
  are no longer listed here even though `src/main.cyr` includes
  them. libro 2.6.2 pulls both transitively (`[deps.sigil]` tag
  3.0.1 + libro's own stdlib reference). Listing them in t-ron's
  stdlib too made `cyrius deps` attempt two writes to
  `lib/sigil.cyr` / `lib/sakshi.cyr`; locally the bytes are
  identical and the second write silently succeeds, but CI
  reports it as `error: cannot write lib/sigil.cyr` and fails the
  resolve step. Same pattern bote uses for transitive sigil
  resolution.
- `scripts/version-bump.sh` reduced to its single load-bearing
  side effect — writing VERSION. With `${file:VERSION}`
  interpolation the manifest does not need editing. The 2.0.0-era
  cargo block (regenerating Cargo.lock, editing Cargo.toml) is
  gone.

### Performance (cyrius 5.10.34 vs 4.8.4, x86_64, 2026-05-10)

| Operation | 2.0.0 | 2.1.0 | Δ |
|---|---:|---:|---:|
| `policy_check` | 719 ns | 489 ns min / 1 µs avg | ~flat (signal at min) |
| `scanner_clean_text` | 4 µs | 4 µs | flat |
| `scanner_sql_detect` | 1 µs | 2 µs avg / 978 ns min | ~flat (signal at min) |
| `audit_log` | 41 µs | **13 µs** | **−68 %** |
| `tron_check_allow` | 52 µs | **17 µs** | **−67 %** |

The full-pipeline wins come from libro 2.6.2's chain optimizations
plus cyrius 5.10.x codegen.

### Size

- **Binary**: `build/t-ron` = **1.12 MB** static x86_64 ELF (was
  375 KB at 2.0.0). The growth is from pulling libro's full
  `dist/libro.cyr` bundle in for the `#derive(accessors)` getters
  that libro 2.0 relies on (per-module pull leaves them
  undefined). bote stays on a per-module pull (nine files) to keep
  the preprocessed source under cyrius's 2 MB compile cap.

### Pending / parked

- **`dist/t-ron.cyr` consumer bundle** via `cyrius distlib` — the
  `[lib] modules` section is staged; `dist/t-ron.cyr` itself ships
  in 2.1.x once the consumer story (daimon, bote middleware,
  phylax) is reviewed end-to-end.
- **Full dist-bundle dep adoption (bote)** — blocked on either a
  cyrius compile-source-size cap raise or a bote opt-in profile
  that excludes the transport stack (sandhi/tls/ws_server). Today
  the two dist bundles together expand past 2 MB.
- **Test-suite refactor for the cyrius 5.10.x assert-nested-call
  parser quirk** (bote 2.7.1 CONTRIBUTING). Not triggered in
  t-ron's current test files at 2.1.0; documented in 2.1.x for
  re-investigation if it surfaces on a future test add.

## [2.0.0] — 2026-04-14 · Cyrius port complete

### Breaking

- **Language**: Rust → [Cyrius](https://github.com/MacCracken/cyrius) 4.8.4 (pinned via `.cyrius-toolchain`).
- **Build**: `cargo build` → `cyrius build src/main.cyr build/t-ron`.
- **Async → sync**: the check pipeline is synchronous; concurrency guarantees move to the embedding dispatcher layer.
- **Risk / confidence scores**: `f64 [0.0, 1.0]` → integer basis points `i64 [0, 1000]`. Callers divide by 1000 for the original scale.
- **External runtime deps removed**: `tokio`, `dashmap`, `thiserror`, `serde_json`, `regex`, `chrono`, `uuid`, `ed25519-dalek`, `chacha20poly1305` are gone. Only libro + bote + sigil remain (all Cyrius). See [ADR-004](docs/architecture/adr-004-cyrius-port.md).
- **Audit-export wire format changed**: ChaCha20-Poly1305 → ChaCha20 + Ed25519 AEAD. Old Rust-format envelopes are not cross-readable. See [ADR-005](docs/architecture/adr-005-chacha20-ed25519-aead.md).

### Added

- Full Cyrius port: 16 modules in `src/*.cyr` covering the complete Rust 0.90.0 surface area.
- `cyrius.toml` with pinned deps: `libro` 1.0.3, `bote` **2.5.1** (+ sigil from Cyrius stdlib).
- `src/crypto_chacha20.cyr` — RFC 7539 ChaCha20 stream cipher, verified against the §2.4.2 test vector.
- `src/signing.cyr` — Ed25519 policy signature verification via sigil. `PolicyVerifier` holds trusted public keys; detached `.sig` files alongside the policy; `tron_verify_and_load_policy` gates the existing load path.
- `src/signal.cyr` — SIGHUP policy hot-reload via non-blocking `signalfd`. Consumer-polled API (`sighup_init` / `sighup_drain_and_reload` / `sighup_close`). `tron_load_policy_file` + `tron_reload_policy` round out the file-backed policy path.
- `src/llm_scan.cyr` — optional LLM-assisted prompt injection detection targeting hoosh 2.0 HTTP `/infer`. Self-contained via stdlib `net.cyr`.
- `src/safety.cyr` — full AGNOS safety submodule: `SafetySeverity` / `SafetyEnforcement` / `ActionType` / `SafetyRuleType` enums; `SafetyRule` / `SafetyPolicy` / `SafetyAction` / `SafetyVerdict` / `SafetyViolation` structs; 6-pattern `PromptInjectionDetector` with Unicode zero-width + directional-override normalization; `SafetyCircuitBreaker` (Closed → Open → HalfOpen sliding window); `SafetyEngine` with priority-ordered policy evaluation and per-agent basis-point score; 5 default AGNOS policies in `safety_default_policies()`. See [ADR-006](docs/architecture/adr-006-safety-submodule.md).
- `audit.cyr::audit_export_json` / `audit_export_encrypted` / `audit_decrypt_export` — plain-JSON ring-buffer dump plus ChaCha20 + Ed25519 AEAD envelope. Wire format: `nonce (12) ‖ signature (64) ‖ ciphertext (N)`.
- `tests/t-ron.tcyr` (312 assertions) + `tests/t-ron-crypto.tcyr` (30) + `tests/t-ron-safety.tcyr` (48) = **390 tests, 0 failures**.
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

### Benchmarks (x86_64, Cyrius 4.8.4, 2026-04-14)

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

- Vendored patch to `lib/libro_entry.cyr::_cjh_hash_object` — upstream libro 1.0.3 passed a cstring to `json_get` (which wants a `Str`), causing SEGV on any non-empty details JSON. **Patch retired in 2.1.0** alongside the libro 2.6.2 bump (upstream fix included).

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
