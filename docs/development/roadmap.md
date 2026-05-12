# t-ron Roadmap

> **Current**: `2.1.3` (cyrius 5.10.44, libro 2.6.3, bote 2.7.2
> via `dist/bote-core.cyr` opt-in profile). Full pipeline ~18 µs
> avg / 14 µs min (was 52 µs at 2.0.0), 390 assertions across
> three test suites, ChaCha20+Ed25519 encrypted audit export,
> 6-pattern prompt-injection detector, 5 default AGNOS safety
> policies, `dist/t-ron.cyr` single-file consumer bundle (4 493
> lines, 18 modules after the `_libro_compat` shim retirement),
> CI capacity gate (fn_table 80 % / identifiers 74 % / code_size
> 100.3 % — `code_size` crossed 100 % on the libro 2.6.3 +
> sigil 3.1.1 cascade; cyrius's emit buffer auto-expands so the
> build holds, but this dimension now actively wants the upstream
> cap raise to land).
>
> **Full release history**: [CHANGELOG.md](../../CHANGELOG.md).
> Rust archive preserved at git tag `0.90.0` under `rust-old/`.

2.0 shipped the Cyrius port. 2.x is feature-stable on the
SecurityGate ABI and the four introspection tools; patch releases
add capabilities and modernization, not shape changes at the
JSON-RPC boundary.

**2.1.x is the modernization arc.** All forward feature work
defers to 2.2.x+ — see the section after the arc table.

---

## Shipped

| Release | Headline |
|---|---|
| **0.22.3** | Core gate types, policy engine, rate limiter, payload scanner, pattern analyzer, risk scorer, audit logger, T.Ron query API, SecurityGate, MCP tools |
| **0.22.4** | libro audit-chain integration; verify_chain / chain_review / DenyCode |
| **0.26.3** | load_policy_file + reload_policy (SIGHUP); RateLimitPolicy from TOML; benchmark suite + bench-history CSV |
| **0.90.0** | Cross-agent correlation detector — coordinated-attack signal |
| **2.0.0** | **Cyrius port complete.** 16 modules in `src/*.cyr`; ChaCha20 + Ed25519 AEAD audit export; sigil-Ed25519 policy signing; SIGHUP signalfd hot-reload; LLM-assisted scan via hoosh HTTP; full AGNOS safety submodule (5 default policies, 6-pattern injection detector, circuit breaker); 390 assertions; security audit with 10 CVE-class fixes |
| **2.1.0** | **Modernization arc opens.** cyrius 5.10.34 / libro 2.6.2 / bote 2.7.1; bote 2.0 handler ABI fully observed (`fn h(args, claims)`); `cyrius.cyml` + `${file:VERSION}` + `cyrius.lock`; versioned-toolchain CI installer + `cyrius deps --verify` + manifest-completeness gate; vendored libro patch retired; full pipeline 17 µs (3× faster) |
| **2.1.1** | **`dist/t-ron.cyr` consumer bundle.** Single-file distribution via `cyrius distlib` (4 512 lines / 157 KB); `DEPS-PATTERN.md` contract doc; CI freshness gate; release asset alongside src tarball + linux binary + lockfile + SHA256SUMS |
| **2.1.2** | **CI capacity gate.** `CYRIUS_STATS=1` at build + parser step in `ci.yml`; fail at ≥95 % on `fn_table` or `identifiers`. Current util fn_table 75 % / identifiers 69 %. Surfaces `code_size` (97 %, the most-constrained dimension) as an informational warning — not gated to avoid an immediately-firing CI |
| **2.1.3** | **bote 2.7.2 opt-in core + cyrius 5.10.44 + libro 2.6.3.** Flips `[deps.bote]` to `dist/bote-core.cyr` (consumer-side unblock; t-ron is the trigger consumer per bote 2.7.2 CHANGELOG). Retires `src/_libro_compat.cyr` (libro 2.6.3 calls `ct_eq_bytes_lens` directly). Picks up sigil 3.1.1 / patra 1.9.4 / agnosys 1.2.6 transitively; adds `slice` / `keccak` / `random` to stdlib. CONTRIBUTING/CLAUDE rewrites ride along. `.cyrius-toolchain` retired — `cyrius.cyml` is the only pin source |

See [CHANGELOG.md](../../CHANGELOG.md) for the full detail per release.

---

## 2.1.x modernization arc

The 2.1.x line catches t-ron up to the first-party Cyrius floor.
Each patch is a small, well-bounded bite — nothing in this arc
ships new SecurityGate surface; behaviour is preserved at the wire
level.

| Patch | Bite | Status |
|---|---|---|
| **2.1.0** | Toolchain + dep floor + bote 2.0 handler ABI + manifest modernization + CI installer + `docs/doc-health.md` ledger + roadmap reslate | ✅ Shipped |
| **2.1.1** | `dist/t-ron.cyr` consumer bundle via `cyrius distlib` (19 modules, 4 512 lines) + `DEPS-PATTERN.md` contract + CI freshness gate + release-asset wiring | ✅ Shipped |
| **2.1.2** | CI capacity gate — `CYRIUS_STATS=1` + 95 % `fn_table` / `identifiers` threshold. Modeled on bote 2.6.4. `code_size` (97 %) surfaced as informational warning | ✅ Shipped |
| **2.1.3** | bote 2.7.2 opt-in `dist/bote-core.cyr` flip + cyrius 5.10.44 + libro 2.6.3 (sigil 3.1.1 / patra 1.9.4 / agnosys 1.2.6 transitive); `src/_libro_compat.cyr` retired; `slice` / `keccak` / `random` added to stdlib; `.cyrius-toolchain` removed; CONTRIBUTING / CLAUDE rewrites ride along | ✅ Shipped |
| **2.1.x** | **`code_size` headroom** — crossed 100 % at 2.1.3 on the libro 2.6.3 + sigil 3.1.1 cascade (was 97 % at 2.1.2). Build holds because cyrius's emit buffer auto-expands past the watermark, but the dimension now actively wants relief. Response paths: (1) **cyrius compile-source-size cap raise — preferred, the upstream proposal already exists** (see Future row note), (2) feature-gate `llm_scan` / `safety` / `signing` behind `#ifdef`, (3) opt-in compile-unit split (bote's `libro_tools.cyr` pattern). Patch number assigned when path chosen | 🟡 Watching — first preference shifts to (1) post-2.1.3 |
| **Watching** | **Test-file refactor for the cyrius 5.10.x assert-nested-call parser quirk** — bote 2.7.1 hit it; t-ron has not surfaced it today. Lands as a patch only if a future test add trips the pattern | 🟡 Conditional |
| **Future** | **Optional flip to `dist/bote.cyr` (full bundle, transport stack included).** The 2.1.3 bote-core flip closed the consumer-side blocker; the cyrius cap raise track ([cyrius compile-source-size cap 2 MB → 4 MB proposal](https://github.com/MacCracken/cyrius/blob/main/docs/development/proposals/2026-05-10-raise-compile-source-cap.md)) remains open and would let consumers that also want bote transports switch from `dist/bote-core.cyr` → `dist/bote.cyr`. t-ron itself never wires bote transports so bote-core stays the recommended pull regardless; this row only flips if a future t-ron feature reaches for a transport-side bote surface | 🟢 Optional |

> **Release discipline.** Docs-only work (`.md` / `docs/` /
> examples prose) does **not** earn a version bump in t-ron. It
> lands on `main` as a regular commit and accumulates under
> `## [Unreleased]` in CHANGELOG until the next release-worthy
> patch (code, CI, release-flow, dep-pin, manifest, tests)
> ships, at which point the unreleased notes ride along into
> that release's section.

Closes when the items above ship.

---

## Forward — post-2.1.x

### 2.2.x candidates

| Item | Notes |
|---|---|
| **Audit-tool authorization** | The 2.1.0 handler-ABI change plumbed `claims` through to t-ron's four introspection tools; 2.2.x adds the policy hook that gates `tron_audit` / `tron_policy` on caller identity (read from `claims`). Spec-aligned with bote's bearer / JWT / PKCE story |
| **agnoshi intents** | Natural-language security queries — was in the original Phase 1 backlog. Compose with agnoshi's intent parser; t-ron exposes the same surface its MCP tools already cover (`tron_status` / `tron_risk` / `tron_audit`) |

### Phase 2 — Advanced detection (post-2.1.x)

| Item | Notes |
|---|---|
| **ML-based anomaly detection** | Train on normal patterns, flag deviations. Sized at ~mid-2.x; needs a training-corpus story and a runtime cost budget |
| **Privilege escalation pattern detection** | Benign → sensitive tool sequences. Pattern analyzer already tracks per-agent histograms; this adds the directed-sequence detector |
| **Time-of-day anomaly detection** | Per-agent histogram + off-hours flag — pattern analyzer covers off-hours today, the extension is per-window scoring |
| **Cross-agent correlation** | ✅ Already shipped at 0.90.0 / carried into 2.0.0 |
| **Prompt injection detection via hoosh** | ✅ Shipped at 2.0.0 (`src/llm_scan.cyr`); future extensions stay incremental |

### Phase 2A — Capability-Source Policy (L3 of agent-injection defense)

> **Spec**: [`agnosticos/docs/development/planning/agent-injection-defense.md`](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/agent-injection-defense.md) — six-layer cross-cutting design. **t-ron owns L3 (MCP boundary).** Triggered by the 2026-05 incident (third-party AI agent drained $200K via Morse-code-in-tweet). **Phasing**: post-closed-beta for the schema work; post-public-beta for full enforcement.

L3's job: track the **provenance** of every tool call (which
content channel triggered it) and refuse high-privilege calls when
provenance is "external."

| Item | Notes |
|---|---|
| **Capability-source policy schema** | Declarative per-tool: which provenance channels can invoke this tool? `system-only` / `user-or-system` / `any-source` / `external-with-confirmation` |
| **Provenance chain ingestion** | daimon publishes the source channel; t-ron evaluates against the per-tool policy |
| **Default policy** | Every tool tagged `irreversible: true` requires `user-or-system` minimum (defense-in-depth with kavach's L4 gate) |
| **Audit emission** | Every tool-call decision logs `{tool, provenance, decision, reason}` to libro chain |
| **Per-tool annotation sweep** | daimon, ark, hoosh tools get explicit source-policy tags |
| **Backward-compatibility migration** | Shadow mode → audit-only mode → enforce mode, configurable per deployment |

**Companion repos**: L1 (input scanning) `phylax`; L2 (gateway
pre-flight) `hoosh`; L4 (capability gating + confirmation tokens)
`kavach`; L5 (audit chain) `libro` (already shipped); L6
(UntrustedInput<T> shared type) `agnostik`.

### Phase 3 — Hardening (post-2.1.x)

| Item | Notes |
|---|---|
| **Policy signing** | ✅ Already shipped at 2.0.0 (`PolicyVerifier` + `tron_verify_and_load_policy`) |
| **Encrypted audit log export** | ✅ Already shipped at 2.0.0 (`audit_export_encrypted` — ChaCha20+Ed25519 AEAD) |
| **Real-time alerts via daimon event bus** | Wire `audit_log` to publish to majra topics daimon subscribes to. Blocked on daimon's event-bus surface firming up |
| **Dashboard integration (aethersafha)** | Surface `query_*` calls over the aethersafha security panel. Blocked on aethersafha's MVP |
| **Edge fleet policy distribution** | Multi-node policy reload + signing-key rotation. Far-future; pairs with agnosticos's edge-fleet story |
| **Description-hash pinning in bote registry (audit F1 follow-up)** | Lives upstream in bote; t-ron integrates when bote exposes the primitive |

---

## Non-goals (won't ship in any 2.x)

- **Tool implementation** — t-ron is a gate, not a tool host.
- **LLM scoring of tool args** — t-ron calls hoosh for that.
- **Workflow orchestration** — that's szal.
- **Agent lifecycle** — that's daimon.
- **OAuth 2.1 AS flow** — bote is the resource server; t-ron sits
  behind it.

---

## Cyrius-language dependencies

Live language-level friction that has touched t-ron this arc lives
in the open issues column below. Resolved items are noted in
CHANGELOG entries.

| Issue | Status |
|---|---|
| `ct_eq` retired in cyrius 5.9.20 → renamed `ct_eq_bytes_lens`; libro 2.6.2 dist bundle still calls the old name | ✅ Resolved at 2.1.3 — libro 2.6.3 calls `ct_eq_bytes_lens` directly inside `dist/libro.cyr`; the `src/_libro_compat.cyr` shim retired with this release |
| bote + libro dist bundles together exceed cyrius's 2 MB compile-source cap (bote drags sandhi 11k lines via the transport stack) | ✅ Resolved at 2.1.3 on the consumer side — flipped `[deps.bote]` to `dist/bote-core.cyr` (opt-in transport-free profile, bote 2.7.2). cyrius compile-source-size cap raise proposal stays open as an orthogonal track |
| `assert(streq(call(…), "lit") == 1, "msg")` parser quirk at cyrius 5.10.x — bote 2.7.1 hit it; t-ron has not (yet) | 🟡 2.1.x will refactor if surfaced — not triggered through 2.1.3 |
| `secret` is a storage-class keyword in 5.10.x | ✅ t-ron has no `secret` identifiers; only one string-literal use in tests/t-ron-crypto.tcyr (safe) |
