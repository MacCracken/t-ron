# t-ron Roadmap

> **Current**: `2.1.0` (cyrius 5.10.34, libro 2.6.2, bote 2.7.1).
> Full pipeline 17 µs (was 52 µs at 2.0.0), 390 assertions across
> three test suites, ChaCha20+Ed25519 encrypted audit export,
> 6-pattern prompt-injection detector, 5 default AGNOS safety
> policies.
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
| **2.1.1** | Test-file refactor for the cyrius 5.10.x assert-nested-call parser quirk if it surfaces on a future test add (not triggered in current suite) | 🟡 Conditional |
| **2.1.2** | `dist/t-ron.cyr` single-file consumer bundle via `cyrius distlib` — daimon / bote middleware / phylax pull `[deps.t-ron] modules = ["dist/t-ron.cyr"]`. CI freshness gate + release asset. `DEPS-PATTERN.md` at root | 🟢 Open |
| **2.1.3** | CI capacity gate — `CYRIUS_STATS=1` + 95% fn_table / identifier-buffer threshold. Modeled on bote 2.6.4 | 🟢 Open |
| **2.1.4** | `CONTRIBUTING.md` Cyrius-era rewrite — current file is Rust-era (cargo / make / MSRV 1.89). Mirrors bote 2.7.1 rewrite | 🟢 Open |
| **Future** | **Full bote dist-bundle adoption** — blocked on either a cyrius compile-source-size cap raise (the 2 MB ceiling forces per-module bote pull today) or a bote opt-in profile that excludes the transport stack | 🔴 Blocked |

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
| `ct_eq` retired in cyrius 5.9.20 → renamed `ct_eq_bytes_lens`; libro 2.6.2 dist bundle still calls the old name | 🟡 Worked around in 2.1.0 via `src/_libro_compat.cyr` shim — drops when libro retags |
| bote + libro dist bundles together exceed cyrius's 2 MB compile-source cap (bote drags sandhi 11k lines via the transport stack) | 🔴 Blocks full dist-bundle adoption; tracked as "Future" in the 2.1.x arc table |
| `assert(streq(call(…), "lit") == 1, "msg")` parser quirk at cyrius 5.10.x — bote 2.7.1 hit it; t-ron has not (yet) | 🟡 2.1.1 will refactor if surfaced |
| `secret` is a storage-class keyword in 5.10.x | ✅ t-ron has no `secret` identifiers; only one string-literal use in tests/t-ron-crypto.tcyr (safe) |
