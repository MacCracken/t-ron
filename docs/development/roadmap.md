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

**2.1.x is the modernization arc — and it stays open past 2.1.3.**
The 2.1.3 release cleared both upstream blockers from the 2.1.x
pause (libro 2.6.3 retag + bote 2.7.2 opt-in core), so the arc
can now absorb forward items that don't require a toolchain
jump. The natural close of 2.1.x is the cyrius **5.11.x** bump
— first-party crates have not crossed yet, so a 5.11.x landing
is the moment to cut 2.2.x. **Items code-doable on the current
5.10.44 floor can land in 2.1.x;** items needing 5.11.x or
upstream-schema coordination defer to 2.2.x+ (see the Forward
section after the arc table).

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

The 2.1.x line catches t-ron up to the first-party Cyrius floor
and stays open for forward items doable on the current 5.10.44
toolchain before the 5.11.x bump triggers a 2.2.x minor cut.
The JSON-RPC boundary and SecurityGate dispatcher signature stay
stable through this arc — any added emissions ride the same
wire shape rather than changing it.

| Patch | Bite | Status |
|---|---|---|
| **2.1.0** | Toolchain + dep floor + bote 2.0 handler ABI + manifest modernization + CI installer + `docs/doc-health.md` ledger + roadmap reslate | ✅ Shipped |
| **2.1.1** | `dist/t-ron.cyr` consumer bundle via `cyrius distlib` (19 modules, 4 512 lines) + `DEPS-PATTERN.md` contract + CI freshness gate + release-asset wiring | ✅ Shipped |
| **2.1.2** | CI capacity gate — `CYRIUS_STATS=1` + 95 % `fn_table` / `identifiers` threshold. Modeled on bote 2.6.4. `code_size` (97 %) surfaced as informational warning | ✅ Shipped |
| **2.1.3** | bote 2.7.2 opt-in `dist/bote-core.cyr` flip + cyrius 5.10.44 + libro 2.6.3 (sigil 3.1.1 / patra 1.9.4 / agnosys 1.2.6 transitive); `src/_libro_compat.cyr` retired; `slice` / `keccak` / `random` added to stdlib; `.cyrius-toolchain` removed; CONTRIBUTING / CLAUDE rewrites ride along | ✅ Shipped |
| **2.1.x** | **Real-time alerts via daimon event bus** — daimon exposes `msg_bus_publish` today (`daimon/src/main.cyr:2635`). Wire `audit_log` to publish on the agreed majra topics. Conditional on confirming daimon's topic schema is settled before the patch. This is the one clear "doable on 5.10.44, no upstream blocker, real user-visible delta" candidate | 🟡 Conditional |
| **2.1.x** | **Pattern-analyzer refinements** — both basic detectors already ship at 2.0.0 (`_pat_check_escalation` count-of-sensitive-in-window with mixed-benign requirement; `_pat_check_time` binary off-hours flag). Possible refinements: (1) directed-sequence detector — replace count-based privilege-escalation with an ordered state machine (A → B → C); (2) continuous basis-point off-hours scoring composing with `score.cyr` instead of a binary flag. Both are optimization-without-a-driver until a real attack pattern motivates them — left as an open option, not a planned patch | 🟢 Optional |
| **2.1.x** | **`code_size` headroom** — crossed 100 % at 2.1.3 on the libro 2.6.3 + sigil 3.1.1 cascade (was 97 % at 2.1.2). Build holds because cyrius's emit buffer auto-expands past the watermark, but the dimension now actively wants relief. Response paths: (1) **cyrius compile-source-size cap raise — preferred, the upstream proposal already exists** (see Future row note), (2) feature-gate `llm_scan` / `safety` / `signing` behind `#ifdef`, (3) opt-in compile-unit split (bote's `libro_tools.cyr` pattern). Patch number assigned when path chosen | 🟡 Watching — first preference shifts to (1) post-2.1.3 |
| **Watching** | **Test-file refactor for the cyrius 5.10.x assert-nested-call parser quirk** — bote 2.7.1 hit it; t-ron has not surfaced it today. Lands as a patch only if a future test add trips the pattern | 🟡 Conditional |
| **Arc close** | **cyrius 5.11.x toolchain bump** — when first-party crates start crossing onto the 5.11.x line, that's the moment to cut **2.2.x** and close this arc. Don't ship a 5.11.x bump inside 2.1.x — minor-cut discipline. cyrius is locally on 5.11.18 today; no first-party consumer has crossed yet | 🔮 Trigger for 2.2.x |
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

> **Cut line:** items in this section are 2.2.x+ because they
> need either the **cyrius 5.11.x line** (toolchain jump =
> minor-cut moment) or upstream schema work in another crate
> that has not firmed up yet. Items code-doable on 5.10.44 with
> no upstream coordination have been pulled forward into the
> 2.1.x arc table above.

### 2.2.x candidates

| Item | Notes |
|---|---|
| **Audit-tool authorization** | The 2.1.0 handler-ABI change plumbed `claims` through to t-ron's four introspection tools; 2.2.x adds the policy hook that gates `tron_audit` / `tron_policy` on caller identity (read from `claims`). **Blocker:** agnosticos claims schema firm-up — no firm-up signal in `agnosticos/docs/development/summer-2026-arc.md` as of 2026-05-11. Spec-aligned with bote's bearer / JWT / PKCE story |
| **agnoshi intents** | Natural-language security queries — was in the original Phase 1 backlog. Compose with agnoshi's intent parser; t-ron exposes the same surface its MCP tools already cover (`tron_status` / `tron_risk` / `tron_audit`). **Blocker:** agnoshi availability |
| **cyrius 5.11.x toolchain bump** | The natural trigger for 2.2.x. First-party crates have not crossed yet (cyrius 5.11.18 locally; bote 2.7.2 / libro 2.6.3 still on 5.10.44). When one does — or when a 2.2.x feature needs a 5.11.x surface — that's the minor cut |

### Phase 2 — Advanced detection (post-2.1.x)

> **Correction (2026-05-11):** an earlier revision of this roadmap
> listed "privilege escalation pattern detection" and "time-of-day
> anomaly detection" as 2.2.x candidates and then pulled them
> forward as 2.1.x patches. Reading `src/pattern.cyr` showed both
> detectors already ship at 2.0.0 (carried forward from the Rust
> 0.90.0 era — `_pat_check_escalation` and `_pat_check_time`).
> The refinement opportunities that remain are tracked in the arc
> table's "Pattern-analyzer refinements" row, not here.

| Item | Notes |
|---|---|
| **ML-based anomaly detection** | Train on normal patterns, flag deviations. Sized at ~mid-2.x; needs a training-corpus story and a runtime cost budget. Stays 2.2.x+ on corpus-readiness, not toolchain |
| **Privilege escalation pattern detection** | ✅ Already shipped at 2.0.0 (`_pat_check_escalation`: 3+ of last 5 sensitive AND ≥ 1 benign mixed). A directed-sequence refinement is the open option — see "Pattern-analyzer refinements" in the arc table |
| **Time-of-day anomaly detection** | ✅ Already shipped at 2.0.0 (`_pat_check_time`: binary flag below 2 % of total once ≥ 50 calls observed, and agent not active in all 24 hours). Continuous basis-point scoring is the open option — see "Pattern-analyzer refinements" in the arc table |
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

### Phase 3 — Hardening

> **Pullable to 2.1.x:** "real-time alerts via daimon event bus"
> is now conditional rather than blocked — daimon exposes
> `msg_bus_publish` (`daimon/src/main.cyr:2635`). See the
> conditional row in the arc table; lands in 2.1.x if the
> daimon-side topic schema is firm enough to commit to.

| Item | Notes |
|---|---|
| **Policy signing** | ✅ Already shipped at 2.0.0 (`PolicyVerifier` + `tron_verify_and_load_policy`) |
| **Encrypted audit log export** | ✅ Already shipped at 2.0.0 (`audit_export_encrypted` — ChaCha20+Ed25519 AEAD) |
| **Real-time alerts via daimon event bus** | 🟡 **Conditional 2.1.x** — daimon's `msg_bus_publish` exists; pending topic-schema confirmation |
| **Dashboard integration (aethersafha)** | Surface `query_*` calls over the aethersafha security panel. Blocked on aethersafha's MVP (repo not present locally as of 2026-05-11) |
| **Edge fleet policy distribution** | Multi-node policy reload + signing-key rotation. Far-future; pairs with agnosticos's edge-fleet story |
| **Description-hash pinning in bote registry (audit F1 follow-up)** | Lives upstream in bote; no `desc_hash` / `description_hash` symbol in `bote/src/registry.cyr` as of 2026-05-11. t-ron integrates when the primitive lands |

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
