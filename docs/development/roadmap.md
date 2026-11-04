# t-ron Roadmap

> **Current**: `2.2.3` (cyrius 6.7.18; libro 2.11.3, bote-core
> 3.8.1 via the transport-free `dist/bote-core.cyr` profile, sigil
> 3.13.15 pinned first-party via `[deps.sigil]` — full
> `dist/sigil.cyr`; majra 2.13.0 / patra 1.16.6 transitively). Full
> pipeline (`tron_check_allow`) **~17.3 µs**, `audit_log` **~10.5
> µs**, `policy_check` **~222 ns**, scanner **~0.4 µs**; **847
> assertions** across four test suites; a **684 KB** static binary;
> `dist/t-ron.cyr` single-file consumer bundle (6 849 lines, 19
> modules); CI resolves `cyrius deps --locked` and runs two failing
> security gates.
>
> **2.2.3 was the P(-1) sweep**: four independent reviews of every
> module, 74 items, every critical and high one fixed
> ([audit report](../audit/2026-11-03.md)). **Next: 2.2.4**, the audit's
> patch-sized follow-ups (below), then feature work from **2.3.x**.
>
> **Capacity is comfortable on every dimension**: `fn_table` **5 902
> / 131 072 (4 %)**, `identifiers` **167 196 / 8 388 608 (2 %)**,
> `code_size` **158 960 / 67 108 864 (0.2 %)**.
>
> **Full release history**: [CHANGELOG.md](../../CHANGELOG.md).
> Rust archive preserved at git tag `0.90.0` under `rust-old/`.

## How versions are used

- **A patch** (2.2.x) moves the toolchain or a dependency, fixes a
  defect, hardens, or changes CI and release flow. 2.2.3 was a
  scheduled one: the P(-1) sweep.
- **A minor** (2.3, 2.4, …) carries one feature line. Anything that
  changes what an MCP client sees from t-ron's own tools lands in a
  minor.
- **2.2.0** opened on the cyrius 6.7.x move, which carried bote
  3.4.x's wire-behaviour changes through SecurityGate.
- The SecurityGate ABI, `dispatcher_dispatch`'s signature and the
  bote 2.0 handler ABI have held since 2.0.0.

> **Release discipline.** Docs-only work (`.md` / `docs/` /
> examples prose) does **not** earn a version bump in t-ron. It
> lands on `main` as a regular commit and accumulates under
> `## [Unreleased]` in CHANGELOG until the next release-worthy
> patch (code, CI, release-flow, dep-pin, manifest, tests)
> ships, at which point the unreleased notes ride along into
> that release's section.

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
| **2.1.4** | **Pattern-analyzer refinements.** New detector #3 (directed sequence: ordered recon→mutation in last 10 calls; catches what the count-based escalation detector misses when sensitive calls are spaced below 3-of-5); new public `pattern_off_hours_score_bp(pa, agent_id, hour)` returning 0..1000 instead of binary flag (composes with `score.cyr`). Existing detectors unchanged at the wire level; +11 test assertions (390 → 401) |
| **2.1.5** | **cyrius major jump 5.10.44 → 6.1.24 + libro 2.7.2 + bote 2.7.3.** The toolchain crossing the arc had earmarked, absorbed as a patch (JSON-RPC + dispatcher unchanged). Transitive: sigil 3.7.8 / patra 1.11.0 / agnosys 1.4.1 / majra 2.4.5 / sakshi 2.2.10. Adds `atomic` / `thread` / `thread_local` to stdlib + includes (before sigil) — sigil 3.7.8's hash path self-installs a TLS scratch bank (`thread_local_get`), so libro `chain_append`'s SHA-256 SIGILL-trapped without them. Mirrors bote 2.7.3. 401 assertions hold; benches flat; `code_size` 100.6 % → 120 % on the larger 6.x stdlib bundle |
| **2.1.6** | **cyrius 6.2.11 (onto the 6.2.x line) + libro 2.7.4 + bote 2.7.6 + the `bayan` stdlib carve.** Toolchain + dep refresh; JSON-RPC + dispatcher unchanged. Transitive: sigil 3.7.14 / patra 1.11.2 / agnosys 1.4.3 / majra 2.4.7. **`bayan` carve** — cyrius 6.1.25 folded standalone `json` / `base64` / `bigint` into one bundle; migrated `[deps].stdlib` + all `src`/test includes (no call-site changes; t-ron has no direct `json_*`/`base64_*`/`bigint_*` calls). Repaired the stale `tests/*.tcyr` + `.bcyr` harnesses that still referenced the retired `src/_libro_compat.cyr` + per-module `lib/bote_*.cyr` (latent — they did not compile post-2.1.3); `registry_new()` → `tool_registry_new()` (bote 2.7.4 rename). Fixed the bench's sigil-before-`ct`/no-`thread_local` ordering — a sigil 3.7.14 SIGILL landmine that only surfaces when *run*. Lock 48 → 47 hashes. 401 assertions hold; benches flat. Mirrors bote 2.7.6 |
| **2.1.7** | **cyrius 6.3.15 base-stack migration + 6.3.x dep-sidecar reconciliation.** Toolchain 6.2.11 → 6.3.15; libro 2.7.4 → 2.7.9, bote-core 2.7.6 → 2.7.7. Added `sakshi` / `fs` / `process` to `[deps].stdlib` (libro's dist `.deps` sidecar on 6.3.x declares them as consumer-scope leaves — the file-backed chain + subprocess-audit paths; on 6.2.x they were folded inside libro's bundle) and `sync` (patra 1.12.7's transitive `lib/sync.cyr` requirement); `main.cyr` includes `lib/fs.cyr` + `lib/process.cyr` before sigil/libro (single-pass). Documented the CYML-comment double-quote gotcha. 401 assertions hold |
| **2.1.8** | **cyrius 6.4.66 + libro 2.8.2 / bote 3.1.4 / sigil 3.12.1 refresh + `[deps.sigil]` first-party pin.** Toolchain 6.3.15 → 6.4.66 (the 6.4.65 `thread_local_alloc` slot allocator sigil 3.12.x / patra 1.12.x call — stale `lib/` failed to link without the re-vendor). libro 2.7.9 → 2.8.2, bote-core 2.7.7 → **3.1.4** (MAJOR, additive on the 2.0 handler ABI; core profile grew 9 → 11 modules). New **`[deps.sigil]` pin — full `dist/sigil.cyr` @ 3.12.1**: libro 2.8.0 thinned its *transitive* sigil to the mldsa/sha folds, whose basenames pollute `dist/t-ron.deps` as bogus stdlib leaves (breaking downstream `cyrius deps`); pinning the full bundle directly keeps `sigil` a recognized named dep so the sidecar stays byte-identical to 2.1.7. Mirrors daimon 1.4.3 / bote 3.1.4 (full bundle; bloat accepted). **Bare `ERR_*`**: t-ron was already 0 bare `ERR_*` (all `TRON_ERR_*`); banks the reciprocal `LIBRO_ERR_*` / `BOTE_ERR_*` dep renames that retire the `ERR_IO`/`ERR_JSON` duplicate-symbol hazard at source. `bench-history.sh` rewritten float-aware for 6.4.x decimal-µs output. 401 assertions hold; benches flat-to-faster (policy_check 655 ns, tron_check_allow 13.0 µs) |
| **2.1.9** | **cyrius 6.5.35 + libro 2.8.12 / bote-core 3.3.7 / sigil 3.12.9 — and the `bote-core` sidecar leak.** Toolchain 6.4.66 → 6.5.35; libro 2.8.2 → 2.8.12, bote-core 3.1.4 → 3.3.7, sigil 3.12.1 → 3.12.9; transitive patra 1.13.10 / majra 2.7.0 / sakshi 2.4.11. **Fixed a live downstream break**: `dist/t-ron.deps` emitted `bote-core` as a *stdlib* leaf because dep name `bote` ≠ module basename `bote-core`, so every consumer wiring t-ron per `DEPS-PATTERN.md` failed `cyrius deps` — renamed the dep to `[deps.bote-core]`; verified end-to-end with a scratch consumer that now resolves, compiles against `dist/t-ron.cyr` and returns a correct `deny`. Same defect 2.1.8 fixed for `sigil` and missed for `bote`. **`code_size` watching row closes on its preferred path** — cyrius 6.5.35 raised the compile-source cap to 64 MB, so t-ron drops ~118 % → **3 %**; `fn_table` 17 %, `identifiers` 35 %, `var_table` 32 %. Lock 54 → 72 entries (TLS/sandhi cluster via `net`, all DCE'd; `bote-core` still carries **zero** `sandhi_` refs). ⚠️ **Consumer advisory**: libro 2.8.11 changes every entry hash — re-export and re-anchor live chains before upgrading. 401 assertions hold; `policy_check` 6.4× faster (1.693 µs → 265 ns) vs a same-session baseline |
| **2.1.10** | **cyrius 6.6.2 value-form migration + libro 2.10.0 / sigil 3.12.16.** Toolchain 6.5.35 → 6.6.2 (`Result`/`Option`/`Either` are now a two-register `(tag, payload)` value; `payload()` deleted). The sigil bump is load-bearing — vendored `lib/sigil.cyr` at 3.12.9 carried **12 `payload()` calls** while t-ron's own `src/` had none, so the repo looked clean and the bundle it compiles against did not. **Four defects the flip exposed, two of them silent**: (1) `_llm_http_post`'s `if (sock_connect(...) < 0)` and `if (sock_send(...) < 0)` guards could **never fire** — `Err`'s tag is `1` — so refused connections and failed writes fell through and t-ron reported a scan against a host it never reached; (2) `circuit_breaker_new` collided with majra's at a **different arity** over a different 48-byte layout, now a hard error at 6.6.2 → family renamed `safety_circuit_breaker_*`; (3) `chacha20_xor` collided with sigil's at the **same** arity, so sigil's `chacha20_aead_encrypt`/`_decrypt` silently called t-ron's process-global, never-wiped keystream instead of sigil's per-thread lane → renamed `cc20_xor`; (4) exposed by (3) — `tests/t-ron.tcyr` and `tests/t-ron.bcyr` include `src/audit.cyr` but not `src/crypto_chacha20.cyr`, so **the 323-assertion suite and the bench exercised sigil's cipher while the binary shipped t-ron's**. ⛔ Defects (2), (3) and (4) all descend from the 2.1.5 row's claim that these were "two benign cross-module `duplicate fn` warnings" — see the correction on that row. 401 assertions hold; benches flat; zero undefined symbols and zero duplicate definitions across all five harnesses |
| **2.1.11** | **cyrius 6.6.6 + libro 2.10.3 / bote-core 3.3.13 / sigil 3.12.18 — `cyrius.cyml` back to a manifest, `[deps.majra]` retired.** Toolchain 6.6.2 → 6.6.6; libro 2.10.0 → 2.10.3, bote-core 3.3.7 → 3.3.13, sigil 3.12.16 → 3.12.18; majra 2.9.1 / patra 1.14.3 transitive. No t-ron source change. The explicit majra pin retires now that bote 3.3.13 pins majra 2.9.1 itself — lock hashes, bundle and sidecar byte-identical without it — and takes with it the two `refusing to overwrite stdlib leaf` warnings 2.1.10 printed on every command (majra's sidecar claimed `sigil` / `patra` ahead of t-ron's own sigil pin). `cyrius.cyml` 228 → 128 lines: release narratives out, present-tense rules in; the stale 2.1.8 rationale for `[deps.sigil]` replaced by the current one (it stops libro's thin sigil sub-bundles compiling beside the full bundle — 233 duplicate definitions without it). Sidecar gains `sys` (29 leaves). Audit path ~20 % faster (`audit_log` 13.4 → 10.2 µs), ~2.7 µs of it attributed to libro 2.10.3 by an A/B. Integration-guide sample fixed (it did not compile). Verified sibling-free (byte-identical binary) and with a clean-room consumer (6 deps resolved, `deny`). 401 assertions hold |
| **2.1.12** | **cyrius 6.6.20 + libro 2.10.8 / bote-core 3.3.17 / sigil 3.13.10 — no `path` lines, sigil resolves first, three-leaf sidecar.** Toolchain 6.6.6 → 6.6.20; every dep moved to the release that pins 6.6.20 (sigil 3.13.10 and patra 1.15.2 are the 6.6.20 folds); majra 2.9.3 / patra 1.15.2 transitive. No t-ron source change. The three committed `path` lines are gone — the sibling checkouts had moved to libro 2.11.3 / bote 3.8.1 / sigil 3.13.15, so a local resolve would have compiled those, not the tags (libro 2.10.5 and bote 3.3.16 made the same change). `[deps.sigil]` moved first: bote-core 3.3.17's sidecar names `sigil`, and listed after it t-ron's pin was refused (`refusing to overwrite stdlib leaf 'sigil'`) — same bytes, wrong owner, the 2.1.10 majra shape again. Its comment now gives the current reason (`verify_data()`; the 2.1.11 "233 duplicates" no longer reproduces at 6.6.20). The "no comments inside the array" rule retires (probed). Sidecar 29 → 3 leaves (6.6.18 `distlib` writes only compile-verified leaves) — consumers calling stdlib directly may need their own `[deps] stdlib`. Lock 76 → 60 entries, with five commit pins matching the remote tags. Binary 2.66 → 2.24 MB from the compiler alone. `policy_check` +13.7 % (289 → 329 ns) — ~9 ns the 6.6.20 `hashmap.cyr` (file-swap A/B), ~30 ns code placement; the other four benches flat. Verified sibling-free (byte-identical) and with a clean-room consumer (6 deps resolved, `deny`). 401 assertions hold |
| **2.2.0** | **cyrius 6.7.9 + libro 2.11.0 / bote-core 3.4.10 / sigil 3.13.11 — the 2.2.x line opens.** bote 3.4.8 refused t-ron's four MCP tool definitions (`Str` values where bote stores C strings — on older bote they were listed as garbage); fixed, with 9 mutation-checked assertions. CI and the release resolve `cyrius deps --locked` (the cyrius 6.7.6 roadmap note). Clients of a SecurityGate-wrapped dispatcher see bote 3.4.x's spec-conformance changes. Consumers need cyrius ≥ 6.7.2. 410 assertions |
| **2.2.1** | **cyrius 6.7.18 + libro 2.11.3 / bote-core 3.8.0 / sigil 3.13.15 — Security: the tool handlers overran their buffers.** `tron_risk` copied an unbounded `agent_id` into `alloc(256)` and `tron_audit` sized its reply at `events × 160 + 32`; both now size each reply exactly and escape every value at both levels (the `text` is a JSON document inside a JSON string). Output for ordinary input byte-identical. Binary 2.28 MB → 676 KB (6.7.18 removes dead code 6.7.9 only NOPed). 426 assertions |
| **2.2.2** | **bote-core 3.8.1 + the quick-item bundle.** `policy_check` does one hash lookup, not two (**−27 %**, 290 → 211 ns, isolated by an A/B). The crypto test's raw `syscall(39/62)` replaced with `sys_getpid` / `sys_kill` — the last warning in any build. CI's dist gate also diffs `dist/t-ron.deps` and no longer swallows a `distlib` failure (mutation-checked). `src/main.cyr` comments rewritten as present-tense rules. The assert-quirk watch row closed. The roadmap reorganized into 2.2.3 + feature lines. 426 assertions |
| **2.2.3** | **The P(-1) sweep.** Four independent reviews of all 19 modules; 74 items, 3 critical and 16 high, all fixed: the gate checked tool names undecoded while bote ran them decoded (an escaped name passed a deny entry); SIGHUP reload skipped the signature check (now signed mode); the scanner never decoded JSON escapes; `DA_FLAG` skipped every later check; the TOML loader read comments as content and wiped the policy on a bad file (now strict and atomic); two more audit-log heap overruns; LLM scan read every real reply as clean and leaked its socket; the safety submodule failed open, leaked and was bypassable. New `src/json_text.cyr`, `tests/t-ron-detect.tcyr`, and two failing CI security gates. Scanner 9× faster. 847 assertions ([report](../audit/2026-11-03.md)) |

See [CHANGELOG.md](../../CHANGELOG.md) for the full detail per release.

**The 2.1.x modernization arc (2.1.0–2.1.12) is closed.** It took
t-ron from cyrius 5.10.34 to 6.6.20, across the 6.x major crossing
(2.1.5), as thirteen patches on an unchanged wire shape. Its one open
feature item, real-time alerts via daimon, moved to 2.4.x below.

---

## 2.2.4 — audit follow-ups (proposed, next)

The patch-sized items the 2.2.3 audit deferred. IDs refer to the
[report](../audit/2026-11-03.md).

| Item | IDs |
|---|---|
| Bound per-agent state: the pattern analyzer, the correlation detector and their intern tables; evict idle safety rate buckets | D14, S16 |
| Unicode confusable mapping in the safety injection detector (a Cyrillic `о` still evades it) | S11 |
| `require_utf8` output validation, which the Rust original had | S15 |
| Scan identifiers only up to the 256-byte cap; check the remaining unchecked allocations in `src/` | P12, C14 |
| The per-call allocation t-ron never frees (~1 KB per `tron_check`, most of it the libro entry): an arena or freelist, or a documented restart budget | P10 |

**Needing a minor** (each changes behaviour or a format; placement is
the maintainer's call):

| Item | IDs |
|---|---|
| **Pattern-detector redesign.** 2.0.0's F10, reconfirmed: the detectors see only the last 5 / 10 / 20 calls, so spacing sensitive calls with benign ones evades them, and calls denied earlier in the pipeline are never recorded. A time-decayed per-agent score, a recon→mutation time-to-live, and recording denied calls | D11 |
| **Export envelope v2.** Bind the symmetric key, domain-separate the signature, bind against replay ([ADR-005](../architecture/adr-005-chacha20-ed25519-aead.md)) | C8, C9 |

---

## 2.3.x and later — open items, one line per minor

Blockers were re-checked against the sibling repos on 2026-11-03.

### 2.3.x — MCP surface and authorization

| Item | Status |
|---|---|
| **Tool titles and output schemas** | `tron_status`, `tron_risk` and `tron_audit` return a JSON document inside a text block. bote 3.8.0's `outputSchema` / `structuredContent` and 3.8.1's `tool_def_with_title` let them declare that shape, so a client can read it without parsing text. Changes what `tools/list` and each result carry. **Unblocked** |
| **Audit-tool authorization** | Gate `tron_audit` / `tron_policy` on caller identity read from `claims`, which the 2.1.0 handler-ABI change already plumbs through. The bote side is ready: 3.6.x verifies JWTs (RS256 / ES256 from a JWK Set, audience, `403 insufficient_scope`). **Blocked** on the agnosticos claims schema; agnosticos's own planning (`native-display-protocol.md`) still says "real auth waits on the claims schema" |
| **Description-hash pinning** (audit F1 follow-up) | Integrate when bote has the primitive. **Blocked upstream**: bote 3.8.1's `src/` has no description-hash symbol |

### 2.4.x — Ecosystem integration

| Item | Status |
|---|---|
| **Real-time alerts via the daimon event bus** | Publish `audit_log` events on agreed majra topics. daimon 2.5.2 exposes `msg_bus_publish` (`daimon/src/ipc.cyr:268`). **Conditional**: daimon defines no security or t-ron topic yet |
| **agnoshi intents** | Natural-language security queries over the surface t-ron's MCP tools already cover. agnoshi now exists (2.2.0), so the old "availability" blocker is gone. **Next step**: read its intent API and scope the binding |
| **Dashboard integration (aethersafha)** | Surface the `query_*` calls on aethersafha's security panel. aethersafha now exists (0.17.7), so the "not present locally" blocker is gone. **Next step**: its panel API |

### 2.5.x — Capability-source policy (L3 of agent-injection defense)

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

### 2.6.x and later

| Item | Status |
|---|---|
| **ML-based anomaly detection** | Train on normal patterns, flag deviations. Needs a training-corpus story and a runtime cost budget |
| **Edge fleet policy distribution** | Multi-node policy reload and signing-key rotation. Pairs with agnosticos's edge-fleet story |

### Shipped, from the old Phase 2 / Phase 3 lists

Privilege-escalation detection (2.0.0; directed-sequence refinement
2.1.4), time-of-day anomaly detection (2.0.0; basis-point scoring
2.1.4), cross-agent correlation (0.90.0), prompt-injection detection
via hoosh (2.0.0), policy signing (2.0.0), encrypted audit export
(2.0.0).

### Not planned

- **Flipping to `dist/bote.cyr`** (bote's full bundle). t-ron wires
  no transport, and `dist/bote-core.cyr` carries zero `sandhi_`
  references, so the full bundle would add the transport stack for no
  reachable caller. Revisit only if a feature needs a transport-side
  bote surface.

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

Language-level friction that has touched t-ron, and how each case
was closed. Resolved items are noted in
CHANGELOG entries.

| Issue | Status |
|---|---|
| `ct_eq` retired in cyrius 5.9.20 → renamed `ct_eq_bytes_lens`; libro 2.6.2 dist bundle still calls the old name | ✅ Resolved at 2.1.3 — libro 2.6.3 calls `ct_eq_bytes_lens` directly inside `dist/libro.cyr`; the `src/_libro_compat.cyr` shim retired with this release |
| bote + libro dist bundles together exceed cyrius's 2 MB compile-source cap (bote drags sandhi 11k lines via the transport stack) | ✅ Fully resolved. Consumer-side at 2.1.3 (flipped `[deps.bote]` to `dist/bote-core.cyr`, opt-in transport-free profile, bote 2.7.2); **upstream at 2.1.9 — cyrius 6.5.35 raised the cap to 64 MB**, retiring the orthogonal track this row was holding open |
| `assert(streq(call(…), "lit") == 1, "msg")` parser quirk at cyrius 5.10.x — bote 2.7.1 hit it; t-ron never did | ✅ Closed at 2.2.2 — a probe of exactly that shape compiles and evaluates correctly at 6.7.18 (2/2) |
| `secret` is a storage-class keyword in 5.10.x | ✅ t-ron has no `secret` identifiers; only one string-literal use in tests/t-ron-crypto.tcyr (safe) |
| `cyrius distlib` emits a bundled dep into the `.deps` sidecar as a **stdlib leaf** whenever the module basename does not match the dep name (`[deps.bote]` + `dist/bote-core.cyr` → basename `bote-core` ≠ dep `bote`) | ✅ Resolved at 2.1.9 — renamed the dep to `[deps.bote-core]`. **This bit twice**: 2.1.8 diagnosed the identical mechanism for `sigil` and fixed *that* instance, while the `bote-core` line sat in the same file undetected, because the 2.1.8 check was "sidecar byte-identical to previous release" rather than "every sidecar line is a real stdlib module". **The durable rule: validate `dist/t-ron.deps` against the toolchain stdlib listing, not against the last release** — a regression check cannot catch a defect that predates the baseline |
| `warning: refusing to overwrite stdlib leaf '<name>'` — a dep's sidecar names a package as a stdlib leaf, and it resolves *before* t-ron's own `[deps.<name>]` pin, so the snapshot copy wins and t-ron's pin is skipped | ✅ Resolved twice by ordering, not by luck: majra's sidecar vs `[deps.sigil]` (removed with the majra pin at 2.1.11), then bote-core 3.3.17's sidecar vs `[deps.sigil]` (section moved first at 2.1.12). Both times the bytes matched, so nothing broke — but the warning means the declared pin is not the one compiled. Treat it as a defect, and fix it by resolution order |
| cyrius 6.7.6 "git first": a `path` beside `git` / `tag` becomes a local-mode override, and `cyrius deps --locked` replaces hand-rolled lock guards (a note cyrius recorded in this roadmap for the next pin move) | ✅ Done. The `path` lines were retired at 2.1.12, and CI and the release resolve `--locked` with `CYRIUS_LOCKED=1` since 2.2.0. The old `cyrius deps` + `--verify` pair passed a lock missing an entry; `--locked` refuses it |

