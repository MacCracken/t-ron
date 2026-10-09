# t-ron Roadmap

> **Current**: `2.1.11` (cyrius 6.6.6, libro 2.10.3, bote-core
> 3.3.13 via the transport-free `dist/bote-core.cyr` profile; sigil
> 3.12.18 pinned first-party via `[deps.sigil]` — full
> `dist/sigil.cyr`; majra 2.9.1 / patra 1.14.3 transitively). Full
> pipeline (`tron_check_allow`) **~16.4 µs**, `audit_log` **~10.2
> µs**, `policy_check` **~288 ns**; **401 assertions** across three
> test suites, ChaCha20+Ed25519 encrypted audit export, 6-pattern
> prompt-injection detector, 5 default AGNOS safety policies,
> `dist/t-ron.cyr` single-file consumer bundle (4 624 lines, 18
> modules), CI capacity gate.
>
> **2.1.11** took cyrius 6.6.6 and the latest deps, retired the
> `[deps.majra]` override now that bote 3.3.13 pins majra 2.9.1
> itself, and rewrote `cyrius.cyml` as a manifest — release history
> lives in the CHANGELOG, not in manifest comments. The audit path
> got ~20 % faster, most of it libro 2.10.3.
>
> **Capacity is comfortable on every dimension**: `fn_table` **5 955
> / 131 072 (4 %)**, `identifiers` **191 765 / 8 388 608 (2 %)**,
> `code_size` **2 157 592 / 67 108 864 (3 %)**.
>
> **Full release history**: [CHANGELOG.md](../../CHANGELOG.md).
> Rust archive preserved at git tag `0.90.0` under `rust-old/`.

2.0 shipped the Cyrius port. 2.x is feature-stable on the
SecurityGate ABI and the four introspection tools; patch releases
add capabilities and modernization, not shape changes at the
JSON-RPC boundary.

**2.1.x is the modernization arc — and it absorbed the cyrius
major jump rather than closing on it.** The arc had earmarked
the cyrius toolchain crossing as its 2.2.x trigger, but when the
ecosystem moved (bote 2.7.3 made the 5.10.44 → 6.1.24 jump),
t-ron took it as the final 2.1.x patch (**2.1.5**) — the
JSON-RPC boundary and SecurityGate dispatcher signature never
moved, so SemVer-wise it stays a patch. The arc now closes on
its remaining feature item (real-time alerts via daimon) rather
than on a toolchain version. Items that change the wire shape or
need upstream-schema coordination still defer to 2.2.x+ (see the
Forward section after the arc table).

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

See [CHANGELOG.md](../../CHANGELOG.md) for the full detail per release.

---

## 2.1.x modernization arc

The 2.1.x line catches t-ron up to the first-party Cyrius floor.
It tracked the toolchain all the way across the **6.x major
crossing** (2.1.5: cyrius 6.1.24) and stays open for its
remaining feature item. The JSON-RPC boundary and SecurityGate
dispatcher signature stay stable through this arc — even the
major toolchain jump rode the same wire shape rather than
changing it.

| Patch | Bite | Status |
|---|---|---|
| **2.1.0** | Toolchain + dep floor + bote 2.0 handler ABI + manifest modernization + CI installer + `docs/doc-health.md` ledger + roadmap reslate | ✅ Shipped |
| **2.1.1** | `dist/t-ron.cyr` consumer bundle via `cyrius distlib` (19 modules, 4 512 lines) + `DEPS-PATTERN.md` contract + CI freshness gate + release-asset wiring | ✅ Shipped |
| **2.1.2** | CI capacity gate — `CYRIUS_STATS=1` + 95 % `fn_table` / `identifiers` threshold. Modeled on bote 2.6.4. `code_size` (97 %) surfaced as informational warning | ✅ Shipped |
| **2.1.3** | bote 2.7.2 opt-in `dist/bote-core.cyr` flip + cyrius 5.10.44 + libro 2.6.3 (sigil 3.1.1 / patra 1.9.4 / agnosys 1.2.6 transitive); `src/_libro_compat.cyr` retired; `slice` / `keccak` / `random` added to stdlib; `.cyrius-toolchain` removed; CONTRIBUTING / CLAUDE rewrites ride along | ✅ Shipped |
| **2.1.4** | **Pattern-analyzer refinements.** Detector #3 (directed sequence): splits `_pat_sensitive` into recon (`aegis_*`, `phylax_*`) vs mutation (`ark_install`, `ark_remove`); `_pat_check_sequence` flags ordered recon→mutation in the last 10 calls. Catches what the count-based escalation detector misses when sensitive calls are spaced below the 3-of-5 threshold. New public surface: `pattern_off_hours_score_bp(pa, agent_id, hour)` returns 0..1000 instead of binary flag — same threshold semantics, composes with `score.cyr` basis-point risk model. Existing detectors unchanged at the wire level. +11 test assertions (390 → 401) | ✅ Shipped |
| **2.1.5** | **cyrius major-toolchain jump 5.10.44 → 6.1.24 + libro 2.7.2 + bote 2.7.3.** Transitive sigil 3.7.8 / patra 1.11.0 / agnosys 1.4.1 / majra 2.4.5 / sakshi 2.2.10. The one source-level fix: `atomic` / `thread` / `thread_local` added to `[deps].stdlib` + the `main.cyr` and three test-suite includes (before `sigil`) — sigil 3.7.8's serial hash path self-installs a per-thread TLS scratch bank (`cbank()` → `thread_local_get`, cyrius ≥ 6.0.52), so libro `chain_append`'s SHA-256 trapped with **SIGILL** without them. Two cross-module `duplicate fn` warnings noted (sigil now ships `chacha20_xor`; majra ships `circuit_breaker_new` — t-ron's tested `src/` definitions win). ⛔ **CORRECTED at 2.1.10 — this row called them "benign" and they were not, which is why they sat unfixed for six patches.** "t-ron's definitions win" *was* the defect: it meant sigil's AEAD called t-ron's global-buffer cipher, and it meant two harnesses tested sigil's cipher rather than the one main.cyr ships. majra's `circuit_breaker_new` disagrees about arity over a different struct layout and became a hard error at cyrius 6.6.2. Both renamed at 2.1.10. Lock now records 48 hashes (6.0.x model, reproducible from empty `./lib`); committed `./lib` stdlib refreshed 5.10.44 → 6.1.24 (it had been stale-shadowing the snapshot). 401 assertions hold; benches flat; `code_size` 100.6 % → 120 %. Mirrors bote 2.7.3 | ✅ Shipped |
| **2.1.6** | **cyrius 6.2.11 (onto the 6.2.x line) + libro 2.7.4 + bote 2.7.6 + `bayan` stdlib carve.** Transitive sigil 3.7.14 / patra 1.11.2 / agnosys 1.4.3 / majra 2.4.7. The **`bayan` carve** (cyrius 6.1.25) consolidated standalone `json` / `base64` / `bigint` into one bundle; migrated `[deps].stdlib` + every `src`/test include (`json` + `base64` + `bigint` → `bayan`) with **no call-site changes** — t-ron makes zero direct `json_*`/`base64_*`/`bigint_*` stdlib calls. Repaired three **stale harnesses** (`tests/t-ron.tcyr`, `-crypto.tcyr`, `.bcyr`) that still `include`d the retired `src/_libro_compat.cyr` + nine per-module `lib/bote_*.cyr` files — latent since 2.1.3, they no longer compiled; swapped to `lib/bote-core.cyr` and re-aligned every harness to `main.cyr`'s lib order. `registry_new()` → `tool_registry_new()` (bote 2.7.4 ToolRegistry rename; test-only). Fixed the bench's `sigil`-before-`ct` / no-`thread_local` ordering — a sigil 3.7.14 SIGILL landmine that only surfaces when *run*. Lock 48 → 47 hashes (`bayan` folds three entries into one). 401 assertions hold; benches flat. Mirrors bote 2.7.6 | ✅ Shipped |
| **2.1.7** | **cyrius 6.3.15 + libro 2.7.9 + bote-core 2.7.7 — 6.3.x dep-sidecar reconciliation.** Added `sakshi` / `fs` / `process` / `sync` to `[deps].stdlib` (libro's 6.3.x dist `.deps` sidecar declares them as consumer-scope leaves; patra 1.12.7 pulls `sync`); `main.cyr` includes `lib/fs.cyr` + `lib/process.cyr` before sigil/libro. Documented the CYML-comment double-quote gotcha. 401 assertions hold; benches flat. Mirrors bote 2.7.7 | ✅ Shipped |
| **2.1.8** | **cyrius 6.4.66 + libro 2.8.2 + bote-core 3.1.4 (MAJOR) + sigil 3.12.1 `[deps.sigil]` first-party pin.** Toolchain re-vendor for the 6.4.65 `thread_local_alloc` slot allocator (stale `lib/` failed to link). bote MAJOR bump is additive on the 2.0 handler ABI. New **`[deps.sigil]` pin — full `dist/sigil.cyr`** insulates `dist/t-ron.deps` from libro 2.8.0's transitive sigil-thinning (mldsa/sha folds would mis-declare as stdlib leaves and break downstream `cyrius deps`); sidecar byte-identical to 2.1.7, mirrors daimon 1.4.3 / bote 3.1.4. Banks the reciprocal `LIBRO_ERR_*` / `BOTE_ERR_*` dep renames (t-ron already 0 bare `ERR_*`). `bench-history.sh` float-aware rewrite for 6.4.x decimal-µs. 401 assertions hold; benches flat-to-faster. Mirrors daimon 1.4.3 | ✅ Shipped |
| **2.1.9** | **cyrius 6.5.35 + libro 2.8.12 + bote-core 3.3.7 + sigil 3.12.9 — dist-sidecar repair + the cap raise.** The `[deps.bote]` → **`[deps.bote-core]`** rename restores basename ↔ dep-name agreement so `bote-core` stops being emitted into `dist/t-ron.deps` as a bogus stdlib leaf; this was a **live** break of every downstream `cyrius deps`, not a latent one, and 2.1.8 missed it by checking the sidecar against the previous release ("byte-identical") rather than against the stdlib. cyrius 6.5.35's 64 MB compile-source cap **closes the `code_size` watching row** on response path (1). `[deps].stdlib` unchanged — 6.5.35 resolves sidecar leaves (`bench` / `test` / `result`) itself. Warnings cleared upstream (`bayan` pointer casts, `chan_try_send`); static data 13.4 MB → 805 KB. 401 assertions hold | ✅ Shipped |
| **2.1.10** | **cyrius 6.6.2 + libro 2.10.0 + sigil 3.12.16 — the value-form migration and the "benign" duplicates.** Four value-form sites in `_llm_http_post` (two of which silently swallowed connect and send failures), the `circuit_breaker_*` → `safety_circuit_breaker_*` rename forced by 6.6.2's arity-collision hard error, the `chacha20_xor` → `cc20_xor` rename that stops t-ron shadowing sigil's AEAD cipher, and the two harnesses that had been testing sigil's implementation instead of t-ron's. 401 assertions hold | ✅ Shipped |
| **2.1.11** | **cyrius 6.6.6 + libro 2.10.3 + bote-core 3.3.13 + sigil 3.12.18 — manifest cleanup and the majra retirement.** `cyrius.cyml` rewritten as a manifest (228 → 128 lines); `[deps.majra]` retired now that bote pins majra 2.9.1; `dist/t-ron.deps` gains `sys`; audit path ~20 % faster via libro 2.10.3. 401 assertions hold | ✅ Shipped |
| **2.1.x** | **Real-time alerts via daimon event bus** — daimon exposes `msg_bus_publish` today (`daimon/src/main.cyr:2635`). Wire `audit_log` to publish on the agreed majra topics. Conditional on confirming daimon's topic schema is settled before the patch. This is the next clear "doable on 5.10.44, no upstream blocker, real user-visible delta" candidate | 🟡 Conditional |
| **~~2.1.x~~ 2.1.9** | **`code_size` headroom — ✅ RESOLVED at 2.1.9 on response path (1).** cyrius **6.5.35 raised the compile-source cap to 64 MB**, the upstream proposal this row named as its preferred fix. t-ron sits at **2 069 656 / 67 108 864 (3 %)**, down from ~118 % over the old 1 MB watermark (126.6 % at 2.1.6, 120 % at 2.1.5, 100.6 % at 2.1.4). Every other counter got a raised ceiling too: `fn_table` **17 %** (cap 8192 → 32768), `identifiers` **35 %** (262144 → 524288), plus a newly surfaced `var_table` at **32 %**. Paths (2) ecosystem-wide sigil-thinning and (3) feature-gating `llm_scan` / `safety` / `signing` are **moot for t-ron** — the full `dist/sigil.cyr` bundle the 2.1.8 `[deps.sigil]` pin keeps now costs 3 % of budget, so the bloat that pin "accepted for now" is free. No further action | ✅ Resolved at 2.1.9 |
| **Watching** | **Test-file refactor for the cyrius 5.10.x assert-nested-call parser quirk** — bote 2.7.1 hit it; t-ron has not surfaced it today. Lands as a patch only if a future test add trips the pattern | 🟡 Conditional |
| **Arc close** | **Remaining feature item (daimon real-time alerts), not a toolchain version.** The original plan was to close 2.1.x on the cyrius toolchain crossing and cut 2.2.x — but the ecosystem made the 5.10.44 → 6.1.24 jump and t-ron absorbed it as a patch (2.1.5) since the wire shape never moved. The arc now closes when its last feature item lands; **2.2.x is reserved for the next change that actually moves the JSON-RPC / dispatcher shape**, not a routine toolchain bump | 🔮 Trigger for 2.2.x = wire-shape change |
| **Future** | **Optional flip to `dist/bote.cyr` (full bundle, transport stack included).** ⚠️ **The blocker this row waited on is gone** — cyrius 6.5.35's 64 MB compile-source cap landed at 2.1.9 (t-ron uses 3 %), so size no longer argues against the full bundle. The row nonetheless stays **Optional, and the recommendation is unchanged**: t-ron never wires bote transports, so `dist/bote-core.cyr` remains the correct pull — and 2.1.9 confirmed `lib/bote-core.cyr` carries **zero** `sandhi_` references, i.e. the transport-free guarantee is real, not nominal. Flipping would pull the sandhi/TLS stack into the compile unit for no reachable caller. This row only moves if a future t-ron feature actually reaches for a transport-side bote surface | 🟢 Optional — unblocked, still not recommended |

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
> need upstream schema work in another crate that has not firmed
> up yet. Items code-doable on the current toolchain with no
> upstream coordination have been pulled forward into the 2.1.x
> arc table above.
>
> ⚠️ **A toolchain jump is no longer the cut trigger.** This
> section used to read "needs the cyrius 5.11.x line"; t-ron has
> since crossed 5.10 → 6.1 → 6.2 → 6.3 → 6.4 → **6.5.35**, all as
> patches, because none of them moved the JSON-RPC boundary or the
> SecurityGate dispatcher signature. **2.2.x is reserved for a
> wire-shape change**, per the arc-close row above.

### 2.2.x candidates

| Item | Notes |
|---|---|
| **Audit-tool authorization** | The 2.1.0 handler-ABI change plumbed `claims` through to t-ron's four introspection tools; 2.2.x adds the policy hook that gates `tron_audit` / `tron_policy` on caller identity (read from `claims`). **Blocker:** agnosticos claims schema firm-up — no firm-up signal in `agnosticos/docs/development/summer-2026-arc.md` as of 2026-05-11. Spec-aligned with bote's bearer / JWT / PKCE story |
| **agnoshi intents** | Natural-language security queries — was in the original Phase 1 backlog. Compose with agnoshi's intent parser; t-ron exposes the same surface its MCP tools already cover (`tron_status` / `tron_risk` / `tron_audit`). **Blocker:** agnoshi availability |
| ~~**cyrius 5.11.x toolchain bump**~~ | ❌ **Retired as a 2.2.x trigger.** Written when 5.11.x looked like the next crossing; the ecosystem has since gone to **6.5.35** and t-ron absorbed every step as a patch (2.1.5 / 2.1.6 / 2.1.7 / 2.1.8 / 2.1.9). Routine toolchain bumps are patch work — see the arc-close row: 2.2.x needs a wire-shape change |

### Phase 2 — Advanced detection (post-2.1.x)

| Item | Notes |
|---|---|
| **ML-based anomaly detection** | Train on normal patterns, flag deviations. Sized at ~mid-2.x; needs a training-corpus story and a runtime cost budget. Stays 2.2.x+ on corpus-readiness, not toolchain |
| **Privilege escalation pattern detection** | ✅ Shipped at 2.0.0 (`_pat_check_escalation`: 3+ of last 5 sensitive AND ≥ 1 benign mixed). **Directed-sequence refinement shipped at 2.1.4** (`_pat_check_sequence`: ordered recon→mutation in last 10 calls; catches the spaced-out variant) |
| **Time-of-day anomaly detection** | ✅ Shipped at 2.0.0 (`_pat_check_time`: binary flag below 2 % of total once ≥ 50 calls observed, and agent not active in all 24 hours). **Continuous basis-point scoring shipped at 2.1.4** (`pattern_off_hours_score_bp`: 0..1000 score with same threshold semantics; composes with `score.cyr`) |
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
| bote + libro dist bundles together exceed cyrius's 2 MB compile-source cap (bote drags sandhi 11k lines via the transport stack) | ✅ Fully resolved. Consumer-side at 2.1.3 (flipped `[deps.bote]` to `dist/bote-core.cyr`, opt-in transport-free profile, bote 2.7.2); **upstream at 2.1.9 — cyrius 6.5.35 raised the cap to 64 MB**, retiring the orthogonal track this row was holding open |
| `assert(streq(call(…), "lit") == 1, "msg")` parser quirk at cyrius 5.10.x — bote 2.7.1 hit it; t-ron has not (yet) | 🟡 2.1.x will refactor if surfaced — not triggered through 2.1.3 |
| `secret` is a storage-class keyword in 5.10.x | ✅ t-ron has no `secret` identifiers; only one string-literal use in tests/t-ron-crypto.tcyr (safe) |
| `cyrius distlib` emits a bundled dep into the `.deps` sidecar as a **stdlib leaf** whenever the module basename does not match the dep name (`[deps.bote]` + `dist/bote-core.cyr` → basename `bote-core` ≠ dep `bote`) | ✅ Resolved at 2.1.9 — renamed the dep to `[deps.bote-core]`. **This bit twice**: 2.1.8 diagnosed the identical mechanism for `sigil` and fixed *that* instance, while the `bote-core` line sat in the same file undetected, because the 2.1.8 check was "sidecar byte-identical to previous release" rather than "every sidecar line is a real stdlib module". **The durable rule: validate `dist/t-ron.deps` against the toolchain stdlib listing, not against the last release** — a regression check cannot catch a defect that predates the baseline |

## Recorded by cyrius 6.7.6 (2026-10-08) — for the next cyrius pin move

⛔ Needs cyrius >= 6.7.6 — nothing to do until cyrius 6.7.6 is tagged; then at your pin bump:

- **Git first: a `path` beside `git` / `tag` becomes a dev override** (here: `libro`, `bote-core` (`../bote`),
  `sigil`).
  From 6.7.6 it is read only in local mode (`CYRIUS_LOCAL=1`, `CYRIUS_LOCAL=<dep,dep>` or `--local`).
  With no switch, `cyrius deps` / `build` resolve the TAG (commit pin checked) and print one `hint:`
  line naming the checkout not used, so a local build and CI compile the same code.
- Local mode prints a `local:` line per override and builds from `build/local-deps/` without writing
  `lib/` or `cyrius.lock`; a hand-written `include "lib/<dep>.cyr"` sees the override there too (the
  compiler's `CYRIUS_LIB_OVERLAY`, set by `cyrius`).
- The first default resolve adds commit pins for these deps to `cyrius.lock` — a one-time diff.
- CI lock guards and `sed`-the-path-out steps can become `cyrius deps --locked`.
- `.github/workflows/ci.yml:58,66` and `release.yml:58,63` (`cyrius deps` then `cyrius deps --verify`) are such
  guards; with `lib/` gitignored, `--locked` checks the resolve against `cyrius.lock` alone and builds from
  `build/locked-deps/`.
- Reference: the cyrius guide's *Git first; local development is a switch (6.7.6)*.
