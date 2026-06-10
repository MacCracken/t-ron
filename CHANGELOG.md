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

_(empty)_

## [2.1.5] — 2026-06-10 · cyrius major-toolchain jump (5.10.44 → 6.1.24) + libro 2.7.2 + bote 2.7.3

Sixth patch of the **2.1.x modernization arc** and its largest
single step: the **cyrius major-version crossing (5.10.44 →
6.1.24)** the arc had earmarked as its closing move. The arc
absorbs the jump as a final 2.1.x patch rather than cutting
2.2.x — the JSON-RPC boundary and the SecurityGate dispatcher
signature are untouched; this is a pure toolchain + dependency
refresh. Mirrors **bote 2.7.3**, which made the identical jump
and is the reference consumer for the pattern.

### Changed

- **Cyrius pin `5.10.44` → `6.1.24`** (5.x → 6.x major crossing).
  `cyrius.cyml` remains the single pin source (`${file:VERSION}`
  for the package version).
- **CI/release toolchain install rewritten** (`ci.yml` +
  `release.yml`). The hand-rolled two-tarball extraction probed
  for `bin/cc5` and ran `cc5 --version` — but the 6.0.0 cycle
  renamed the compiler binary `cc5` → `cycc`, so the install gate
  failed outright on 6.1.24 (`FAIL: bin/cc5 missing`). Both
  workflows now delegate to the upstream `scripts/install.sh`
  keyed on the `cyrius.cyml` pin (lays out `$HOME/.cyrius/{bin,
  lib}` with `cycc`/`cyrius`/`cyrfmt`/`cyrlint` + the stdlib
  snapshot), and the verify step uses `cyrius --version`. Same
  installer body as patra / bote / agnosys on the 6.x toolchain.
  All other CI steps already shell the `cyrius` wrapper
  (`build`/`test`/`deps`/`distlib`/`bench`), so nothing else moved;
  the `CYRIUS_STATS=1` capacity gate parses the unchanged `cyrius
  stats:` block.
- **libro `2.6.3` → `2.7.2`** (`dist/libro.cyr`) and **bote
  `2.7.2` → `2.7.3`** (`dist/bote-core.cyr` opt-in core profile,
  unchanged shape). Transitive pins advance: **sigil 3.1.1 →
  3.7.8**, **patra 1.9.4 → 1.11.0**, **agnosys 1.2.6 → 1.4.1**,
  **majra → 2.4.5**, **sakshi → 2.2.10**.
- **`cyrius.lock` now records 48 hashes** (t-ron's full
  dependency closure under the 6.0.x lock model — stdlib modules
  + dep bundles) instead of the prior 7 git-dep-bundle entries.
  `cyrius deps --verify` passes (48 verified, 0 failed); the count
  is reproducible from an empty `./lib` (CI regenerates it).
- **Refreshed the committed `./lib` stdlib from 5.10.44 → 6.1.24
  content.** The repo tracks a subset of `./lib` (a legacy of
  pre-`.gitignore` history); those files had gone stale and were
  shadowing the version-matched 6.1.24 toolchain snapshot at build
  time. Regenerated `./lib` clean so the build compiles against
  genuine 6.1.24 stdlib (12 tracked stdlib modules updated; the
  `sigil`/`patra`/`sakshi` entries flipped from `…/3.1.1` symlinks
  to real 6.x files).

### Added

- **`atomic` / `thread` / `thread_local` stdlib modules** added to
  `[deps].stdlib` and the `src/main.cyr` + all three test-suite
  include lists, ordered **before `sigil`**. Required by sigil
  3.7.8: its crypto path self-installs a per-thread TLS scratch
  bank on the **serial** hash path (`cbank()` → `thread_local_get`,
  cyrius ≥ 6.0.52), and its parallel `sv_verify_batch` spawns
  `thread_create`/`thread_join` workers (`thread` builds on the
  lock-free `atomic` queue). Without these, the SHA-256 inside
  libro's `chain_append` lands on a DCE-NOPed trap and the audit
  chain crashes with **SIGILL** on first append. This was the only
  source-level breakage from the major jump; it surfaced as the
  `t-ron` and `t-ron-crypto` suites trapping in their audit tests
  while `t-ron-safety` (no chain path) stayed green. Mirrors bote
  2.7.3's `thread` addition.

### Notes

- **Two new cross-module `duplicate fn` warnings** (benign): sigil
  3.7.8 now ships its own `chacha20_xor`, and majra 2.4.5 a
  `circuit_breaker_new` (different signature). t-ron's `src/`
  definitions are included **after** the dep bundles, so they win
  ("last definition wins") — confirmed by the passing RFC-7539
  ChaCha20 vector and safety circuit-breaker tests.
- **Consumer note**: downstreams that include `dist/t-ron.cyr` and
  exercise the audit chain must now carry `atomic` / `thread` /
  `thread_local` in their own `[deps].stdlib` (consumers already on
  bote 2.7.3 list `thread`). The dist bundle is unchanged apart
  from the version header — t-ron's bundled `src/` modules did not
  move; `main.cyr` (entry, not in `[lib]`) holds the new includes.

### Tests

- All three suites green under cyrius 6.1.24: **401 assertions, 0
  failures** (`t-ron` + `t-ron-crypto` restored from the SIGILL
  trap; `t-ron-safety` 48/48). No assertion-count change — this is
  a toolchain refresh, not new surface.

### Performance (cyrius 6.1.24, x86_64, 2026-06-10)

Flat across the major jump — within run-to-run noise, no
regression.

| Operation | 2.1.4 | 2.1.5 | Δ |
|---|---:|---:|---:|
| `policy_check` | 907 ns min / 1 µs avg | 907 ns min / 1 µs avg | flat |
| `scanner_clean_text` | 3 µs min / 5 µs avg | 3 µs min / 4 µs avg | within noise |
| `scanner_sql_detect` | — | 978 ns min / 2 µs avg | — |
| `audit_log` | — | 10 µs min / 13 µs avg | — |
| `tron_check_allow` (full pipeline) | 14 µs min / 18 µs avg | 12 µs min / 18 µs avg | within noise |

### Capacity (`CYRIUS_STATS=1`, cyrius 6.1.24)

| Dimension | 2.1.4 | 2.1.5 | Cap |
|---|---:|---:|---:|
| `fn_table` | ~40 % | 3 735 (46 %) | 8 192 |
| `identifiers` | ~37 % | 114 094 (44 %) | 262 144 |
| `code_size` | 100.6 % | 1 257 400 (120 %) | 1 048 576 |

`code_size` grew with the larger 6.x stdlib bundle and sits
further over the 1 MB watermark — still the informational,
**non-gated** dimension (per the 2.1.2 CI capacity gate, only
`fn_table` / `identifiers` fail-gate at ≥ 95 %). It continues to
want the upstream compile-source-size cap raise.

## [2.1.4] — 2026-05-11 · pattern-analyzer refinements (directed sequence + continuous off-hours score)

Fifth patch of the **2.1.x modernization arc**, and the first
forward-feature pull into the arc — both refinements ride the
existing 5.10.44 toolchain with no upstream coordination. The
JSON-RPC boundary is unchanged; the SecurityGate dispatcher
signature is unchanged. New surface is internal to
`src/pattern.cyr` and one new public function.

### Added

- **Detector #3: directed sequence** in `pattern_check_anomaly`.
  Splits the prior single `_pat_sensitive` list into two
  semantic categories — recon (`aegis_*`, `phylax_*`) and
  mutation (`ark_install`, `ark_remove`) — and adds
  `_pat_check_sequence` which scans the last 10 calls for a
  recon-class call appearing strictly before a mutation-class
  call. Catches ordered recon→mutation patterns that the
  count-based escalation detector (#2) misses when sensitive
  calls are spaced below the 3-of-5 threshold. New emission
  string: `"directed sequence: recon followed by mutation"`.
  Detector ordering: enumeration → escalation → sequence →
  off-hours; first match wins.
- **`pattern_off_hours_score_bp(pa, agent_id, current_hour)`** —
  basis-point variant of detector #4. Returns 0..1000 instead of
  a binary flag, using the same threshold semantics
  (`max(1, total * 2 / 100)`). Returns 0 on insufficient
  history (< 50 calls), unknown agent, fully-active agent
  (24 active hours), or current-hour ≥ threshold. Otherwise
  returns `1000 * (threshold - current_count) / threshold` —
  monotonic with anomaly degree (1000 = dead hour, 0 = within
  pattern). Composes with `score.cyr`'s basis-point risk model
  so consumers can blend off-hours signal with deny / flag
  history rather than a yes/no decision. Existing binary
  `_pat_check_time` retained — no consumer ABI change.
- **`PAT_SEQUENCE_WINDOW = 10`** constant alongside the existing
  `PAT_MAX_HISTORY` / `PAT_MIN_HISTORY_FOR_TIME` / `PAT_ACTIVE_HOUR_*`.
- **`_pat_recon` / `_pat_mutation` arrays** + `_pat_is_recon` /
  `_pat_is_mutation` / `_pat_match_any` helpers. `_pat_is_sensitive`
  becomes a union over both arrays — preserves detector #2's
  behaviour exactly.

### Tests

- **`test_pattern_directed_sequence`** (5 sub-groups, 5
  assertions): recon→mutation flagged with escalation winning
  on the wire; isolated sequence (below escalation threshold)
  flagged on its own; mutation→recon order ignored;
  recon-only ignored; mutation-only ignored.
- **`test_pattern_off_hours_score_bp`** (5 sub-groups, 6
  assertions): insufficient history → 0; unknown agent → 0;
  in-pattern hour → 0; dead off-hour → 1000; partial off-hour
  → between 0 and 1000 (monotonic check).
- Total: **11 new assertions**. Suite total now **323 + 30 + 48 =
  401 assertions, 0 failures**.

### Performance (cyrius 5.10.44, x86_64, 2026-05-11)

| Operation | 2.1.3 | 2.1.4 | Δ |
|---|---:|---:|---:|
| `policy_check` | 489 ns min / 1 µs avg | 907 ns min / 1 µs avg | within noise |
| `scanner_clean_text` | 3 µs min / 5 µs avg | 3 µs min / 5 µs avg | flat |
| `scanner_sql_detect` | 978 ns min / 2 µs avg | 1 µs min / 2 µs avg | flat |
| `audit_log` | 10 µs min / 14 µs avg | 12 µs min / 14 µs avg | within noise |
| `tron_check_allow` | 14 µs min / 18 µs avg | 14 µs min / 18 µs avg | flat |

The new detector is bounded at 10 history scans + a single pass
through 2-element classification arrays per call; not on the
hot-path budget.

### Capacity utilisation (cyrius 5.10.44, 2026-05-11)

| Counter | Used | Cap | % | Δ from 2.1.3 |
|---|---:|---:|---:|---:|
| `fn_table` | 3 300 | 8 192 | 40 % | +5 |
| `identifiers` | 97 804 | 262 144 | 37 % | +151 |
| `var_table` | 1 638 | 8 192 | 20 % | +3 |
| `fixup_table` | 9 987 | 262 144 | 4 % | +14 |
| `string_data` | 28 856 | 2 097 152 | 1 % | +46 |
| `code_size` | 1 055 344 | 1 048 576 | **100.6 %** | +1 744 B |

Tiny absolute deltas across every dimension — refinement code
is ~50 LOC. `code_size` ticks +0.1 pp; still within emit-buffer
auto-expand.

### Regenerated

- **`dist/t-ron.cyr`** — header stamps `# Version: 2.1.4`; 4 621
  lines (was 4 493 at 2.1.3, +128 lines from the new detector +
  bp score function + their helpers). CI freshness gate verifies.

## [2.1.3] — 2026-05-11 · bote 2.7.2 opt-in dist + cyrius 5.10.44 + libro 2.6.3 + libro_compat retired

Fourth patch of the **2.1.x modernization arc**. Two unblocks
land at once: bote 2.7.2 ships the opt-in `dist/bote-core.cyr`
profile (the consumer-side fix tracked in the 2.1.0 CHANGELOG's
"Pending / parked" block), and libro 2.6.3 calls
`ct_eq_bytes_lens` directly inside its dist bundle, retiring the
`src/_libro_compat.cyr` shim. The 9-module bote cherry-pick that
shipped at 2.1.0 collapses to a single bundle include, and the
queued CONTRIBUTING/CLAUDE rewrites ride along. No SecurityGate
behaviour change; the four introspection tools and JSON-RPC wire
format are byte-identical.

### Breaking

None at the public surface. The compat-shim retirement and bote
include shape are internal — consumers pulling `dist/t-ron.cyr`
see no signature change.

### Changed

- **Cyrius pin: 5.10.34 → 5.10.44** (`cyrius.cyml [package].cyrius`).
  Picks up the 5.10.x stdlib + frontend deltas. New stdlib
  surface: `lib/slice.cyr` (required by agnosys 1.2.6's slice
  subscript lowering, pulled transitively through libro 2.6.3),
  `lib/keccak.cyr` + `lib/random.cyr` (required by sigil 3.1.1's
  ML-DSA + AES-GCM surfaces). Same toolchain landing as bote 2.7.2
  / libro 2.6.3 / phylax 1.1.1.
- **libro pin: 2.6.2 → 2.6.3** (`[deps.libro] tag`). 2.6.3 ships
  sigil 3.1.1 / patra 1.9.4 / agnosys 1.2.6, fixes the call-site
  for the post-5.9.20 `ct_eq_bytes_lens` rename inside
  `dist/libro.cyr`, and migrates three `str_from(sig_alg_name(…))`
  call sites away from the cyrius 5.10.44 dispatcher path that
  would otherwise format the alg cstring as a decimal integer.
- **bote pin: 2.7.1 → 2.7.2** + **module list flipped to
  `["dist/bote-core.cyr"]`**. t-ron is the trigger consumer for
  bote's new opt-in `[lib.core]` profile (9 transport-free
  modules — `error`, `protocol`, `jsonx`, `codec`, `registry`,
  `events`, `audit`, `dispatch`, `schema` — 1989 lines / 70 KB)
  packaged via `cyrius distlib core`. Same nine modules that the
  2.1.0 cherry-pick listed by hand, now delivered as a single
  bundle. Excludes the transport stack (`transport_*` / `bridge`
  / `auth` / `session` / `discovery` / `content` / `host` /
  `audit_libro` / `events_majra`) that t-ron does not consume and
  that previously pushed the combined `dist/libro.cyr` +
  per-module-bote source past cyrius's 2 MB compile-source cap
  when a single-bundle bote was attempted.
- **`cyrius.cyml [deps].stdlib`** picks up `slice`, `keccak`,
  `random`. Ordering note in the file: `ct` / `keccak` / `random`
  precede `sigil`/`libro` so cyrius's single-pass resolver sees
  the symbols before the consumers reach for them. Mirrors bote
  2.7.2's `[deps].stdlib` comment.
- **`src/main.cyr`** reordered to match: `lib/ct.cyr` /
  `lib/keccak.cyr` / `lib/random.cyr` now precede `lib/sigil.cyr`
  (was `sigil` → `net` → `ct`). Adds `lib/slice.cyr`. Drops the
  nine `lib/bote_<module>.cyr` lines in favour of a single
  `include "lib/bote-core.cyr"`. Drops `include "src/_libro_compat.cyr"`.
- **`.cyrius-toolchain`** removed — old convention. The cyrius
  pin lives only in `cyrius.cyml [package].cyrius` now, matching
  the bote / libro / phylax 5.10.x layout.

### Removed

- **`src/_libro_compat.cyr`** retired. Shipped at 2.1.0 as a
  one-symbol shim aliasing the retired `ct_eq` (cyrius 5.9.20
  renamed it `ct_eq_bytes_lens`) for libro 2.6.2's bundle
  internals. libro 2.6.3's `dist/libro.cyr` calls
  `ct_eq_bytes_lens` directly (verified at line 116 of the new
  bundle); no remaining caller. Drops from `cyrius.cyml [lib]
  modules` (19 → 18) and `src/main.cyr`.

### Performance (cyrius 5.10.44, x86_64, 2026-05-11)

| Operation | 2.1.2 | 2.1.3 | Δ |
|---|---:|---:|---:|
| `policy_check` | 489 ns min / 1 µs avg | 489 ns min / 1 µs avg | flat |
| `scanner_clean_text` | 4 µs | 3 µs min / 5 µs avg | within noise |
| `scanner_sql_detect` | 978 ns min / 2 µs avg | 978 ns min / 2 µs avg | flat |
| `audit_log` | 13 µs | 10 µs min / 14 µs avg | within noise |
| `tron_check_allow` (full pipeline) | 17 µs | 14 µs min / 18 µs avg | within noise |

390-assertion baseline holds (312 + 30 + 48), 0 failures.

### Capacity utilisation (cyrius 5.10.44, 2026-05-11)

| Counter | Used | Cap | % |
|---|---:|---:|---:|
| `fn_table` | 3 295 | 8 192 | 40 % |
| `identifiers` | 97 653 | 262 144 | 37 % |
| `var_table` | 1 635 | 8 192 | 20 % |
| `fixup_table` | 9 973 | 262 144 | 4 % |
| `string_data` | 28 810 | 2 097 152 | 1 % |
| `code_size` | 1 053 600 | 1 048 576 | **100.5 %** |

**Re-baselined.** cyrius 5.10.44 ships **doubled** caps for both
`fn_table` (4 096 → 8 192) and `identifiers` (131 072 → 262 144)
relative to 5.10.34. The 2.1.2 CHANGELOG's 75 % / 69 % numbers
were against the old caps; against 5.10.44 the same code sits at
40 % / 37 % — well clear of the 95 % CI gate. The sigil 3.1.1 +
libro 2.6.3 cascade in this release adds modest absolute growth
(fn_table +219 from 2.1.2's 3 076; identifiers +6 639 from
91 014) but utilisation drops sharply because the cap doubled.

`code_size` is the unchanged dimension and stays at **100.5 %** —
the cyrius compile-time emit buffer auto-expands past this
watermark (the build succeeds and all 390 tests pass), so it
remains informational rather than gated. Response paths
unchanged from 2.1.2: (1) upstream cyrius cap raise (the
compile-source-size cap raise proposal filed 2026-05-10 covers
exactly this dimension), (2) feature-gate `llm_scan` /
`safety` / `signing`, (3) opt-in compile-unit split.

### Regenerated

- **`dist/t-ron.cyr`** — header stamps `# Version: 2.1.3`; 4 493
  lines (was 4 512 at 2.1.2). 19-line drop from retiring the
  compat shim. CI freshness gate verifies.

### Docs (riding along from `## [Unreleased]`)

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
  Project Identity now reflects the Cyrius port (cyrius 5.10.44
  pin via `cyrius.cyml [package].cyrius`, `VERSION` +
  `${file:VERSION}` as single source of truth); cleanliness
  check uses `cyrius deps --verify` / `cyrius distlib` /
  `CYRIUS_STATS=1` / `git diff --exit-code dist/t-ron.cyr`
  rather than `cargo fmt` / `cargo clippy`; `#[non_exhaustive]`
  / `#[must_use]` / `#[inline]` re-cast as the cyrius-equivalent
  disciplines; `unwrap()`/`panic!()` DO-NOT entries reframed as
  "no unguarded `syscall(60, ...)` or out-of-bounds in library
  code"; new Release Discipline section formalizes the
  docs-no-version-bump rule; added Bote handler ABI notes. The
  `src/_libro_compat.cyr` reference dropped with the shim
  retirement in this same release.

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
