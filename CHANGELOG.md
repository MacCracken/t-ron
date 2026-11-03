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

## [2.2.2] — 2026-11-03 · bote-core 3.8.1 + the quick-item bundle — `policy_check` 27 % faster, no warnings left, and the roadmap reorganized

bote-core **3.8.0 → 3.8.1**, plus every open item small enough to land
without the full audit. That audit is now scheduled as 2.2.3. The roadmap is
reorganized: 2.2.3 is the P(-1) sweep, and open features sit one line per
minor from 2.3.x. **426 assertions** (348 · 30 · 48) pass. `policy_check` is
**27 % faster**; the other benches are flat. Every build and suite now prints
**zero warnings**.

### Changed — `policy_check` does one hash lookup, not two

`policy_get` and `policy_get_or_create` (`src/policy.cyr`) did `map_has`, then
`map_get`: two hashes and two probes of the same key. `map_get` returns 0 for a
missing key, and a stored policy is always a non-zero 24-byte allocation, so
one `map_get` answers both questions.

**Isolated by an A/B** (three interleaved rounds, mean):

| `policy_check` build | mean |
|---|---|
| 2.2.1 | 294.7 ns |
| 2.2.2 with 2.2.1's `src/policy.cyr` | 289.7 ns |
| **2.2.2** | **210.7 ns** |

The change alone is **−79 ns (−27 %)**. The other ~5 ns is bote 3.8.1 or noise.
So one string hash and probe costs ~80 ns at 6.7.18. That also sizes the ten
remaining double lookups 2.2.3 will take, several of them on `tron_check`'s
path.

### Changed — bote-core 3.8.0 → 3.8.1

bote 3.8.1 pins the same cyrius 6.7.18, libro 2.11.3 and majra 2.13.0, so only
`lib/bote-core.cyr` and its commit pin (`9e28f67`, matching the remote tag)
move in the lock. It adds titles, icons and server instructions, all opt-in.
It also fixes ten defects in 3.8.0. The one that reaches t-ron's result shape
refuses a result naming `content`, `structuredContent` or `isError` twice, and
t-ron's results never repeat a key. None of the 17 bote functions t-ron calls
changed. Binary 675,640 → 677,336 B (+1,696 B).

### Fixed — the last warning in any build

`tests/t-ron-crypto.tcyr` sent itself SIGHUP with raw x86_64
`syscall(39, 0)` / `syscall(62, …)`. It printed `syscall arity mismatch` on
every run since at least 2.1.10, and was wrong off x86_64. It now calls stdlib
`sys_kill(sys_getpid(), SIGHUP)`. The build and all three suites print no
warnings.

### Changed — CI's dist gate checks the sidecar, and no longer hides a `distlib` failure

`ci.yml`'s freshness step ran `cyrius distlib || true` and diffed only
`dist/t-ron.cyr`, and `release.yml` did the same. Both now run `cyrius distlib`
unguarded and diff `dist/t-ron.cyr` **and** `dist/t-ron.deps`. Tested on a
CI-shaped copy (no `lib/`, `CYRIUS_LOCKED=1`): `distlib` exits 0 there, so
`|| true` could only hide a real failure.

**Mutation-checked**: an `assert` line planted in the committed
`dist/t-ron.deps` passed the old gate *and* the sidecar validity gate, because
`assert` is a real stdlib leaf. The new diff fails on it. libro 2.10.7 made the
same change.

### Changed — docs and comments

- **The roadmap is reorganized.**
  - It states how patch and minor versions are used.
  - The closed 2.1.x arc collapses to one paragraph; its rows stay in Shipped.
  - **2.2.3** lists the P(-1) sweep's known inputs.
  - Open features sit one line per minor: **2.3.x** MCP surface and
    authorization, **2.4.x** ecosystem integration, **2.5.x** capability-source
    policy, **2.6.x+** ML detection and edge fleet.
  - Every blocker was re-checked against the sibling repos instead of carried
    forward. agnoshi (2.2.0) and aethersafha (0.17.7) now exist, so two
    "not available" blockers are gone. daimon's `msg_bus_publish` moved to
    `src/ipc.cyr:268`. The claims schema and bote's description-hash
    primitive are still missing.
  - The cyrius 6.7.6 note is done and became a resolved row.
- **The cyrius 5.10.x `assert(streq(call(…), "lit") == 1, …)` watch row is
  closed.** A probe of exactly that shape compiles and evaluates correctly at
  6.7.18.
- **`src/main.cyr`'s comments state present-tense rules**, not release history
  ("2.1.3 picks up…", "(migration 2.1.7)"). Every include-order reason was
  re-checked against the 6.7.18 sources first, and two were corrected:
  - **bayan** is there for libro's canonical JSON; sigil makes no base64 or
    bigint calls.
  - **process** precedes sigil, whose agnosys helpers call `exec_capture`; libro
    makes no `process_` calls.
  - **fs** is called by nothing in `src/` or the deps (2.2.3 decides whether it
    stays).
  - The non-comment lines are byte-identical.
- `tests/t-ron.tcyr`'s `_echo_handler` takes the bote 2.0 handler ABI's two
  arguments.
- `src/tools.cyr`'s note on claims-gated tools names its blocker, not a version.

### Performance

Same session, three interleaved rounds, mean. The 2.2.1 column is the committed
tree built sibling-free (675,640 B, as released).

| bench | 2.2.1 | 2.2.2 | Δ |
|---|---|---|---|
| `policy_check` | 294.7 ns | 210.7 ns | **−28.5 %** (−27 % from `src/policy.cyr`, above) |
| `scanner_clean_text` | 3.556 µs | 3.527 µs | −0.8 % |
| `scanner_sql_detect` | 1.123 µs | 1.113 µs | −0.9 % |
| `audit_log` | 10.377 µs | 10.341 µs | −0.3 % |
| `tron_check_allow` | 17.110 µs | 16.986 µs | −0.7 % |

`tron_check` calls `policy_check` once, and 79 ns of ~17 µs is ~0.5 %, inside
this bench's spread. Recorded in `bench-history.csv`.

### Verified

- **`ci.yml`'s build-and-test job, run step by step from the YAML** with its
  own `env:` under `bash -e`, on a CI-shaped copy (fresh git, no `lib/`). Every
  step passes: locked resolve, manifest completeness, build, ELF, capacity,
  smoke, the three suites, the new dist gate, sidecar validity, bench.
  `lib/` is never created.
- **Clean-room consumer** (local mode; tag 2.2.2 is not on GitHub yet), from the
  integration guide's §1–§2: 6 deps resolved, bote-core 3.8.1, 0 undefined,
  0 duplicate, **`deny`**.
- **All four examples** build with 0 undefined and 0 duplicate diagnostics and
  pass.
- **Capacity**: `fn_table` 5,818 / 131,072 (4 %), `identifiers` 165,011 /
  8,388,608 (2 %), `code_size` 154,920 / 67,108,864 (0.2 %). Binary
  **677,336 B**.

### Known — recorded for 2.2.3

- `cyrius distlib` warns that 12 names are undefined on **x86_64-windows only**,
  the same 12 as 2.2.1. t-ron's signalfd SIGHUP path (`src/signal.cyr`) owns 6;
  deps own the rest. No other target is affected.
- `audit_export_encrypted` calls `ed25519_sign` twice, the first over the wrong
  bytes.
- These and the rest of the sweep's inputs are in the roadmap's 2.2.3 table.

## [2.2.1] — 2026-11-03 · cyrius 6.7.18 + libro 2.11.3 / bote-core 3.8.0 / sigil 3.13.15 — the tool handlers escape what they echo, and stop overrunning their buffers

Toolchain **6.7.9 → 6.7.18**, dependencies to their latest releases, with bote
held at **3.8.0** for this release. It fixes the JSON defect 2.2.0 recorded as
known, and a heap overrun found while fixing it. Both are in `src/tools.cyr`'s
MCP handlers. **426 assertions** (t-ron 348 · crypto 30 · safety 48) pass, 16
of them new. The binary is **70 % smaller** (2.28 MB → 676 KB) because 6.7.18
removes the dead code 6.7.9 only NOPed. `policy_check` is 11 % faster; the
other four benches are flat.

### Security — `tron_risk` and `tron_audit` wrote past their buffers

Both handlers built their reply in a fixed-size allocation and copied
caller-controlled strings into it without a length check:

- **`tron_risk`** used `alloc(256)`, then copied the `agent_id` from the call's
  arguments. Any ID over ~190 bytes ran past the buffer. With the bump
  allocator, the next allocation (the score's digits) landed inside the copied
  ID, so the reply came back truncated and corrupted. Measured on the 2.2.0
  code: a 2,048-byte ID was echoed as 241 bytes.
- **`tron_audit`** sized its array at `events × 160 + 32` bytes, whatever the
  recorded IDs and tool names held. About 61 bytes of each 160 are fixed
  syntax, so any event whose two strings exceeded ~100 bytes overran it.

Each reply is now sized exactly before it is written. A first pass measures
every value's escaped length, then one checked `alloc` takes it. On a failed
alloc the handler returns 0, which bote reports as a failed call; there is no
abort path. Reachable by any MCP client that can call these tools, or by any
agent whose calls the gate records.

### Fixed — the tool results were not valid JSON for hostile IDs

Recorded as known at 2.2.0. A result's `text` is a JSON document inside a JSON
string. The handlers hand-wrote the outer escapes and spliced values in raw.
There were two distinct breaks:

- **`tron_audit`** spliced the gate's raw agent IDs and tool names into the
  reply. One holding `"` broke the outer JSON, which bote 3.4.8+ turns into an
  `isError` result.
- **`tron_risk`** receives `jsonx_get_str`'s undecoded body (`a\"b\\c`), so its
  outer JSON stayed valid. But the `text` decoded to invalid JSON, so the
  document a client was meant to parse did not parse.

Every interpolated value is now escaped once into the document (RFC 8259 §7:
`"`, `\` and every byte below 0x20, with short forms for `\b \t \n \f \r`). The
document is then escaped once into `text`. **Output for ordinary input is
byte-identical**; three new assertions pin it exactly. `tron_risk` echoes the ID
it scored, the undecoded body, so the echo and the lookup agree.

The escaping is t-ron's own (`_tron_json_esc_len` / `_tron_json_esc_into`), not
bote's `bote_json_escape`. bote's writes through `str_builder_putc`, which
aborts the process on OOM, and CLAUDE.md rules that out in library code.

**Tests (+16 assertions, 3 new groups).**
- `tool results: exact bytes for plain input` pins the current output of
  `tron_status`, `tron_risk` and a `tron_policy` error.
- `hostile ids stay valid JSON` decodes both levels for IDs holding `"`, `\` and
  a newline, and round-trips them.
- `long ids fit their buffers` uses 2 KB IDs, all quotes for `tron_audit`, so
  they double when escaped.

Against the 2.2.0 handlers, 12 of the 16 fail, including `risk: 2 KB id echoed
whole (got 241, expected 2048)`. The 4 that pass are the 3 exact-bytes pins and
`tron_risk`'s outer validity, as the analysis above predicts.

### Changed — toolchain and dependency pins

| dep | was | now |
|---|---|---|
| cyrius | 6.7.9 | **6.7.18** |
| libro | 2.11.0 | **2.11.3** |
| bote-core | 3.4.10 | **3.8.0** *(held; 3.8.1 is tagged)* |
| sigil | 3.13.11 | **3.13.15** |
| majra | 2.12.0 *(transitive)* | **2.13.0** *(transitive, via bote-core)* |
| patra | 1.16.0 *(transitive)* | **1.16.6** *(transitive, via libro)* |

The set is consistent with no overrides. libro 2.11.3, bote 3.8.0 and majra
2.13.0 pin 6.7.18; bote 3.8.0 pins libro 2.11.3 and majra 2.13.0; libro 2.11.3
pins sigil 3.13.15 and patra 1.16.6. Those two are also the 6.7.18 folds
(`cmp`-identical), so the 2.2.0 `note: sigil 3.13.12 (wanted by libro) not
used` is gone.

What the deps changed, as it reaches t-ron:

- **bote 3.4.11–3.8.0.** None of the 17 bote functions t-ron calls changed
  shape. `registry_check_tool_def` now also refuses a bad `x-mcp-header`
  annotation, which t-ron does not use. Output schemas (3.8.0) are opt-in, and a
  tool without one "pays nothing more". t-ron is not named anywhere in those
  entries.
- **libro 2.11.x**: "No preimage, proof or signature format changes." Existing
  audit chains verify as before.
- **sigil 3.13.14** fixes CYRIUS-2026-0040 (ChaCha20-Poly1305 accepting a forged
  tag across shared crypto lanes). t-ron's encrypted export uses its own
  ChaCha20 (`cc20_*`) and sigil's Ed25519, not that AEAD, so the fix is
  inherited but off t-ron's path. 3.13.15 also drops the 256 KB static scratch
  array whose warning every build printed since 2.1.10.

⚠️ **Consumer floor unchanged: cyrius ≥ 6.7.2.** bote 3.8.0's bundles say
"Minimum cyrius: 6.7.13", but for the full `dist/bote.cyr`. Its own note says
`dist/bote-core.cyr`, the profile t-ron takes, compiles from 6.7.2. Measured
here: the clean-room consumer pinned at 6.7.2 builds with 0 undefined functions
and returns `deny`.

### Changed — `cyrius.lock`

- **60 → 68 entries**: `lib/math.cyr` and seven `lib/unicode/*` files, which
  6.7.18's `bayan.cyr` includes. 42 of the 60 carried-over hashes moved.
- Five commit pins, each matching its remote tag: bote-core `0de2037`, libro
  `f4a31a4`, majra `40b827f`, patra `efa2e34`, sigil `3c47656`. The lock was
  regenerated from scratch, so no 2.2.0 pins linger.

### Performance

Same session, three interleaved rounds, mean. The 2.2.0 column is the committed
tree built sibling-free at 6.7.9 (2,282,720 B, as released).

| bench | 2.2.0 | 2.2.1 | Δ |
|---|---|---|---|
| `policy_check` | 333.7 ns | 297.0 ns | **−11.0 %** |
| `scanner_clean_text` | 3.533 µs | 3.534 µs | 0.0 % |
| `scanner_sql_detect` | 1.119 µs | 1.113 µs | −0.5 % |
| `audit_log` | 10.339 µs | 10.291 µs | −0.5 % |
| `tron_check_allow` | 16.998 µs | 16.984 µs | −0.1 % |

`policy_check` is faster in every round (294–302 ns against 333–334). It is
not t-ron code: `src/policy.cyr` did not change, and neither did `hashmap.cyr`
or `regex.cyr` (byte-identical to 6.7.9). Two toolchain candidates remain, not
separated. First, `vec_get`'s out-of-bounds abort moved out of line into
`_vec_abort` (a cold path, but a smaller body). Second, 6.7.18's dead-code
compaction re-laid out the binary; 2.1.12 measured ~30 ns of placement
sensitivity on this bench. The handlers' new escaping is off `tron_check`'s
path, which the flat `tron_check_allow` confirms. Recorded in
`bench-history.csv`.

### Verified

- **Sibling-free, locked.** A copy of the working tree with no `lib/`:
  `cyrius deps --locked` proves the lock. Every CI verb under `CYRIUS_LOCKED=1`
  reproduces the local binary (675,640 B) and `dist/` byte-for-byte, runs all
  426 assertions and the bench, and writes neither `lib/` nor the lock.
- **Clean-room consumer** (local mode, tag 2.2.1 not yet on GitHub): **6 deps
  resolved** (t-ron 2.2.1, libro 2.11.3, bote-core 3.8.0, sigil 3.13.15, patra
  1.16.6, majra 2.13.0). It builds with 0 undefined and 0 duplicate diagnostics
  and returns **`deny`**. Pinned at 6.7.2, it does the same.
- **Every `ci.yml` gate run locally**: locked resolve, manifest completeness
  (18 modules), build + ELF + smoke, capacity, the three suites, dist freshness,
  sidecar validity (3/3: `regex net syscalls`, unchanged).
- **All four examples** build with 0 undefined and 0 duplicate diagnostics and
  pass on 6.7.18.
- **Warnings**: the build and the main and safety suites print **none**. The
  sigil static-array and large-static-data warnings are gone.
- **Capacity** (`CYRIUS_STATS=1`, DCE): `fn_table` 5,751 / 131,072 (4 %),
  `identifiers` 163,546 / 8,388,608 (2 %), `code_size` 153,000 / 67,108,864
  (0.2 %). Binary 2,282,720 → **675,640 B (−1,607,080 B, −70.4 %)**. At 6.7.9
  the dead code was NOPed in place ("compaction declined … the repair registry
  cap"). At 6.7.18 it is removed ("1992807 bytes of dead code eliminated").
  Live code went 148,775 → 153,000 B (+2.8 %, the handlers' escaping among
  it).

### Known — upstream / pre-existing, not changed here

- **`syscall arity mismatch` at `tests/t-ron-crypto.tcyr:138`** — a raw x86_64
  `syscall(39, 0)` getpid in a test.

## [2.2.0] — 2026-11-03 · cyrius 6.7.9 + libro 2.11.0 / bote-core 3.4.10 / sigil 3.13.11 — t-ron's four MCP tools register, and CI resolves `--locked`

First release of the 2.2.x line. Toolchain **6.6.20 → 6.7.9**, and every
dependency moved to the release that matches it. bote 3.4.x changes what a
client of a SecurityGate-wrapped dispatcher sees on the wire (listed below),
and it refused t-ron's own tool definitions, which forced **one source fix**
(`src/tools.cyr`). `dispatcher_dispatch`'s signature, the 2.0 handler ABI and
`security_gate_*` are unchanged. **410 assertions** (t-ron 332 · crypto 30 ·
safety 48) pass, 9 of them new. Benches are within ±3 %.

### Fixed — t-ron's four MCP tools were never registered correctly

`tron_tool_defs()` passed `str_from("object")` as each schema's type, and
`Str` values for every property name, property schema and `required` entry.
bote's `ToolSchema` stores C strings, so it read the `Str` header bytes.
bote 3.4.8's CHANGELOG names t-ron for this. Through bote 3.4.7 the four tools
(`tron_status`, `tron_risk`, `tron_audit`, `tron_policy`) were listed with
garbage bytes in `tools/list`, and calls failed validation on a garbage
`required` key. From 3.4.8, `registry_register` refuses them:

```
[ERROR] tool registration refused tool=tron_status reason="inputSchema type must be \"object\""
```

All 14 values are now C-string literals.

**Why 401 passing assertions never caught it.** `test_tron_tool_defs` only
counted the definitions. The gate harness `_make_gate` ignored
`registry_register`'s return value, and registered its own `echo` tool with
the same `str_from("object")`, which is what failed
`test_gate_allow_with_policy` at 6.7.9. The harness is fixed, and
`test_tron_tool_defs` gains **9 assertions**: each definition passes
`registry_check_tool_def`, each registers, and the registry then holds 4 tools.
**Mutation-checked**: against the old `src/tools.cyr` those 9 fail and the
other 323 pass. The integration guide's §3 snippet had the same call and is
corrected.

### Changed — toolchain and dependency pins

| dep | was | now |
|---|---|---|
| cyrius | 6.6.20 | **6.7.9** |
| libro | 2.10.8 | **2.11.0** |
| bote-core | 3.3.17 | **3.4.10** |
| sigil | 3.13.10 | **3.13.11** |
| majra | 2.9.3 *(transitive)* | **2.12.0** *(transitive, via bote-core)* |
| patra | 1.15.2 *(transitive)* | **1.16.0** *(transitive, via libro)* |

libro 2.11.0 is the only libro pinned to 6.7.9. bote 3.4.0–3.4.10 all pin
6.7.9, and 3.4.10 is the latest; it pins libro 2.11.0 and majra 2.12.0. patra
1.16.0 is both libro's pin and the 6.7.9 fold.

**sigil is 3.13.11, the 6.7.9 fold, not 3.13.12.** The manifest rule keeps
`[deps.sigil]` on the release the toolchain folds, and `cmp` shows the fold is
byte-identical to 3.13.11's `dist/sigil.cyr`. bote compiles that same fold.
libro 2.11.0 asks for 3.13.12, and every resolve says so in one line:

```
note: sigil 3.13.12 (wanted by libro) not used; 3.13.11 (the root) resolved first
```

3.13.12 is a pin move plus one LOW fix in `hash_file_into`, which t-ron does
not call.

⚠️ **Consumer impact: cyrius ≥ 6.7.2.** bote 3.4.x's bundles need it (bote
3.4.9 measured 6.7.0 and 6.7.1 failing). Measured here with the clean-room
consumer: pinned at 6.6.20 it fails to build (`lib/alloc.cyr:120:25: undefined
variable '_threads_active'`); at 6.7.2 it builds and returns `deny`.

### Changed — wire behaviour, inherited from bote 3.4.x

A client talking to a dispatcher behind `security_gate_dispatch` sees these.
t-ron passes `dispatcher_dispatch`'s result through without re-wrapping it,
and its handlers already return CallToolResults (`_tron_result_text`). So
nothing here needs a t-ron change, but clients may:

- `tools/call` naming an unknown tool: error `-32601` → **`-32602`** (3.4.5).
- Arguments that fail the tool's `inputSchema`: error `-32602` → a **result
  with `isError: true`** naming the argument (3.4.5, SEP-1303). Types, enums and
  bounds are enforced from 3.4.8, where only `required` was before.
- A handler that returns bare JSON is wrapped in a text block, and one that
  returns bytes that are not JSON becomes a failed call (3.4.8).
- A result with `isError: true` is audited as a failure (3.4.8).
- Invalid JSON is `-32700`, and a bad `id` / `params` / `cursor` is refused
  (3.4.5).

t-ron's own denials (`security: <reason> [<code>]`) are unchanged.

### Changed — CI and release resolve `--locked` (the roadmap note recorded by cyrius 6.7.6)

`ci.yml` and `release.yml` replace `cyrius deps` + `cyrius deps --verify` with
one `cyrius deps --locked`, and set `CYRIUS_LOCKED=1` job-wide. Every verb then
compiles the resolution the lock proves, from `build/locked-deps/`; nothing
writes `lib/` or `cyrius.lock`. The note's other items were already done at
2.1.12 (no `path` lines, commit pins in the lock).

⭐ **The old guard had a hole, and the new one closes it.** Tested on a
sibling-free copy with no `lib/`, as on a runner:

| committed `cyrius.lock` | `cyrius deps` + `--verify` | `cyrius deps --locked` |
|---|---|---|
| as committed | pass | pass, nothing written |
| one hash flipped (`lib/hashmap.cyr`) | fail (6.7.9 refuses to re-lock a changed leaf) | fail, naming both hashes |
| one entry deleted (`lib/poison.cyr`) | **pass**: `deps` re-added the line, `--verify` checked the rewrite (60/60) | **fail**: "the tags resolve it and cyrius.lock has no line for it" |

Every CI verb was then run under `CYRIUS_LOCKED=1` on that copy. The build is
byte-identical to the local one, all 410 assertions pass, `distlib` output is
identical, the bench runs, and `lib/` is never created.

### Changed — `cyrius.lock`

- The same 60 entries; 39 hashes moved with the toolchain and deps.
- Five commit pins: bote-core `deeb32f`, libro `53f00ce`, majra `e7e244b`,
  patra `00cf574`, sigil `fb42c8a`. Each matches its remote tag
  (`git ls-remote`).
- Regenerated from scratch rather than updated. Since 6.6.20, cyrius keeps an
  old tag's commit pin after a tag bump, so an in-place resolve left all five
  2.1.12 pins beside the new ones (10 lines). The file hashes were identical
  either way.

### Performance

Same session, three interleaved rounds, mean. The 2.1.12 column is the
committed tree built sibling-free at 6.6.20. It reproduces the 2.1.12 binary
exactly (2,241,072 B).

| bench | 2.1.12 | 2.2.0 | Δ |
|---|---|---|---|
| `policy_check` | 324.7 ns | 333.7 ns | +2.8 % |
| `scanner_clean_text` | 3.516 µs | 3.527 µs | +0.3 % |
| `scanner_sql_detect` | 1.123 µs | 1.109 µs | −1.2 % |
| `audit_log` | 10.299 µs | 10.281 µs | −0.2 % |
| `tron_check_allow` | 17.039 µs | 16.919 µs | −0.7 % |

`policy_check` is slower in all three rounds (+7 to +12 ns). The stdlib source
on its path did not change as code. `hashmap.cyr` and `vec.cyr` differ from
6.6.20 only in comments, and `regex.cyr` only names a constant inside the regex
compiler, not `glob_match`. So the delta is the 6.7.9 compiler's codegen or
placement, inside the ~30 ns placement effect 2.1.12 measured. Recorded in
`bench-history.csv`.

### Verified

- **Sibling-free, locked.** A copy of the working tree with no `lib/`:
  `cyrius deps --locked` proves the committed lock is exactly what the tags
  resolve. Every CI verb under `CYRIUS_LOCKED=1` reproduces the local binary
  (2,282,720 B) and `dist/` byte-for-byte.
- **Clean-room consumer.** A project declaring only `[deps.t-ron]`, running the
  integration guide's §1–§2 sample: **6 deps resolved** (t-ron 2.2.0, libro
  2.11.0, bote-core 3.4.10, sigil 3.13.11, patra 1.16.0, majra 2.12.0). It
  builds with 0 undefined and 0 duplicate diagnostics and returns **`deny`**.
  From 6.7.6 a `path` is read only in local mode, so the probe ran with
  `CYRIUS_LOCAL=t-ron`: tag 2.2.0 does not exist on GitHub yet.
- **Every `ci.yml` gate run locally**: locked resolve, manifest completeness
  (18 modules), build + ELF + smoke, capacity, the three suites, dist
  freshness, sidecar validity (3/3: `regex net syscalls`, unchanged).
- **All four examples** build with 0 undefined and 0 duplicate diagnostics and
  pass on 6.7.9.
- **Capacity** (`CYRIUS_STATS=1`, DCE): `fn_table` 5,071 / 131,072 (4 %),
  `identifiers` 144,370 / 8,388,608 (2 %), `code_size` 1,788,752 / 67,108,864
  (3 %). Binary 2,241,072 → **2,282,720 B (+41,648 B, +1.9 %)**.

### Known — t-ron, not fixed in this release

- **`tron_risk` and `tron_audit` build their JSON by concatenation, without
  escaping.** An `agent_id` (or a recorded tool name) holding `"` or `\`
  produces invalid JSON. Under bote 3.4.8 that becomes an `isError` result
  instead of a malformed reply. The defect predates this release.

### Known — upstream, not t-ron defects

- **sigil's 256 KB crypto scratch array gets static storage** — a `warning:`,
  now at `lib/sigil.cyr:28103`.
- **`compaction declined on x86_64 ELF: more than 4096 dead-code runs`** —
  informational. DCE still NOPs the 4,738 unreachable functions.
- **`syscall arity mismatch` at `tests/t-ron-crypto.tcyr:138`.** Pre-existing:
  a raw x86_64 `syscall(39, 0)` getpid in a test.

## [2.1.12] — 2026-11-03 · cyrius 6.6.20 + libro 2.10.8 / bote-core 3.3.17 / sigil 3.13.10 — no `path` lines, sigil resolves first, and a three-leaf sidecar

Thirteenth patch of the **2.1.x modernization arc**. Toolchain **6.6.6 →
6.6.20**, and every dependency moved to the release that matches it. **No
t-ron source changed.** `dist/t-ron.cyr` differs from 2.1.11 in its version
stamp and a new `# Requires` block. All **401 assertions** (t-ron 323 ·
crypto 30 · safety 48) pass. `policy_check` is **~14 % slower**; the other four
benches are flat. Both are measured and attributed below.

### Changed — toolchain and dependency pins

| dep | was | now |
|---|---|---|
| cyrius | 6.6.6 | **6.6.20** |
| libro | 2.10.3 | **2.10.8** |
| bote-core | 3.3.13 | **3.3.17** |
| sigil | 3.12.18 | **3.13.10** |
| majra | 2.9.1 *(transitive)* | **2.9.3** *(transitive, via bote-core)* |
| patra | 1.14.3 *(transitive)* | **1.15.2** *(transitive, via libro)* |

libro 2.10.8, bote 3.3.17 and majra 2.9.3 are the releases that pin cyrius
6.6.20. sigil has no 6.6.20-pinned release. 3.13.10 is the one 6.6.20 folds
into its stdlib, and patra 1.15.2 is the patra it folds. So the git pins and
the snapshot agree byte-for-byte: `cmp` shows the fold's `lib/sigil.cyr` is
identical to sigil 3.13.10's `dist/sigil.cyr`. The set is also self-consistent:
bote 3.3.17 pins libro 2.10.8 and majra 2.9.3, and libro 2.10.8 pins sigil
3.13.10 and patra 1.15.2.

### Changed — no `path` lines in `cyrius.cyml`

`path = "../libro"`, `"../bote"` and `"../sigil"` are gone. Below cyrius 6.7.6
`path` beats `tag` and skips commit-pin verification. On the release machine the
sibling checkouts had moved on to libro 2.11.3, bote 3.8.1 and sigil 3.13.15,
all pinned to cyrius 6.7.x. A local resolve would therefore have compiled those
working trees, not the tags CI clones. libro 2.10.5 and bote 3.3.16 made the
same change for the same reason. Rule 2 above the git deps now says a `path`
line is never committed, and the local build is now the CI build; the
sibling-free reproduction below is byte-identical.

### Changed — `[deps.sigil]` resolves first

At 6.6.20, bote-core 3.3.17's sidecar names `sigil` as a stdlib leaf. With
`[deps.sigil]` listed after bote-core (as at 2.1.11), that leaf claimed
`lib/sigil.cyr` first, and every command printed:

```
warning: refusing to overwrite stdlib leaf 'sigil' -- a dependency resolves a package of the same name.
  kept (stdlib snapshot): lib/sigil.cyr
  skipped (dep artifact): ~/.cyrius/deps/sigil/3.13.10/dist/sigil.cyr
```

This is the same shape as the majra warning 2.1.11 removed. The two copies are
the same bytes, so nothing compiled differently, but the pin t-ron declared was
not the one that resolved. The section now comes first, which clears the warning
and also matches `src/main.cyr`'s include order (sigil → libro → bote-core).
The reorder is **perf-neutral**: in an interleaved A/B (sigil first vs. last,
three rounds) all five benches are within noise. The binaries are the same size
with different bytes, because the compile order changed.

The section's comment is rewritten with its current reason. 2.1.11 said that
without the section, libro's thin sigil sub-bundles compile beside the full copy
(233 duplicate definitions). **That no longer happens at 6.6.20.** Probed with
the section removed, the build is clean: 0 duplicates, and the thin modules are
reported "not vendored". But that is only because bote-core's sidecar happens to
name `sigil`, and bote 3.3.17's own CHANGELOG calls that line an artifact no core
module uses. `src/signing.cyr` needs `verify_data()`, which only the full bundle
carries, so the section stays. That way t-ron's crypto does not depend on another
package's sidecar.

### Changed — `cyrius.cyml` drops the "no comments inside the array" rule

cyrius 6.6.17 reads the manifest with a single reader that skips comments (as
libro 2.10.7 and bote 3.3.17 recorded). Checked here rather than inherited: a
comment holding a quoted `"bogusmod"` and a stray `]`, placed mid-`stdlib`, was
ignored, and the entry after it was still read.

### Changed — `dist/t-ron.deps` drops from 29 leaves to 3, and the bundle opens with `# Requires`

Since cyrius 6.6.18, `distlib` writes only the stdlib leaves its compile-verify
proves the bundle needs: **`regex`, `net`, `syscalls`**. Everything else arrives
through the named deps' own `# Requires` blocks. `dist/t-ron.cyr` now opens with
the matching include block. The sidecar validity gate resolves all 3 leaves
against the 6.6.20 stdlib.

⚠️ **Consumer impact.** A consumer that calls a stdlib module from its own code,
and got it only through t-ron's old 29-leaf sidecar, may need to list it in its
own `[deps] stdlib`. The integration guide's sample is unaffected. It still
resolves 6 deps, builds and returns `deny` (below), even though its hand-written
`include "lib/args.cyr"` / `assert` / `fs` are no longer vendored into `lib/`;
the compiler finds them in the toolchain snapshot.

### Changed — `cyrius.lock`

- **76 → 60 entries.** The deps' sidecars shrank (libro 27 leaves → 1, bote-core
  8 → 4), so `async` ×4, `tls_*` ×8, `sandhi`, `bench`, `test`, `dynlib` and
  `fdlopen` are no longer vendored. `poison` is new (6.6.18's `freelist`
  includes it). 54 of the 59 surviving hashes moved with the toolchain and deps.
- ⭐ **The lock carries commit pins again**: bote-core `cd7dd95`, libro
  `53401e7`, majra `ddf26f1`, patra `2bc1925`, sigil `6d065da`. Each was checked
  against its remote tag with `git ls-remote`. 2.1.11's committed lock had none,
  for two reasons: `path` overrides skip pinning, and 6.6.6 dropped inherited
  pins. Both are gone (the `path` lines above; 6.6.20's CYRIUS-2026-0030 fix
  merges inherited pins). The 2.1.11 note "the committed lock carries no
  `commit` pins" no longer applies.
- `tests/t-ron.bcyr` includes `lib/bench.cyr`, which is no longer vendored. It
  resolves from the toolchain snapshot, so `cyrius bench` and CI's bench step run
  unchanged.

### Performance

Same session, same machine, three interleaved rounds, mean. The 2.1.11 column
is the committed tree built sibling-free at 6.6.6. It reproduces the 2.1.11
binary exactly (2,664,672 B).

| bench | 2.1.11 | 2.1.12 | Δ |
|---|---|---|---|
| `policy_check` | 289 ns | 329 ns | **+13.7 %** |
| `scanner_clean_text` | 3.556 µs | 3.544 µs | −0.3 % |
| `scanner_sql_detect` | 1.132 µs | 1.133 µs | +0.1 % |
| `audit_log` | 10.487 µs | 10.375 µs | −1.1 % |
| `tron_check_allow` | 17.099 µs | 17.202 µs | +0.6 % |

⭐ **Attributed, not inferred.** `policy_check` calls nothing from libro, bote
or sigil, only stdlib `map_has` / `map_get`, `vec_get` and `glob_match`.
`glob_match` is unchanged and `hashmap.cyr` was rewritten (6.6.20 counts
tombstones toward the rebuild). Three interleaved rounds, each binary run by
hand:

| `policy_check` build | mean |
|---|---|
| `cyrius build` of `tests/t-ron.bcyr` (what `cyrius bench` runs) | ~330 ns |
| same source, hand-assembled prepend, compiled by 6.6.20 `cycc` | 298 ns |
| as above, with 6.6.6's `hashmap.cyr` + `hashseed.cyr` swapped in | 289 ns |

- **~9 ns comes from 6.6.20's `hashmap.cyr`.** Swapping in the 6.6.6 file
  restores the 2.1.11 number exactly.
- **~30 ns is code placement.** The `cyrius build` and hand-assembled binaries
  compile the same source to the same size (2,209,864 B) with different bytes.
  Run directly, outside `cyrius bench`, they keep their gap, which rules out the
  runner and environment size (a 0–4 KB environment pad moves nothing).

Neither part is t-ron code. `policy_check` does two hash lookups per call
(`map_has`, then `map_get`) where one would do, which doubles its exposure to
both; that is noted, not changed in this patch. Recorded in
`bench-history.csv`.

### Verified

- **Sibling-free reproduction.** A copy of the working tree with no siblings
  beside it, resolved so every dep cloned at its tag. Byte-identical to the
  local build: the binary (2,241,072 B), `dist/t-ron.cyr`, `dist/t-ron.deps` and
  `cyrius.lock`.
- **Clean-room consumer.** A project declaring *only* `[deps.t-ron]` and running
  the integration guide's §1–§2 sample: `cyrius deps` → **6 deps resolved**
  (t-ron 2.1.12, libro 2.10.8, bote-core 3.3.17, sigil 3.13.10, patra 1.15.2,
  majra 2.9.3), five commit-pinned. It builds with 0 undefined and 0 duplicate
  diagnostics and returns **`deny`** for `ark_install` from an unregistered agent.
- **Every `ci.yml` gate run locally**: dep verify (60/60), manifest completeness
  (18 modules), build + ELF + smoke, capacity, the three suites, dist freshness,
  sidecar validity (3/3).
- **All four examples** build with 0 undefined and 0 duplicate diagnostics and
  pass on 6.6.20.
- **Capacity** (`CYRIUS_STATS=1`, DCE): `fn_table` 4,987 / 131,072 (4 %),
  `identifiers` 142,314 / 8,388,608 (2 %), `code_size` 1,747,728 / 67,108,864
  (3 %). Binary 2,664,672 → **2,241,072 B (−423,600 B, −15.9 %)**; `fn_table`
  5,955 → 4,987. **The shrink comes from the toolchain.** The prepend list is the
  same 33 modules, and every vendored bundle *grew* in source (sigil 1,168 →
  1,264 functions).

### Known — upstream, not t-ron defects

- **`duplicate fn 'uname_release'` is gone.** sigil 3.13.10 dropped its copy, the
  fix 2.1.11 said belonged upstream.
- **sigil's 256 KB crypto scratch array gets static storage.** Still a
  `warning:`, now at `lib/sigil.cyr:28046`. Same code, which sigil indexes per
  thread bank.
- **New `note:` on every build**: `compaction declined on x86_64 ELF: more than
  4096 dead-code runs, the repair registry cap`. DCE still NOPs the 4,654
  unreachable functions; the bytes stay in the file.
- **`syscall arity mismatch` at `tests/t-ron-crypto.tcyr:138`.** Pre-existing: a
  raw x86_64 `syscall(39, 0)` getpid in a test.

## [2.1.11] — 2026-09-23 · cyrius 6.6.6 + libro 2.10.3 / bote-core 3.3.13 / sigil 3.12.18 — `cyrius.cyml` back to a manifest, and `[deps.majra]` retires

Twelfth patch of the **2.1.x modernization arc**. Toolchain **6.6.2 → 6.6.6**,
dependency refresh, the explicit majra pin retired now that bote carries the
fix itself, and `cyrius.cyml` rewritten as a manifest. **No t-ron source
changed** — `dist/t-ron.cyr` differs from 2.1.10 only in its version stamp. All
**401 assertions** (t-ron 323 · crypto 30 · safety 48) pass; the audit path is
**~20 % faster**, measured and attributed below.

### Changed — toolchain and dependency pins

| dep | was | now |
|---|---|---|
| cyrius | 6.6.2 | **6.6.6** |
| libro | 2.10.0 | **2.10.3** |
| bote-core | 3.3.7 | **3.3.13** |
| sigil | 3.12.16 | **3.12.18** |
| majra | 2.7.1 *(explicit pin)* | **2.9.1** *(transitive via bote-core — pin retired, below)* |
| patra | 1.14.1 *(transitive)* | **1.14.3** *(transitive)* |

sigil 3.12.18 and patra 1.14.3 are exactly the releases cyrius 6.6.6 folds into
its stdlib, so the git pins and the snapshot agree byte-for-byte (checked with
`cmp`).

### Removed — the `[deps.majra]` pin

2.1.10 added an explicit majra 2.7.1 pin for one reason: bote-core 3.3.7
dragged in majra 2.7.0, whose `_sub_new` collided with libro's at a different
arity, and cyrius 6.6.2 made that a hard error. The section's own comment said
to retire it once bote re-pinned majra ≥ 2.7.1. bote 3.3.13 pins **2.9.1**, so
it is gone. Verified sibling-free, not assumed:

- majra still resolves to **2.9.1**, now through bote-core's own pin (commit
  `baca558`, matching the GitHub tag).
- `cyrius.lock` file hashes, `dist/t-ron.cyr` and `dist/t-ron.deps` are
  **byte-identical** with and without the section; 401/401 either way.
- ⭐ **It removes two warnings every 2.1.10 command printed** —
  `refusing to overwrite stdlib leaf 'sigil'` and `… 'patra'`. majra's sidecar
  declares `sigil` and `patra` as stdlib leaves, and the explicit pin sat
  *ahead of* `[deps.sigil]` in resolution order, so the snapshot copies were
  claimed first and t-ron's own sigil pin was refused. The bytes happened to
  match, so nothing broke — but the pin t-ron declared was not the one it
  compiled.
- The binary grows **+12,272 B, all of it dead**: DCE NOPs **+12,916 B** more
  and the live code is **268 B smaller** (same 5,955 functions, same 4,816
  eliminated). The cause is single-pass compile order — `cyrius build` prepends
  each resolved dep in resolution order, so majra now compiles after bote-core
  instead of before it.

### Changed — `cyrius.cyml` is a manifest again (228 → 128 lines)

The comment blocks had turned into a release ledger: version-by-version
narratives (`(2.1.3)`, `(migration 2.1.7)`, …), a dated account of the
2.1.3–2.1.8 sidecar break, size measurements at old toolchains, module counts
"verified against bote 3.3.7". All of that already lives in this file and the
roadmap. What remains states current rules only: why `[lib]` order matters,
the no-comments-inside-arrays rule, the dep-name ↔ basename rule, why `path`
needs a sibling-free check before a release, and one present-tense reason per
dep.

Two carried-over rationales were **stale, and are corrected rather than
copied**:

- **`deps.sigil`.** The 2.1.8 reason — libro's thin sigil sub-bundles would be
  emitted into the sidecar as bogus stdlib leaves — no longer holds at 6.6.6:
  without the section, distlib emits `sigil`, which *is* a valid stdlib leaf.
  The section is still load-bearing, for a different reason. Without it,
  libro's thin sub-bundles (`sigil-mldsa`, `sigil_sha256`, `sigil_sha_ni`,
  `sigil_hex`) are vendored *beside* the full copy and the build reports **233
  duplicate definitions**. The explicit pin wins over libro's, so exactly one
  sigil compiles — and only the full bundle carries the `verify_data()` that
  `src/signing.cyr` calls.
- **"Never write the bracketed `[deps.X]` header in a comment"** (still carried
  by libro 2.10.2 and bote 3.3.13) is **not adopted**: cyrius v6.5.28 anchored
  distlib's named-dep scan to real section headers and skips `#` comments
  (`_distlib_named_deps`, `cbt/commands.cyr`).

The cleanup is behaviour-neutral, and checked: `cyrius lib sync --dry-run`
lists the same 50 stdlib files before and after, and resolution produces
identical lock hashes.

### Changed — `dist/t-ron.deps` gains `sys` (28 → 29 leaves)

sigil 3.12.18 routes `agnosys_uname` through stdlib `sys_uname`
(`lib/sys.cyr`), so distlib's compile-verify pass adds `sys` as a leaf — the
same artifact libro 2.10.2 recorded for its own sidecar. `lib/sys.cyr` ships in
the 6.6.6 stdlib; the sidecar validity gate resolves all 29 leaves.

### Changed — `cyrius.lock` format

- Entries are now **sorted** (cyrius 6.6.3), so the lock is reproducible
  across machines, and it ends with a **`cyrius\t6.6.6`** pin trailer (6.6.4).
- Two new files: `lib/sys.cyr` (above) and `lib/alloc_cx.cyr` (6.6.6's
  cx-target allocator). 34 of 76 hashes moved with the toolchain and deps.

⚠️ **The committed lock carries no `commit` pins.** 2.1.10's lock pinned
majra's commit only because majra was the one dep without a `path` override;
libro, bote-core and sigil never had one. A local `cyrius deps` resolves every
dep through a `path` sibling, and cyrius 6.6.6 then writes the lock from an
*empty* pin list — the 6.6.4 carry-forward only fires when that list was never
allocated (the bare `--lock` verb), so inherited pins are dropped. That is an
upstream gap, not a t-ron choice. CI still verifies all 76 file hashes. A
sibling-free resolve records all five pins (libro `c95f296`, bote-core
`d0e8d86`, sigil `eb6b922`, patra `b9d3cf8`, majra `baca558`), each matching
its GitHub tag.

### Performance

Same session, same machine, mean of three runs. The 2.1.10 baseline is the
committed tree built sibling-free at 6.6.2.

| bench | 2.1.10 | 2.1.11 | Δ |
|---|---|---|---|
| `policy_check` | 300 ns | 288 ns | −4.1 % |
| `scanner_clean_text` | 3.560 µs | 3.467 µs | −2.6 % |
| `scanner_sql_detect` | 1.141 µs | 1.101 µs | −3.5 % |
| `audit_log` | 13.397 µs | 10.194 µs | **−23.9 %** |
| `tron_check_allow` | 20.238 µs | 16.402 µs | **−19.0 %** |

⭐ **Attributed, not inferred.** An A/B swapped *only* `dist/libro.cyr`
(2.10.0 ↔ 2.10.3) under otherwise identical 6.6.6 resolution, three
interleaved rounds:

| bench | libro 2.10.0 | libro 2.10.3 |
|---|---|---|
| `audit_log` | 12.86 µs | 10.15 µs |
| `tron_check_allow` | 19.12 µs | 16.63 µs |
| `policy_check` (control) | ~279 ns | ~283 ns |

The libro bundle alone accounts for **~2.7 µs** of `audit_log`'s ~3.2 µs. On
that path libro 2.10.3's `uuid_v4` draws its 16 bytes with one `random_bytes`
call instead of opening, reading and closing `/dev/urandom`, and 2.10.2 moved
`get_epoch_secs` onto stdlib `clock_epoch_secs()`; the split between the two
was not measured. The remainder is the rest of the toolchain and dependency
move. Recorded in `bench-history.csv`.

### Fixed — the integration guide's "verified" sample did not compile

`docs/guides/integration.md` wrote `if verdict_is_denied(v) == 1 {`, which
cyrius 6.6.6 rejects (`expected '(', got identifier 'verdict_is_denied'`). The
condition is now parenthesized and the guide re-verified at 2.1.11.

Re-verifying also showed that §3 (*Construct the gate*) does not compile
either: the multi-line string passed to `tron_load_policy` is rejected
(`expected ')', got string`), and its one-argument handler predates the bote
2.0 `fn h(args, claims)` ABI. That section now carries a warning, the guide's
"verified" claim is scoped to §1–§2, and the rewrite is left open.

### Fixed — examples 01 and 02 referenced an undefined `cc20_xor`

Fallout from 2.1.10's `chacha20_xor` → `cc20_xor` rename, and the same shape
as the harnesses that release fixed: `docs/examples/01-minimal-gate.cyr` and
`02-signed-policy.cyr` include `src/audit.cyr` but not
`src/crypto_chacha20.cyr`. Before the rename the call silently resolved to
sigil's cipher; after it, both built with `warning: undefined function
'cc20_xor'` and ran only because neither reaches the export path. Both now
include the module. All four examples build with **zero undefined symbols**
and pass on 6.6.6.

### Verified

- **Sibling-free reproduction** — built from a copy with no sibling checkouts,
  so every dep cloned at its tag exactly as CI does. Byte-identical to the local
  build: the binary (2,664,672 B), `dist/t-ron.cyr`, `dist/t-ron.deps`, and
  every lock hash.
- **Clean-room consumer** — a project declaring *only* `[deps.t-ron]` and
  running the integration guide's sample: `cyrius deps` → **6 deps resolved, 0
  errors** (t-ron, libro 2.10.3, bote-core 3.3.13, sigil 3.12.18, patra 1.14.3,
  majra 2.9.1); it builds against `dist/t-ron.cyr` and returns **`deny`** for
  `ark_install` from an unregistered agent.
- **Every `ci.yml` gate run locally**: dep verify (76/76), manifest
  completeness (18 modules), build + ELF + smoke, capacity, the three suites,
  dist freshness, sidecar validity (29/29).
- **Capacity** (`CYRIUS_STATS=1`, DCE): `fn_table` 5,955 / 131,072 (4 %),
  `identifiers` 191,765 / 8,388,608 (2 %), `code_size` 2,157,592 / 67,108,864
  (3 %). Binary 2,622,816 → **2,664,672 B**: +29,584 B from the toolchain and
  dep move (measured with the majra pin still in place), +12,272 B the majra
  dead code above.

### Known — upstream, not t-ron defects

- **`duplicate fn 'uname_release'`** (`lib/sigil.cyr` vs `lib/sys.cyr`) —
  sigil 3.12.18 adopted `lib/sys.cyr` but kept its own `uname_release` and
  `UTS_*` offsets. **Checked, not waved through**: both bodies are the same
  expression (`uts + UTS_RELEASE`), both `UTS_*` enums carry identical values
  under identical `CYRIUS_TARGET_AGNOS` guards (16/32 agnos, 65/130 Linux), and
  t-ron's `src/` calls neither — which copy wins cannot change behaviour on any
  target. The fix belongs in sigil (drop its copy).
- **sigil's 256 KB crypto scratch array gets static storage** — a `note:` at
  6.6.2, a `warning:` at 6.6.6; same code, which sigil indexes per thread bank.
- **`syscall arity mismatch` at `tests/t-ron-crypto.tcyr:138`** — pre-existing
  (6.6.2 reports the same line): a raw x86_64 `syscall(39, 0)` getpid in a test.

## [2.1.10] — 2026-09-10 · cyrius 6.6.2 value-form migration — and the two `duplicate fn` warnings 2.1.5 wrote down as "benign"

Eleventh patch of the **2.1.x modernization arc**. Toolchain jump
**6.5.35 → 6.6.2** (the `Result`/`Option`/`Either` *value form*), dependency
refresh, and **four silent defects** that the toolchain flip exposed. All
**401 assertions** (t-ron 323 · crypto 30 · safety 48) pass; benches flat.

### Changed — toolchain and dependency pins

| dep | was | now |
|---|---|---|
| cyrius | 6.5.35 | **6.6.2** |
| libro | 2.8.12 | **2.10.0** |
| sigil | 3.12.9 | **3.12.16** |
| bote-core | 3.3.7 | 3.3.7 (current) |
| majra | *(transitive, 2.7.0)* | **2.7.1 — now an explicit pin** |

The sigil bump is load-bearing, not cosmetic: the vendored `lib/sigil.cyr`
at 3.12.9 carried **12 calls to `payload()`**, the accessor cyrius 6.6.0
deleted when `Result` became a two-register `(tag, payload)` value. t-ron's
own `src/` never called it, so the repo looked clean while the bundle it
compiles against did not.

### Fixed — `_llm_http_post` treated connect and send failures as success

⛔ **Two of these four sites were silent, and they are the headline.**
`tcp_socket` / `sock_connect` / `sock_send` / `sock_recv` are all `: Result`.
Under the value form a Result consumed as a single value yields only its
**tag** — `0` for `Ok`, `1` for `Err`:

```
if (sock_connect(fd, addr, port) < 0) { return 0; }   # can NEVER fire
if (sock_send(fd, req, off) < 0)      { return 0; }   # can NEVER fire
```

Neither guard could ever be true, so a refused connection or a failed write
fell through into the read loop and `_llm_http_post` reported a scan against
a host it never reached. The other two sites (`tcp_socket`, `sock_recv`) the
compiler rejected outright. All four now bind both halves and test
`is_err_result`.

### Fixed — `circuit_breaker_new` collided with majra's, at a different arity

t-ron's `circuit_breaker_new(threshold, window_secs, cooldown_secs)` and
majra's `circuit_breaker_new(failure_threshold, cooldown_ns)` share a name,
disagree about arity, and describe **different 48-byte layouts**. cyrius
6.6.2 promotes that to a hard error. The safety module's family is renamed
to `safety_circuit_breaker_*` — matching its own `safety_engine_*` /
`safety_default_policies` convention and the `SafetyCircuitBreaker` name
already used in ADR-006. Six functions; no behaviour change.

### Fixed — t-ron's `chacha20_xor` was silently overriding sigil's

Same name, **same** arity, so this one stayed a warning rather than an error
— and it was the more dangerous of the two. "Last definition wins" meant
sigil's `chacha20_aead_encrypt` / `_decrypt` (`lib/sigil.cyr:8437`, `:8475`)
did not call sigil's cipher. They called t-ron's, which keys its keystream
off a **single process-global buffer** (`cc20_ks_g`) where sigil uses a
per-thread lane, and which never wipes the keystream after use. Renamed to
`cc20_xor`, consistent with the module's `cc20_block` / `cc20_init` / `cc20_qr`.
t-ron's own use is unchanged and still pins the RFC 7539 vector.

### Fixed — CI could not build at all: bote's transitive majra 2.7.0

⛔ **Found by CI after this release was first cut locally-green — the local
build was not representative.** `[deps.libro]`, `[deps.bote-core]` and
`[deps.sigil]` each carry a `path = "../sibling"` override. That is the
language's sanctioned local-dev mechanism, and it makes `git`/`tag` inert: the
dep resolves from the sibling **worktree**. CI has no siblings, so it clones the
tag. The two environments therefore resolved different code, and the difference
was two levels down — `path = "../bote"` chained into bote's own
`path = "../majra"` and picked up an unreleased majra, while CI cloned
bote 3.3.7, which pins **majra 2.7.0**.

majra ≤ 2.7.0 defines `_sub_new(chan, filter_fn)`; libro defines
`_sub_new(pattern)`. cyrius 6.6.2 promotes that same-name/different-arity pair
from a silent "last definition wins" to a **hard error**, so CI could not
produce a binary at all. Fixed with an explicit `[deps.majra]` pinned to
**2.7.1** (which renamed it `_majra_sub_new`), declared ahead of
`[deps.bote-core]` so it wins the resolution — the same "explicit pin wins"
pattern `[deps.sigil]` already uses against libro's thin sub-bundles. That
section carries **no** `path` override, deliberately: t-ron co-develops no part
of majra, and the override is what hid the break. Retire it once bote re-pins
majra ≥ 2.7.1.

### Fixed — the Build step went GREEN on a failed compile

`CYRIUS_STATS=1 cyrius build ... 2>&1 | tee build/build.log` takes **tee's**
exit status. GitHub Actions runs `run:` blocks under `bash -e`, not
`bash -eo pipefail`, so a compiler exit 1 was discarded and the step passed.
The break surfaced two steps later as:

```
xxd: build/t-ron: No such file or directory
```

— a missing-file error standing in for a compiler diagnostic that had already
been printed and thrown away. The step now sets `set -o pipefail` and asserts
`test -s build/t-ron` before reporting the size.

### Fixed — the main test suite and the bench exercised a different cipher than the binary

Direct consequence of the above, and only visible once the name stopped
colliding. `tests/t-ron.tcyr` (323 assertions) and `tests/t-ron.bcyr` both
include `src/audit.cyr` but neither included `src/crypto_chacha20.cyr`.
Their `audit_export_encrypted` coverage therefore resolved against **sigil's**
implementation, while `src/main.cyr` — which does include the module — shipped
t-ron's. The suite passed either way because the assertions round-trip.
Both harnesses now include the module; `cyrius test` / `cyrius bench` report
zero undefined symbols and zero duplicate definitions.

> **Correction to the 2.1.5 entry.** That release recorded these as "two
> benign cross-module `duplicate fn` warnings … t-ron's tested `src/`
> definitions win". Neither was benign. Writing a defect down as acceptable
> is what kept it unfixed for six patches — and "t-ron's definitions win"
> was precisely the problem, not the reassurance.


## [2.1.9] — 2026-08-23 · cyrius 6.5.35 + libro 2.8.12 / bote-core 3.3.7 / sigil 3.12.9 — and the `bote-core` sidecar leak that broke every downstream `cyrius deps`

Tenth patch of the **2.1.x modernization arc**. Toolchain + dependency
refresh, one **downstream-breaking sidecar defect fixed**, and the
long-standing `code_size` pressure **resolved upstream** — cyrius 6.5.35
raises the compile-source cap to 64 MB, so the dimension the roadmap has
been watching since 2.1.2 drops from ~118 % to **3 %**. No t-ron runtime
*logic* changed; all **401 assertions** (t-ron 323 · crypto 30 · safety 48)
pass, and benches are flat-to-**6× faster** against a same-session baseline.

### Fixed — `dist/t-ron.deps` declared `bote-core` as a stdlib leaf, breaking every consumer

⛔ **This is the headline, and it was a live break — not a latent one.**
`[deps.bote]` pinned `modules = ["dist/bote-core.cyr"]`, so the module
basename (`bote-core`) did not match the dep name (`bote`). `cyrius distlib`
recognizes a bundle as a *named dep* — and therefore excludes it from the
generated sidecar — only when basename and dep name agree. They did not, so
`bote-core` was emitted into `dist/t-ron.deps` as a required **stdlib** leaf.
It is not in the stdlib, so any consumer wiring t-ron per `DEPS-PATTERN.md`
got:

```
error: cannot read /home/macro/.cyrius/versions/6.5.35/lib/bote-core.cyr
error: dep t-ron requires 'bote-core' but it is not in the cyrius stdlib
6 deps resolved, 1 errors
```

⚠️ **This is exactly the defect 2.1.8 fixed for `sigil` — and missed for
`bote`.** The 2.1.8 `[deps.sigil]` pin was introduced with the correct
reasoning (basename ↔ dep name) and verified `dist/t-ron.deps`
byte-identical to 2.1.7 — but "byte-identical" was the wrong check: the
`bote-core` line was *already in that file* and already wrong, so comparing
against the previous release preserved the bug instead of catching it.

Fixed by renaming the dep `[deps.bote]` → **`[deps.bote-core]`**, so the
basename matches. `bote-core` now drops out of the sidecar; `sync` is
correctly declared in its place.

⭐ **Verified end-to-end against a real consumer, not inferred.** A scratch
project that pins t-ron per the `DEPS-PATTERN.md` contract now runs
`cyrius deps` (**6 deps resolved, 0 errors**), compiles against
`dist/t-ron.cyr`, and executes — returning a correct `deny` verdict for
`ark_install` from an unregistered agent. Before the fix the same probe
failed at the `cyrius deps` step.

### Added — CI gate: `dist/t-ron.deps` validated against the toolchain stdlib

A new **"Dist sidecar validity gate"** in `ci.yml` reads every leaf in
`dist/t-ron.deps` and fails the build if the corresponding
`$CYRIUS_HOME/versions/$PIN/lib/<leaf>.cyr` does not exist — i.e. if
the sidecar claims something is stdlib that is not.

The existing freshness gate could not catch this: it only asserts the
committed `dist/t-ron.cyr` matches a regeneration. The sidecar was
never checked at all, and the 2.1.8 manual check ("byte-identical to
last release") was structurally incapable of finding a defect older
than its baseline. The new gate compares against the **toolchain**,
which has no such blind spot.

⭐ **Mutation-tested, and tested through the real YAML path** — the
step's `run:` block was extracted from the parsed workflow and
executed, so the escaping is verified, not assumed. It reports
`all 28 leaves resolve` on the fixed tree, and re-adding the
`bote-core` line turns it red with the downstream error quoted.

### Changed

- **Toolchain**: cyrius **6.4.66 → 6.5.35**. The wrapper had already rolled
  forward locally (`manifest-pin: 6.4.66 (drift — wrapper is 6.5.35)`).
  `rm -rf ./lib && cyrius deps` re-vendored the snapshot.
- **Dependencies**: libro **2.8.12** (was 2.8.2), bote-core **3.3.7** (was
  3.1.4), sigil **3.12.9** (was 3.12.1). Transitive: patra **1.13.10**,
  majra **2.7.0**, sakshi **2.4.11**. The set matches bote 3.3.7's own pins
  (libro 2.8.12 / cyrius 6.5.35) — one coherent ecosystem stack.
- **`[deps].stdlib` needs no `bench` / `test` / `result` entry.** libro's and
  sigil's 6.5.x sidecars declare all three, but cyrius 6.5.35 resolves
  sidecar leaves itself — `cyrius deps` succeeds with the list unchanged and
  `cyrius deps --verify` reports **72 verified, 0 failed**.
- **Lockfile 54 → 72 entries.** 18 modules vendored transitively that were
  not before: `bench`, `test`, `dynlib`, `fdlopen`, `thread_macos`, the
  four `async*`, `sandhi`, and the eight `tls*` / `tls_native*` files. The
  TLS/sandhi cluster arrives through t-ron's own `net` stdlib dep, whose
  TLS surface 6.5.x carves into separate modules.
  ✅ `lib/bote-core.cyr` contains **zero** `sandhi_` references — the
  transport-free guarantee the 2.1.3 core-profile flip rests on still holds;
  none of the cluster is reachable from t-ron, and DCE NOPs all of it.

### Fixed — build warnings that cleared on the new stack

- `lib/bayan.cyr`'s three `assigning non-pointer to typed pointer` warnings:
  **gone** (fixed upstream).
- `warning: undefined function 'chan_try_send'`: **gone**.
- **Static data 13,411,920 → 805,216 bytes** (16.6× smaller) on the DCE
  build. Binary 2,929,424 B.

Three benign `duplicate fn` warnings remain and are unchanged since 2.1.5
(`_sub_new` libro/majra; `chacha20_xor` and `circuit_breaker_new`, where
t-ron's own tested definitions win).

### Capacity — the cap raise landed, and `code_size` is no longer a concern

cyrius 6.5.35 raises every counter's ceiling. `CYRIUS_STATS=1`, DCE build:

| Counter | 2.1.8 | 2.1.9 | Cap change |
|---|---|---|---|
| `fn_table` | 3866 / 8192 (47 %) | **5751 / 32768 (17 %)** | 8192 → 32768 |
| `identifiers` | 114767 / 262144 (44 %) | **185909 / 524288 (35 %)** | 262144 → 524288 |
| `var_table` | — | **2689 / 8192 (32 %)** | newly surfaced |
| `code_size` | ~118 % over a 1 MB watermark | **2069656 / 67108864 (3 %)** | → 64 MB |

⭐ **This closes the roadmap's `code_size` watching row on its preferred
path.** That row named three responses and ranked them: (1) the upstream
compile-source-size cap raise, (2) ecosystem-wide sigil-thinning, (3)
feature-gating `llm_scan` / `safety` / `signing`. Path (1) shipped, so
(2) and (3) are moot for t-ron — the full `dist/sigil.cyr` bundle the 2.1.8
`[deps.sigil]` pin keeps is now 3 % of budget, and the bloat that pin
"accepted for now" costs nothing.

### Benchmarks

Measured on the same machine in the same session — the old stack was
re-benchmarked immediately before the upgrade, because the 2.1.8 CSV row was
recorded on a different day under different load and is not a fair baseline.

| Bench | 6.4.66 baseline | 6.5.35 | Δ |
|---|---|---|---|
| `policy_check` | 1.693 µs | **265 ns** | **6.4× faster** |
| `scanner_sql_detect` | 2.470 µs | **1.04 µs** | **2.4× faster** |
| `scanner_clean_text` | 4.713 µs | **3.35 µs** | 1.4× faster |
| `audit_log` | 14.154 µs | **13.0 µs** | ~8 % faster |
| `tron_check_allow` | 20.733 µs | **19.6 µs** | ~5 % faster |

Three consecutive runs; `policy_check` held 273/265/264 ns and
`tron_check_allow` 19.4/19.4/20.0 µs, so the ordering is stable, not noise.

⚠️ **Read `audit_log` and `tron_check_allow` carefully.** Against the *2.1.8
CSV row* (10.4 µs / 13.0 µs) both look like regressions. They are not
comparable measurements: the **old** stack benchmarked on this machine today
at 14.2 µs / 20.7 µs, i.e. slower still, so the delta is machine conditions,
not the upgrade. Both paths do get genuinely more work per call — libro
2.8.11 added strict `canonical_json_is_valid` validation ahead of the
canonical-JSON hasher — and that cost is real but smaller than the codegen
win. Worth re-measuring on a quiet machine before quoting an absolute.

### Documentation — three docs were not stale, they were broken

The docs pass started as a routine pin refresh and turned up code
samples that **do not compile**. Each was verified by building it, not
by reading it:

- **All four `docs/examples/*.cyr` failed to build**, while
  `docs/doc-health.md` recorded them as "✅ Fresh — Builds + runs
  clean". They still included `lib/bigint.cyr` / `lib/json.cyr` /
  `lib/base64.cyr` (folded into `bayan` at the 2.1.6 carve) and
  `src/_libro_compat.cyr` (retired at 2.1.3) — latent since 2.1.6.
  Include blocks rebuilt; **all four now build and run**:
  `01` allow/deny, `02` signed-policy enforce, `03` a 456-byte
  ChaCha20+Ed25519 envelope round-trip, `04` blocks `rm -rf /`.
- **`docs/guides/testing.md` was 100 % Rust-era** — `cargo test`,
  `make clippy`, `cargo audit`, `serde` round-trips, `.await` — in a
  repo with no `Cargo.toml`. The ledger had it as "🟡 Stale — refresh
  the cyrius pin reference". Fully rewritten to the real three-suite
  Cyrius layout, `test_group` / `assert_eq` idiom, and the
  include-order hazards specific to harnesses.
- **`docs/guides/integration.md` sections 1–2 did not compile** —
  `cyrius.toml`, cyrius 4.8.4, per-module `lib/libro_*.cyr` +
  `lib/bote_*.cyr` pulls. Rewritten around the verified one-block
  manifest; `registry_new()` → `tool_registry_new()`; every cited
  symbol checked against `dist/t-ron.cyr` / `lib/bote-core.cyr`.
- **`README.md`** carried the same non-compiling
  `include "lib/bote_dispatch.cyr"`, a 2.1.2 version badge, a
  "2.1.0 — modernization arc opens" headline, and 5.10.34-era pins.
  Refreshed throughout, including an honest note on why the binary
  grew 1.12 MB → 2.93 MB (the deliberate full-sigil pin).
- **`CONTRIBUTING.md`** told contributors `.cyrius-toolchain` "is kept
  as a local-dev convenience" — that file was retired at 2.1.3 and
  does not exist.
- **`CLAUDE.md`** stated a 390-assertion floor (312+30+48); the real
  floor has been **401** (323+30+48) since 2.1.4.
- **`DEPS-PATTERN.md`** — the consumer contract — documented the
  *broken* `[deps.bote]` pattern this release fixes, so it was
  actively teaching the defect. Rewritten.

⭐ **The pattern behind all of it:** these rows were assessed by
reading, and a stale include list reads fine. `docs/doc-health.md`
now carries the rule that an executable doc may only be marked Fresh
if it was **built and run** in that pass, and a table of what the
ledger previously got wrong.

### Notes — ⚠️ consumer advisory: libro 2.8.11 changes every entry hash

libro **2.8.11** is a **breaking data-format change**: four fixes alter the
entry-hash preimage, so **a chain written by libro ≤ 2.8.10 will not verify
against 2.8.12**, and proofs, anchors and tree-head signatures over it will
not either. The most serious of the four was a forgery primitive — the
canonical-JSON hasher silently dropped unrecognized bytes, so `{"a":1}` and
`{approved_by_legal"a":1}` hashed identically with `verify_chain` returning
clean. `details` is exactly the field t-ron fills from caller data via
`audit_log`.

**t-ron's code needs no change** — it calls only six high-level libro
functions (`chain_new` / `chain_append` / `chain_append_with_agent` /
`chain_len` / `chain_verify` / `chain_review`) and does no raw-offset reads
of libro's structs, so the 2.8.11 `struct error` field *prepend* that bote
3.3.4 flagged does not reach us either.

**Impact assessment: none known.** t-ron has no production consumer
carrying a live audit chain at 2.1.9, so nothing needs re-anchoring and
this rides as a routine patch rather than a coordinated migration. The
requirement still stands for anyone who *does* hold a chain from an
older build — re-export and re-anchor before upgrading; there is no
migration path, because the old preimage was unsound. Worth revisiting
the moment a consumer starts persisting chains.

## [2.1.8] — 2026-07-17 · cyrius 6.4.66 + libro 2.8.2 / bote 3.1.4 / sigil 3.12.1 refresh + `[deps.sigil]` first-party pin

Ninth patch of the **2.1.x modernization arc** — the consumer step of the
ecosystem's cyrius **6.4.66** sweep (sakshi 2.4.6 → sigil 3.12.1 → majra 2.5.1
→ libro 2.8.2 → bote 3.1.4 → daimon 1.4.3 → **t-ron 2.1.8**). Toolchain pin +
dependency refresh, plus a new first-party `[deps.sigil]` pin that insulates
t-ron's dist sidecar from libro's transitive sigil-thinning. No t-ron runtime
*logic* changed — all **401 assertions** (t-ron 323 · crypto 30 · safety 48)
pass on the new stack; benches flat-to-faster.

### Changed

- **Toolchain**: pinned to cyrius **6.4.66** (was 6.3.15). The wrapper had
  already rolled forward locally, leaving the 6.3.15-vintage `lib/` snapshot
  stale enough that every binary failed to link with `undefined function
  'thread_local_alloc'` — the 6.4.65 thread-local **slot allocator** that
  sigil 3.12.x's `crypto_scratch` (`cbank()`) and patra 1.12.x's TLS slots
  now call. `rm -rf ./lib && cyrius deps` re-vendored the snapshot (which
  carries `thread_local_alloc` in `lib/thread_local.cyr`) and cleared the
  drift.
- **Dependencies**: libro **2.8.2** (was 2.7.9), bote-core **3.1.4** (was
  2.7.7 — a MAJOR bump that is fully additive on the 2.0 handler ABI
  `fn h(args, claims)`; the `dist/bote-core.cyr` core profile grew 9 → 11
  modules with `prompts` / `resources`, all transport-free surface t-ron
  does not wire). sigil **3.12.1**, sakshi **2.4.6** (transitive via bote's
  `[deps.sakshi]`), patra **1.12.12** / majra **2.5.1** transitive.
- **New `[deps.sigil]` first-party pin — `dist/sigil.cyr` @ 3.12.1.** Before
  2.1.8 t-ron inherited sigil *only transitively* via libro's `[deps.sigil]`.
  libro 2.8.0 **thinned** its transitive sigil surface to the
  `sigil-mldsa` + `sha_ni` + `sha256` + `hex` folds — whose multi-module
  basenames do **not** match the dep name `sigil`, so `cyrius distlib` would
  mis-declare each fold (`sigil-mldsa`, `sigil_sha256`, …) as a required
  *stdlib* leaf in `dist/t-ron.deps`, and every downstream `cyrius deps`
  would error `dep t-ron requires 'sigil-mldsa' but it is not in the cyrius
  stdlib`. Pinning the full `dist/sigil.cyr` bundle directly (basename
  `sigil` ↔ dep `sigil`) keeps it recognized as a named dep and **excluded
  from the sidecar** — `dist/t-ron.deps` is byte-identical to 2.1.7. Mirrors
  **daimon 1.4.3 / bote 3.1.4**, which both keep the full bundle. The x509 /
  RSA bignum tables t-ron never calls are accepted bloat for now
  (`code_size` ~118 %); thinning is a future ecosystem-wide step.
- **`scripts/bench-history.sh` parser rewritten (float-aware).** cyrius 6.4.x
  emits sub-µs bench precision with **decimal** units (`3.569us`,
  `33.302us`); the pre-6.4 integer-only sed/bash parser silently dumped raw
  bench lines into the CSV's numeric columns. Replaced with a float-aware
  `awk` pass (`to_ns` handles `ns`/`us`/`ms`/`s` decimals); five polluted
  rows removed from `bench-history.csv`.

### Notes

- **Bare `ERR_*` → prefixed enums, ecosystem-wide.** t-ron's own error enum
  has been fully `TRON_ERR_*` since the Cyrius port — **zero bare `ERR_*` in
  `src/` or `tests/`**, so no t-ron-side migration was required. This
  release banks the **reciprocal** rename in the dependency bundles: libro
  2.8.2 namespaced `LibroErr` → `LIBRO_ERR_*` and bote 3.1.4 namespaced
  `BoteErrTag` → `BOTE_ERR_*` (verified: `dist/libro.cyr`,
  `dist/bote-core.cyr`, `dist/sigil.cyr` all carry **0 bare `ERR_`**),
  resolving the historic `duplicate symbol 'ERR_IO' / 'ERR_JSON'` hazard
  (bote-core vs libro) **at the source** rather than by include-order luck.
- **Capacity** (`CYRIUS_STATS=1`): `fn_table` **3866 / 8192** (47 %),
  `identifiers` **114767 / 262144** (44 %) — both well under the 95 % CI
  gate; `code_size` **~118 %** over the 1 MB watermark (the full sigil
  bundle; daimon 1.4.3 runs 173 % on the same bundle, so this is the
  accepted ecosystem state, not a t-ron regression). The upstream
  compile-source-size cap raise remains the preferred response path.
- **Benches flat-to-faster** vs the 2.1.7 baseline (6.4.66 sub-µs
  precision + codegen): `policy_check` 655 ns (was ~1 µs),
  `scanner_sql_detect` 1.39 µs (was ~2 µs), `audit_log` 10.4 µs (was
  ~15 µs), `tron_check_allow` 13.0 µs (was ~19 µs).
- **Benign cross-module `duplicate fn` warnings** unchanged from 2.1.7:
  `chacha20_xor` (sigil ships one; t-ron's tested `src/crypto_chacha20.cyr`
  wins), `circuit_breaker_new` (majra vs t-ron's `src/safety.cyr`), and the
  sigil ML-DSA internal duplicates — all "last definition wins".

## [2.1.7] — 2026-06-30 · cyrius 6.3.15 base-stack migration + 6.3.x dep-sidecar reconciliation

Tier-4 (consumer) step of the coordinated base-security-stack migration
to cyrius **6.3.15** (sakshi 2.4.3 → sigil 3.9.8 → majra 2.5.0 → libro
2.7.9 → bote 2.7.7 → **t-ron 2.1.7**). Toolchain pin + dependency refresh
plus the stdlib boundary reconciliation the 6.3.x line requires. No t-ron
runtime *logic* changed — all 401 assertions (t-ron 323 · crypto 30 ·
safety 48) pass on the new stack.

### Changed

- **Toolchain**: pinned to cyrius **6.3.15** (was 6.2.11).
- **Dependencies**: libro **2.7.9** (was 2.7.4), bote-core **2.7.7**
  (was 2.7.6).
- **`[deps] stdlib`**: added `sakshi`, `fs`, `process` (libro's dist
  bundle carries a `.deps` sidecar on 6.3.x that declares these as
  required consumer-scope stdlib leaves — the file-backed chain +
  subprocess-audit paths; on 6.2.x they were folded inside libro's own
  bundle) and `sync` (patra 1.12.7's transitive `lib/sync.cyr`
  requirement via libro). `src/main.cyr` now includes `lib/fs.cyr` +
  `lib/process.cyr` before the sigil/libro includes (single-pass).

### Notes

- **CYML gotcha (documented for the next migrator)**: a `#` comment
  placed *inside* the `stdlib = [...]` array must not contain a
  double-quoted string — the CYML parser extracts any `"…"` token in the
  array region as a module name, even inside a comment, yielding a bogus
  "cannot read ./lib/<…>.cyr" during `cyrius deps`.

## [2.1.6] — 2026-06-15 · cyrius 6.2.11 (first move onto the 6.2.x line) + libro 2.7.4 + bote 2.7.6 + the `bayan` stdlib carve

Seventh patch of the **2.1.x modernization arc** — a toolchain +
dependency refresh that steps onto the **6.2.x maintenance line** and
finally migrates t-ron onto the **`bayan` consolidated-stdlib carve**
(cyrius 6.1.25) that libro 2.7.3 / bote 2.7.4 already absorbed. The
JSON-RPC boundary and the SecurityGate dispatcher signature are
untouched; 2.2.x stays reserved for a wire-shape change, not a
toolchain bump. Mirrors **bote 2.7.6**, the reference consumer for the
6.2.x sweep.

All **401 assertions** (323 + 30 + 48 — up from the 390 floor; the main
suite gained 11 as the repaired dispatcher path now compiles) pass
exit-0 on the new stack; all 5 benchmarks run clean and within run-to-run
noise of 2.1.5; `dist/t-ron.cyr` regenerated at v2.1.6.

### Changed

- **Cyrius pin `6.1.24` → `6.2.11`** (`cyrius.cyml [package].cyrius`).
  First step onto the 6.2.x line; the installed toolchain was already
  6.2.11, so this aligns the manifest pin and clears the drift warning.
- **Dependencies bumped to current tags:**
  - **libro `2.7.2` → `2.7.4`** (`[deps.libro]` `dist/libro.cyr`) —
    toolchain refresh; bundle body byte-identical apart from the version
    header.
  - **bote `2.7.3` → `2.7.6`** (`[deps.bote]` `dist/bote-core.cyr`
    opt-in core profile, unchanged shape).
  - Transitive pins advance: **sigil 3.7.8 → 3.7.14**, **patra 1.11.0 →
    1.11.2**, **agnosys 1.4.1 → 1.4.3**, **majra 2.4.5 → 2.4.7**.
- **`cyrius.lock` now records 47 hashes** (was 48) — the `bayan` carve
  folds three standalone stdlib entries (`json` / `base64` / `bigint`)
  into one. `cyrius deps --verify` passes (47 verified, 0 failed),
  reproducible from an empty `./lib`.

### Breaking (internal — test harness only, no consumer-facing API change)

- **`registry_new()` → `tool_registry_new()`** in `tests/t-ron.tcyr`.
  bote 2.7.4 renamed its `ToolRegistry` constructor to resolve a
  symbol collision with ai-hwaccel's `registry_new`; t-ron's test gate
  builder is the only caller. The dist bundle and the JSON-RPC surface
  are unaffected — t-ron exports no `registry_*` symbol.

### Fixed

- **`bayan` stdlib carve migration (build-breaking on 6.2.11).** The
  6.1.x toolchain consolidated the standalone `json` / `base64` /
  `bigint` stdlib modules into one bundled **`bayan`** dist; the
  individual modules no longer ship in the 6.1.35+ snapshot, so
  `cyrius deps` against 6.2.11 errors on the retired names. Migrated
  `[deps] stdlib` (`json` + `base64` + `bigint` → `bayan`) and every
  `include "lib/{json,base64,bigint}.cyr"` → `include "lib/bayan.cyr"`
  across `src/main.cyr` and all four test/bench harnesses. **No
  call-site changes** — t-ron makes zero direct `json_*` / `base64_*` /
  `bigint_*` stdlib calls (its base64/JSON heuristics in
  `src/safety.cyr` / `src/llm_scan.cyr` are hand-rolled); `bayan` is
  pulled transitively for libro's canonical-JSON hashing and sigil.
  Mirrors libro 2.7.3 / bote 2.7.4's carve.
- **Stale test/bench harnesses repaired (latent — they did not compile
  against the post-2.1.3 deps).** `tests/t-ron.tcyr`,
  `tests/t-ron-crypto.tcyr` and `tests/t-ron.bcyr` still `include`d
  `src/_libro_compat.cyr` (the ct_eq shim retired at 2.1.3) and the
  nine per-module `lib/bote_*.cyr` files (replaced by the
  `dist/bote-core.cyr` bundle at 2.1.3) — neither exists under the
  current deps profile, so `cyrius test` failed at the first missing
  include. Dropped `_libro_compat`, swapped the per-module bote
  cherry-pick for `lib/bote-core.cyr`, and re-aligned every harness's
  lib-include block to `src/main.cyr`'s proven ordering.
- **sigil 3.7.14 TLS-path SIGILL landmine in the bench harness
  (CI-breaking, would only surface when *run*).** `tests/t-ron.bcyr`
  included `lib/sigil.cyr` ahead of `lib/ct.cyr` and with **no**
  `lib/thread_local.cyr` / `lib/keccak.cyr` / `lib/random.cyr` at all.
  sigil 3.7.14's `crypto_scratch` exercises the thread-local-storage
  path older sigils never hit, so the bench would link clean but
  **SIGILL at first crypto use (exit 132)** — a build-only check misses
  it. Added the `atomic` / `thread` / `thread_local` + `ct` / `keccak`
  / `random` prelude ahead of `sigil` in the bench (and the matching
  `ct`/`keccak`/`random` prelude to the crypto and safety suites). All
  harnesses now run exit-0. This is the exact failure mode libro 2.7.4
  / bote 2.7.6 document.

### Notes

- **New benign 6.2.11 linker diagnostics.** The 6.2.11 linker now warns
  on duplicate global symbols from the bundled deps —
  `duplicate symbol 'ERR_IO' / 'ERR_JSON'` (`lib/bote-core.cyr`,
  `lib/sigil.cyr`, `lib/agnosys.cyr`) and `duplicate fn '_sub_new'`
  (`lib/majra.cyr`). Pre-existing name collisions between the bundles'
  error enums; harmless (last-definition-wins, all 401 assertions pass),
  simply silent before 6.2.11 began diagnosing them. Not a t-ron
  regression. Matches the note in libro 2.7.4 / bote 2.7.6.

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
