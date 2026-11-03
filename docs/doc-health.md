---
name: t-ron Documentation Health
description: Living state of doc currency in the t-ron repo — fresh / stale / archived / read-through-outstanding, refreshed as docs are touched
type: state
---

# Documentation Health — t-ron

> **Last refresh**: 2026-11-03 (2.1.12 release — cyrius 6.6.6 → 6.6.20; libro 2.10.3 → 2.10.8, bote-core 3.3.13 → 3.3.17, sigil 3.12.18 → 3.13.10; majra 2.9.3 / patra 1.15.2 transitive). Every version-tied row re-checked, and every executable doc rebuilt and re-run on 6.6.20: all four examples pass, and the integration guide's §1–§2 sample passes clean-room. Two claims were re-scoped rather than carried: the README / `cyrius.cyml` reason for `[deps.sigil]` (the 2.1.11 "233 duplicates" no longer reproduces), and the guide's §3 warning (not re-tested this pass, so it now says so). | **Refresh cadence**: when docs are touched, update the affected row.
> **Scope**: This repo only (`t-ron`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree. Cross-repo dep pin drift lives in CHANGELOG entries and the [roadmap](development/roadmap.md), not here.

This is a **ledger**, not a one-time audit. Rewrite-in-place as
docs change. t-ron is an MCP security monitor consumed by daimon,
bote middleware, and phylax — stale API / threat-model / safety-
policy docs propagate downstream, so doc currency carries weight.

Pattern lifted from the libro ledger ([`libro/docs/doc-health.md`](https://github.com/MacCracken/libro/blob/main/docs/doc-health.md))
— same buckets, t-ron-shaped tiers.

---

## ⛔ What this ledger got wrong last time

Recording it, because the failure mode is the interesting part: **a
doc can be marked ✅ Fresh and still not compile.** Three rows were
wrong at 2.1.8, and none of the errors were visible by reading:

| Row | Claimed | Actually |
|---|---|---|
| `docs/examples/*.cyr` (×4) | "✅ Fresh — Builds + runs clean" | **All four failed to build.** They still included `lib/bigint.cyr` / `lib/json.cyr` / `lib/base64.cyr` (folded into `bayan` at the 2.1.6 carve) and `src/_libro_compat.cyr` (retired at 2.1.3). Latent since 2.1.6 |
| `docs/guides/testing.md` | "🟡 Stale — refresh the cyrius pin reference" | **Entirely Rust-era** — `cargo test`, `make clippy`, `serde` round-trips. Not a pin refresh; a full rewrite |
| `docs/guides/integration.md` | "🟡 Stale — verify code samples build" | **Non-compiling** — `cyrius.toml`, cyrius 4.8.4, per-module `lib/libro_*.cyr` + `lib/bote_*.cyr` pulls |

The common cause: rows were assessed by **reading** the doc, and a
stale include list reads perfectly fine. The 2.1.6 CHANGELOG had
already recorded exactly this for the *test harnesses* ("latent — they
did not compile post-2.1.3") without anyone checking whether the
examples shared the defect. They did.

**Rule adopted at 2.1.9: a row for an executable doc may only be
marked ✅ Fresh if it was built and run in that pass.** All four
examples now are — see Tier 7.

---

## At a glance — 2026-11-03 inventory

**23 markdown files** (7 root + 16 under `docs/`), plus 4 runnable
`.cyr` examples.

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — verified in the 2.1.12 pass** | 15 | CHANGELOG, README, CLAUDE.md, DEPS-PATTERN.md, CONTRIBUTING, roadmap, doc-health (this file), testing guide, examples/README, 6 ADRs — plus all 4 `.cyr` examples, **built + run on 6.6.20** — see tiers |
| 🟠 **Read-through outstanding** | 2 | `docs/architecture/overview.md`, `docs/development/threat-model.md` — both 2026-04-14 vintage, neither verified this pass |
| 🔵 **No version-tied claims** | 3 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE` |
| 🟡 **Stale** | 2 | `docs/benchmarks-rust-v-cyrius.md` — 2.0.0 baseline; README carries current numbers, this file does not. `docs/guides/integration.md` — §1–§2 verified at 2.1.12; §3 did not compile at 2.1.11 and was not re-tested |
| 📦 **Date-stamped historical record** | 1 | `docs/audit/2026-04-14.md` |

---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-11-03 | ✅ Fresh | **2.1.12**: badge, headline callout, Rust-vs-Cyrius column (2.24 MB / 329 ns / 17.2 µs, ~87× smaller), benchmark table (6.6.20, same-session 2.1.11 baseline, with the `policy_check` attribution), roadmap highlights and dep reference table re-pinned; the binary-size paragraph's sigil rationale updated — the 2.1.11 "compiles beside the full copy as duplicates" no longer holds at 6.6.20. **2.1.11**: badge, headline callout, Rust-vs-Cyrius column (2.66 MB / 288 ns / 16.4 µs), benchmark table (6.6.6, same-session 2.1.10 baseline), roadmap highlights and dep reference table re-pinned; the binary-size paragraph's sigil rationale corrected to the current one (one sigil in the build, `verify_data()`), not the stale 2.1.8 sidecar reason. **2.1.9 rewrite of every version-tied claim** — badge 2.1.2 → 2.1.9; headline callout replaced (was still "2.1.0 modernization arc opens"); **fixed a non-compiling include sample** that showed the retired per-module `lib/bote_dispatch.cyr`; assertion count 312 → 323; binary 1.12 MB → 2.93 MB with an explicit note on *why* it grew (full sigil bundle, deliberate); perf table refreshed to 6.5.35 numbers with a same-session-baseline caveat; Rust-vs-Cyrius column moved to 2.1.9 with a measurement-conditions warning; dep reference table re-pinned. Carries the libro 2.8.11 re-anchor advisory |
| `CHANGELOG.md` | 2026-11-03 | ✅ Fresh | 2.1.12 entry: pins, the `path` retirement, the sigil-first reorder (with the refusal warning, its cause and a perf-neutral A/B), the re-derived `[deps.sigil]` rationale, the retired array-comment rule (probed), the 29 → 3 sidecar with consumer impact, lock 76 → 60 with five commit pins checked against the remote tags, same-session benches with a file-swap attribution of the `policy_check` regression, verification, and upstream-only notes. 2.1.11 entry: pins, the `[deps.majra]` retirement (with the refusal-warning cause and the dead-code binary delta), the `cyrius.cyml` manifest rewrite and the two stale rationales it corrected, the `sys` sidecar leaf, lock format + commit-pin note, same-session benches with a libro A/B attribution, the two doc fixes, and the upstream-only warnings. 2.1.9 entry: the `bote-core` sidecar fix (with the reproduced consumer error), toolchain + dep refresh, the capacity cap raise, cleared warnings, benchmark table with an explicit note on why `audit_log` / `tron_check_allow` look like regressions against the 2.1.8 row and are not, and the libro 2.8.11 consumer advisory |
| `CLAUDE.md` | 2026-11-03 | ✅ Fresh | 2.1.12: pin 6.6.6 → 6.6.20; the consumer-resolution sentence updated for the 3-leaf compile-verified sidecar (consumers list stdlib modules their own code calls); re-verified with a clean-room consumer. 2.1.11: pin 6.5.35 → 6.6.6; the consumer-resolution sentence corrected — `sakshi` is a stdlib leaf from the sidecar, not a named dep, and majra / patra arrive through bote / libro; re-verified with a clean-room consumer. 2.1.9: pin 5.10.44 → 6.5.35; assertion floor 390 (312+30+48) → **401 (323+30+48)** — the old figure had been stale since 2.1.4; new **"Dep-name ↔ module-basename rule"** section under Consumers documenting the sidecar hazard and the "validate against stdlib, not last release" rule; Consumers block notes the 6.5.x single-block manifest |
| `CONTRIBUTING.md` | 2026-11-03 | ✅ Fresh | 2.1.12: pin line 6.6.6 → 6.6.20. 2.1.11: pin line 6.5.35 → 6.6.6 (it had missed the 2.1.10 bump). Cyrius-era rewrite holds, but the 2.1.9 pass found two stale claims: the pin read `cyrius = "5.10.34"`, and Prerequisites described `.cyrius-toolchain` as "kept as a local-dev convenience" — that file was **retired at 2.1.3** and is not in the tree, so the instruction pointed at nothing. Both fixed; assertion count 312 → 323 |
| `SECURITY.md` | 2026-04-14 | 🔵 No version-tied claims | Reporting policy + scope |
| `CODE_OF_CONDUCT.md` | 2026-04-14 | 🔵 No version-tied claims | Standard |
| `DEPS-PATTERN.md` | 2026-11-03 | ✅ Fresh | 2.1.12: consumer example tag → 2.1.12 and **re-verified clean-room** on 6.6.20 (6 deps resolved, five commit-pinned, `deny`); the sidecar description updated for 6.6.18's compile-verified leaves and the `# Requires` block, plus a consumer-impact note for the 29 → 3 shrink. 2.1.11: consumer example tag → 2.1.11 and **re-verified clean-room** on 6.6.6 (6 deps resolved, `deny`); the resolved-dep list corrected (`sakshi` comes from the sidecar; majra / patra are transitive). 2.1.9: **Substantially rewritten.** The old minimal-consumer snippet taught the *broken* `[deps.bote]` + `dist/bote-core.cyr` pattern and still listed `bigint` / `json` / `base64`. Replaced with the verified 6.5.x contract (**one `[deps.t-ron]` block suffices**; sidecar resolves the rest), plus a new section on the basename ↔ dep-name rule, the exact downstream error, and why the 2.1.8 "byte-identical" check could not catch it |
| `VERSION` | 2026-11-03 | ✅ Fresh | `2.1.12` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}` |
| `LICENSE` | (initial commit) | 🔵 No version-tied claims | GPL-3.0-only |

---

## Tier 2 — Project state (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-11-03 | ✅ Fresh | 2.1.12 rows in both tables; **Current** pointer rebuilt; a status line on the cyrius 6.7.6 note (no `path` lines left for it to override); new Cyrius-deps row for the `refusing to overwrite stdlib leaf` mechanism, which has now bitten twice. 2.1.11 rows in both tables; **Current** pointer rebuilt — it had still read 2.1.9 through the 2.1.10 release. 2.1.9: rows in both tables; **Current** pointer rebuilt (pins, capacity, the sidecar fix); **`code_size` watching row CLOSED** — cyrius 6.5.35's 64 MB cap is response path (1), so paths (2)/(3) are moot; the `dist/bote.cyr` Future row marked unblocked-but-still-not-recommended (bote-core verified to carry zero `sandhi_` refs); **retired the stale "cyrius 5.11.x toolchain bump" 2.2.x trigger** and the cut-line prose that named it; new Cyrius-deps row for the sidecar basename rule |
| `threat-model.md` | 2026-04-14 | 🟠 Read-through outstanding | Not verified this pass. Still wants the note that audit-tool authorization (gating `tron_audit` / `tron_policy` on caller identity) is a 2.2.x candidate. **Also now wants a libro 2.8.11 note**: the canonical-JSON hasher previously accepted junk bytes inside `details`, a forgery primitive on a field t-ron fills from caller data — fixed upstream, but the threat model should say so |

---

## Tier 3 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-04-14 | 🟠 Read-through outstanding | Not verified this pass. Module map is believed to still match `src/` (18 `[lib]` modules, unchanged since 2.1.3), but "believed" is exactly the posture that produced the errors above — treat as unverified until someone diffs it against `src/`. Bote 2.0 handler-ABI prose should reference the 2.1.0 plumbing |

---

## Tier 4 — ADRs (`docs/architecture/adr-*.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `adr-001-dual-audit.md` | 2026-04-14 | ✅ Fresh | Accepted. Ring buffer + libro chain duality. Holds |
| `adr-002-default-deny.md` | 2026-04-14 | ✅ Fresh | Accepted. Deny-wins-over-allow. Verified live this pass — the 2.1.12 clean-room consumer probe got `deny` for an unregistered agent |
| `adr-003-bote-middleware.md` | 2026-04-14 | ✅ Fresh | Accepted. SecurityGate wraps bote Dispatcher. Carries unchanged through bote-core 3.3.17 — the middleware suite passes against it (MAJOR bumps were additive on the 2.0 handler ABI) |
| `adr-004-cyrius-port.md` | 2026-04-14 | ✅ Fresh | Accepted. Historical decision, holds |
| `adr-005-chacha20-ed25519-aead.md` | 2026-04-14 | ✅ Fresh | Accepted. Verified live this pass (6.6.20) — example 03 round-trips a 456-byte envelope |
| `adr-006-safety-submodule.md` | 2026-04-14 | ✅ Fresh | Accepted. Verified live this pass (6.6.20) — example 04 blocks `rm -rf /` |

**ADR posture today**: low decision-velocity. A 2.2.x amendment to
ADR-003 may add a "claims-aware authorization" subsection.

---

## Tier 5 — Audit reports (`docs/audit/`)

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-04-14.md` | 2026-04-14 | 📦 Historical record | 2.0.0 P(-1) audit; 10 CVE-class fixes |

A 2.1.x audit will land when the modernization arc closes.

---

## Tier 6 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `integration.md` | 2026-11-03 | 🟡 Stale (§3 on) | **2.1.12: §1–§2 re-verified clean-room on 6.6.20** (6 deps resolved, `deny`); pins refreshed; a note that consumers calling stdlib directly need their own `[deps] stdlib` now that the sidecar is 3 leaves; the §2 `fs / process / sync` comment no longer claims libro's sidecar declares them (libro 2.10.7's is `hashmap` only). §3 was **not** re-tested, and its warning now says so instead of asserting a current failure. **2.1.11: §1–§2 re-verified clean-room on 6.6.6** (6 deps resolved, `deny`) after fixing their `if` — it lacked parentheses and failed with `expected '('`; pins and the resolved-dep list refreshed. **§3 does not compile**: the multi-line string passed to `tron_load_policy` is rejected (`expected ')', got string`), and its one-argument handler predates the bote 2.0 `fn h(args, claims)` ABI. A warning now sits on §3; it wants a rewrite built and run against bote-core 3.3.13 — §4–§7 are unverified with it. 2.1.9: **Sections 1–2 rewritten.** Was 2.0.0-era and non-compiling: `cyrius.toml`, cyrius 4.8.4, per-module `[deps.libro]`/`[deps.bote]` source pulls, `lib/libro_chain.cyr` + `lib/bote_dispatch.cyr` + `lib/json.cyr` includes. Now shows the verified one-block manifest, the full single-pass include order with the SIGILL and sidecar-ordering hazards called out, and a working `tron_check` sample (it takes **2** args — the old prose implied loose strings). `registry_new()` → `tool_registry_new()` (bote 2.7.4). Every cited symbol checked against `dist/t-ron.cyr` / `lib/bote-core.cyr` |
| `testing.md` | 2026-11-03 | ✅ Fresh | 2.1.12: "current for" line → 2.1.12 / 6.6.20; 323 / 30 / 48 re-checked by running all three suites. 2.1.11: "current for" line → 2.1.11 / 6.6.6; the commands and the 323 / 30 / 48 counts re-checked by running all three suites. 2.1.9: **Full rewrite — was 100 % Rust-era** (`cargo test`, `make clippy`, `cargo audit`, `serde` round-trips, `.await`). Replaced with the real three-suite Cyrius layout (323 / 30 / 48 = **401** across 144 groups), the actual `test_group` + `assert_eq` idiom, the include-order hazards that bite harnesses specifically, the latent-staleness history, and the four-part cleanliness check |

---

## Tier 7 — Examples (`docs/examples/`)

All four rebuilt and re-run on **6.6.20** in the 2.1.12 pass, with
**zero undefined symbols and zero duplicate definitions**; none needed
a change. At 2.1.11, 01 and 02 needed a fix: they include
`src/audit.cyr` without `src/crypto_chacha20.cyr`, so after 2.1.10's
`chacha20_xor` → `cc20_xor` rename both built with `undefined function
'cc20_xor'` and passed only because neither reaches the export path.
(2.1.9 had rebuilt all four after they failed on the retired
`bigint` / `json` / `base64` and `_libro_compat` includes.)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `01-minimal-gate.cyr` | 2026-09-23 | ✅ Fresh | Builds + **runs** on 6.6.20: `web-agent tarang_probe -> allow`, unknown agent `-> deny`. Now includes `src/crypto_chacha20.cyr` |
| `02-signed-policy.cyr` | 2026-09-23 | ✅ Fresh | Builds + **runs** on 6.6.20: Ed25519 signed policy loaded and enforced. Now includes `src/crypto_chacha20.cyr` |
| `03-audit-export.cyr` | 2026-08-23 | ✅ Fresh | Builds + **runs** on 6.6.20: ChaCha20 + Ed25519 AEAD round-trip, 456-byte envelope |
| `04-safety-check.cyr` | 2026-08-23 | ✅ Fresh | Builds + **runs** on 6.6.20: `ls -la /tmp` allowed, `rm -rf /` blocked |
| `README.md` | 2026-09-23 | ✅ Fresh | Examples index. 2.1.11: the build note still named `cyrius.toml`; now `cyrius.cyml` |

---

## Tier 8 — Sources / benchmarks (`docs/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-04-14 | ✅ Fresh | Algorithm + spec citations (RFC 7539, sigil API). Holds |
| `benchmarks-rust-v-cyrius.md` | 2026-04-14 | 🟡 Stale | Still the 2.0.0 baseline. README's table carries 6.6.20 numbers (2.1.12) and this file does not, so the two disagree — README is the correct one. Wants a current column and the same measurement-conditions caveat |

---

## Open strategic questions

Three open at the 2.1.12 cut:

1. **The two 🟠 read-through rows have been outstanding since
   2026-04-14** — `architecture/overview.md` and
   `development/threat-model.md`, now eight releases deep. Neither is
   *known* wrong; both are unverified, which after this pass is not a
   comfortable distinction. `threat-model.md` has also acquired
   concrete new content to absorb (the libro 2.8.11 canonical-JSON
   forgery primitive, on a field t-ron populates from caller data).
2. **`benchmarks-rust-v-cyrius.md` contradicts `README.md`** —
   README's table carries 6.6.20 numbers (2.1.12), this one still
   carries the 2.0.0 baseline. Two documents disagreeing is worse
   than one being stale; whichever is cheaper, converge them.
3. **`guides/integration.md` §3 onward needs a rewrite** — §3 did
   not compile at 2.1.11 (multi-line policy string, pre-bote-2.0
   handler signature), and §4–§7 have not been built with it. It needs
   to be written against bote-core 3.3.17 and built and run before the
   warning comes off.

This section will also repopulate when:

- A new doc category appears that doesn't fit an existing tier
  (e.g. a `docs/compliance/` directory if the L3 capability-source
  policy work lands a standards-mapping deliverable).
- The audit / review cadence shifts (current pattern: P(-1) at
  minor cuts per CLAUDE.md, last full audit at 2.0.0).
- An ADR needs to be retired or formally superseded.

---

## Refresh procedure

When docs are touched:

1. Find the affected row in the relevant tier table.
2. Update **Last touched** column to the new date.
3. Update **Status** column if the bucket changed.
4. Update **Notes** column if the next step changed.
5. If a doc moved or was archived, update its row to reflect the
   new home.
6. Re-anchor "Last refresh" date in the header.

When the bucket counts at the top drift, refresh the at-a-glance
table.

---

## What this file is NOT

- Not a substitute for [`development/roadmap.md`](development/roadmap.md)
  (which holds the forward plan).
- Not a CHANGELOG (which records what shipped, not what's stale).
- Not a per-doc review log (we record the result of an audit pass,
  not the per-doc reasoning).

---

*Last refresh: 2026-11-03 (2.1.12 release — cyrius 6.6.20 + libro
2.10.8 / bote-core 3.3.17 / sigil 3.13.10; committed `path` lines
retired; `[deps.sigil]` moved first. Every executable doc rebuilt and
re-run on 6.6.20 per the 2.1.9 rule: all four examples and the
integration guide's §1–§2 pass; §3 stays flagged, not re-tested.)
Refresh in place when docs are touched.*
