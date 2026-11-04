---
name: t-ron Documentation Health
description: Living state of doc currency in the t-ron repo — fresh / stale / archived / read-through-outstanding, refreshed as docs are touched
type: state
---

# Documentation Health — t-ron

> **Last refresh**: 2026-11-03 (2.2.3 release — the P(-1) sweep; [audit report](audit/2026-11-03.md)). The documentation audit (P(-1) step 9) ran over every doc: `architecture/overview.md` and `development/threat-model.md` were rewritten from `src/` (both still described the Rust port), the integration guide's §3–§7 were rewritten as one program built and run as a clean-room consumer, three ADRs gained amendments, and `sources.md` and `benchmarks-rust-v-cyrius.md` were brought current. No doc is stale or outstanding after this pass. | **Refresh cadence**: when docs are touched, update the affected row.
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

## At a glance — 2026-11-03 inventory (2.2.3)

**23 markdown files** (7 root + 16 under `docs/`), plus 4 runnable
`.cyr` examples.

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — verified in the 2.2.3 pass** | 21 | CHANGELOG, README, CLAUDE.md, DEPS-PATTERN.md, CONTRIBUTING, roadmap, threat model, overview, doc-health (this file), integration and testing guides, examples/README, sources, benchmarks-rust-v-cyrius, 6 ADRs, the new audit report — plus all 4 `.cyr` examples, **built + run on 6.7.18** |
| 🔵 **No version-tied claims** | 3 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE` |
| 📦 **Date-stamped historical record** | 1 | `docs/audit/2026-04-14.md` |
---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-11-03 | ✅ Fresh | **2.2.3**: badge, headline (the audit and its upgrade note), Rust-vs-Cyrius column (684 KB / 222 ns / 17.3 µs; `src/` 6 862 lines), the four suites with their counts, benchmark table (scanner −89 % / −68 %), roadmap highlights → 2.2.4 next. Earlier passes: see the CHANGELOG entries |
| `CHANGELOG.md` | 2026-11-03 | ✅ Fresh | 2.2.3 entry: the three criticals and the high items, every behaviour change callers will see, hygiene (CI gates, new suite, double lookups, `fs`, raw syscalls), the doc rewrites, performance with attribution, verification, and the deferred list; points at the audit report for the full table |
| `CLAUDE.md` | 2026-11-03 | ✅ Fresh | 2.2.3: pin and re-verified lines → 2.2.3; the P(-1) test sweep names the fourth suite; assertion floor 426 → **847 (386 + 64 + 205 + 192)** |
| `CONTRIBUTING.md` | 2026-11-03 | ✅ Fresh | 2.2.3: pin line; the command table and pre-PR list name all four suites with their counts |
| `SECURITY.md` | 2026-04-14 | 🔵 No version-tied claims | Reporting policy + scope |
| `CODE_OF_CONDUCT.md` | 2026-04-14 | 🔵 No version-tied claims | Standard |
| `DEPS-PATTERN.md` | 2026-11-03 | ✅ Fresh | 2.2.3: tag → 2.2.3; sidecar unchanged (`regex net syscalls`). Consumer floor cyrius ≥ 6.7.2 (measured at 2.2.0 and 2.2.1) |
| `VERSION` | 2026-11-03 | ✅ Fresh | `2.2.3` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}` |
| `LICENSE` | (initial commit) | 🔵 No version-tied claims | GPL-3.0-only |

---

## Tier 2 — Project state (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-11-03 | ✅ Fresh | 2.2.3: Current pointer; a 2.2.3 Shipped row; the scheduled 2.2.3 table replaced by **2.2.4 — audit follow-ups (proposed)** and the two items that need a minor (pattern-detector redesign, export envelope v2). 2.2.2: reorganized (versions, 2.3.x+ lines, re-checked blockers) |
| `threat-model.md` | 2026-11-03 | ✅ Fresh | **Rewritten at 2.2.3** from `src/`: it still cited `toml::from_str`, the `regex` crate, `cargo-deny` and "zero `unsafe` blocks". Trust boundaries, an attack-surface table with each mitigation and the release that added it, known limitations (F10, unbounded per-agent state, the never-freed allocation, the export envelope, Linux-only SIGHUP), memory-safety discipline, supply chain |

---

## Tier 3 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-11-03 | ✅ Fresh | **Rewritten at 2.2.3** from `src/`: it claimed `RwLock` / `DashMap` / `tokio` thread safety and listed 11 of the modules. Now: all 19 modules in bundle order, design principles, data flow, the real `tron_check` steps (0–6, pending flags), a Concurrency section stating t-ron is single-threaded and naming its process-wide state, integration points |

---

## Tier 4 — ADRs (`docs/architecture/adr-*.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `adr-001-dual-audit.md` | 2026-04-14 | ✅ Fresh | Accepted. Ring buffer + libro chain duality. Holds |
| `adr-002-default-deny.md` | 2026-11-03 | ✅ Fresh | Accepted. **2.2.3 amendment**: `DA_FLAG` no longer skips later checks; the sample is Cyrius, not Rust; an unknown `DefaultAction` denies |
| `adr-003-bote-middleware.md` | 2026-04-14 | ✅ Fresh | Accepted. SecurityGate wraps bote Dispatcher. Carries unchanged through bote-core 3.8.1 — the middleware suite passes against it (MAJOR bumps were additive on the 2.0 handler ABI) |
| `adr-004-cyrius-port.md` | 2026-04-14 | ✅ Fresh | Accepted. Historical decision, holds |
| `adr-005-chacha20-ed25519-aead.md` | 2026-11-03 | ✅ Fresh | Accepted. **2.2.3 amendment**: what the audit confirmed and fixed (double sign, ignored sign result, wiping, nonce 0), and the three gaps that keep it short of a full AEAD (key binding, domain separation, replay) |
| `adr-006-safety-submodule.md` | 2026-11-03 | ✅ Fresh | Accepted. **2.2.3 amendment**: fail closed everywhere, strongest verdict wins, destructive-command detectors, scope normalisation, action-type filters, bounded memory; what stays open |

**ADR posture today**: low decision-velocity. A 2.2.x amendment to
ADR-003 may add a "claims-aware authorization" subsection.

---

## Tier 5 — Audit reports (`docs/audit/`)

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-04-14.md` | 2026-04-14 | 📦 Historical record | 2.0.0 P(-1) audit; 10 CVE-class fixes |
| `2026-11-03.md` | 2026-11-03 | ✅ Fresh | **2.2.3 P(-1) audit.** Four independent reviews; 74 items, one row each with status and guard test; behaviour changes; verification; deferred items with proposed placement |

The next full audit follows CLAUDE.md's P(-1) process at the next minor cut.

---

## Tier 6 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `integration.md` | 2026-11-03 | ✅ Fresh | **2.2.3: §3–§7 rewritten** as one program built against `dist/t-ron.cyr` in a clean-room project and run; every JSON line it quotes matches that run byte for byte. Documents signed mode, the strict loader, decoded tool names, single-threaded use, `sighup_init` before threads; §5–§6 no longer include `src/` files; §2 drops `fs`. The whole guide is now verified |
| `testing.md` | 2026-11-03 | ✅ Fresh | 2.2.3: four suites, **847 assertions across 225 groups**, the suite table, and the rule that a security regression test must fail against the pre-fix code |

---

## Tier 7 — Examples (`docs/examples/`)

All four rebuilt and re-run on **6.7.18** in the 2.2.3 pass, with
**zero undefined symbols and zero duplicate definitions**; none needed
a change (none registers t-ron's tool definitions). At 2.1.11, 01 and 02 needed a fix: they include
`src/audit.cyr` without `src/crypto_chacha20.cyr`, so after 2.1.10's
`chacha20_xor` → `cc20_xor` rename both built with `undefined function
'cc20_xor'` and passed only because neither reaches the export path.
(2.1.9 had rebuilt all four after they failed on the retired
`bigint` / `json` / `base64` and `_libro_compat` includes.)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `01-minimal-gate.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18: `web-agent tarang_probe -> allow`, unknown agent `-> deny`. Now includes `src/crypto_chacha20.cyr` |
| `02-signed-policy.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18: Ed25519 signed policy loaded and enforced. Now includes `src/crypto_chacha20.cyr` |
| `03-audit-export.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18: ChaCha20 + Ed25519 AEAD round-trip, 456-byte envelope |
| `04-safety-check.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18: `ls -la /tmp` allowed, `rm -rf /` blocked |
| `README.md` | 2026-09-23 | ✅ Fresh | Examples index. 2.1.11: the build note still named `cyrius.toml`; now `cyrius.cyml` |

---

## Tier 8 — Sources / benchmarks (`docs/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-11-03 | ✅ Fresh | 2.2.3: RFC 8439 (obsoletes 7539) with the counter limit; RFC 8259 §7 for `json_text`; libro's UUID now from `random_bytes`; the export described as encrypt-then-sign with its gaps; TOML described as the strict subset |
| `benchmarks-rust-v-cyrius.md` | 2026-11-03 | ✅ Fresh | 2.2.3: a 2.2.3 column beside the 2.0.0 history (timings, binary, `src/` lines), with a warning that it was not measured alongside the Rust run. It no longer contradicts README |

---

## Open strategic questions

None open at the 2.2.3 cut. The three carried since 2.1.x (the two
read-through rows, the benchmark doc contradicting README, and the
integration guide's unverified §3–§7) were closed by 2.2.3's
documentation audit.

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

*Last refresh: 2026-11-03 (2.2.3 release — the P(-1) sweep and its
documentation audit; every doc fresh, every executable doc rebuilt and
re-run on 6.7.18.)
Refresh in place when docs are touched.*
