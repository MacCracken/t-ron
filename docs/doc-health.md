---
name: t-ron Documentation Health
description: Living state of doc currency in the t-ron repo — fresh / stale / archived / read-through-outstanding, refreshed as docs are touched
type: state
---

# Documentation Health — t-ron

> **Last refresh**: 2026-11-04 (2.2.4 release — bote-core 3.8.9 and four audit follow-ups). Every doc that names a version, a pin, a count or a behaviour 2.2.4 changed was updated; the integration guide's program, its §2 snippet and the four examples were rebuilt and re-run against the new code. The 2.2.3 pass's rewrites (overview, threat model, integration §3–§7) still hold. No doc is stale or outstanding. | **Refresh cadence**: when docs are touched, update the affected row.
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
| ✅ **Fresh — verified in the 2.2.3 pass, refreshed at 2.2.4** | 21 | CHANGELOG, README, CLAUDE.md, DEPS-PATTERN.md, CONTRIBUTING, roadmap, threat model, overview, doc-health (this file), integration and testing guides, examples/README, sources, benchmarks-rust-v-cyrius, 6 ADRs, the new audit report — plus all 4 `.cyr` examples, **built + run on 6.7.18 / bote-core 3.8.9** |
| 🔵 **No version-tied claims** | 3 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE` |
| 📦 **Date-stamped historical record** | 1 | `docs/audit/2026-04-14.md` |
---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-11-04 | ✅ Fresh | **2.2.4**: badge, a 2.2.4 headline above the 2.2.3 audit note (kept: it carries the upgrade advice), roadmap highlight, bote tag 3.8.9 in the reference table, and the Benchmarks table from the 2.2.4 `bench-history.csv` row. The Rust-vs-Cyrius column stays 2.2.3's, labelled as measured on 2026-11-03 |
| `CHANGELOG.md` | 2026-11-04 | ✅ Fresh | 2.2.4 entry: bote-core 3.8.9 and what its duplicate-key refusal means for the gate, P12 / C14 / S11 / S15, behaviour callers will see, the mutation results, the A/B table under load, and what stays open |
| `CLAUDE.md` | 2026-11-04 | ✅ Fresh | 2.2.4: pin and re-verified lines → 2.2.4; assertion floor **902** (407 + 64 + 239 + 192) |
| `CONTRIBUTING.md` | 2026-11-04 | ✅ Fresh | 2.2.4: pin line; the command table's per-suite counts (407 and 239 changed) |
| `SECURITY.md` | 2026-04-14 | 🔵 No version-tied claims | Reporting policy + scope |
| `CODE_OF_CONDUCT.md` | 2026-04-14 | 🔵 No version-tied claims | Standard |
| `DEPS-PATTERN.md` | 2026-11-04 | ✅ Fresh | 2.2.4: tag → 2.2.4; sidecar unchanged (`regex net syscalls`). Re-verified at 2.2.4 with a clean-room consumer (6 deps resolved; the guide's §2 snippet denies `ark_install` from an unregistered agent). Consumer floor cyrius ≥ 6.7.2 unchanged |
| `VERSION` | 2026-11-04 | ✅ Fresh | `2.2.4` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}` |
| `LICENSE` | (initial commit) | 🔵 No version-tied claims | GPL-3.0-only |

---

## Tier 2 — Project state (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-11-04 | ✅ Fresh | 2.2.4: Current pointer and capacity; a 2.2.4 Shipped row; the 2.2.4 table replaced by **Remaining patch-sized follow-ups** (D14/S16 with why a cap needs a decision, P10, and the injection detector's measured 26 µs); the description-hash blocker re-checked against bote 3.8.9's full bundle |
| `threat-model.md` | 2026-11-04 | ✅ Fresh | Rewritten at 2.2.3 from `src/`. 2.2.4: rows for a key named twice, an unterminated identifier, allocation failure, lookalike letters and ill-formed UTF-8 output; the memory-safety section says which allocations are checked |

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
| `adr-003-bote-middleware.md` | 2026-04-14 | ✅ Fresh | Accepted. SecurityGate wraps bote Dispatcher. Carries unchanged through bote-core 3.8.9 — the middleware suite passes against it (MAJOR bumps were additive on the 2.0 handler ABI) |
| `adr-004-cyrius-port.md` | 2026-04-14 | ✅ Fresh | Accepted. Historical decision, holds |
| `adr-005-chacha20-ed25519-aead.md` | 2026-11-03 | ✅ Fresh | Accepted. **2.2.3 amendment**: what the audit confirmed and fixed (double sign, ignored sign result, wiping, nonce 0), and the three gaps that keep it short of a full AEAD (key binding, domain separation, replay) |
| `adr-006-safety-submodule.md` | 2026-11-04 | ✅ Fresh | Accepted. **2.2.3 amendment**: fail closed everywhere, strongest verdict wins, destructive-command detectors, path normalisation, action filters, bounded memory. **2.2.4 amendment**: lookalike folding, `require_utf8`, the allocation-failure verdict; rate-bucket bounds still open |

**ADR posture today**: low decision-velocity. A 2.2.x amendment to
ADR-003 may add a "claims-aware authorization" subsection.

---

## Tier 5 — Audit reports (`docs/audit/`)

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-04-14.md` | 2026-04-14 | 📦 Historical record | 2.0.0 P(-1) audit; 10 CVE-class fixes |
| `2026-11-03.md` | 2026-11-04 | ✅ Fresh | **2.2.3 P(-1) audit.** Four independent reviews; 74 items, one row each with status and guarding test. 2.2.4 outcomes added to the P12, C14, S11 and S13–S18 rows, and a "Since" column on the deferred table; the findings themselves are left as written |

The next full audit follows CLAUDE.md's P(-1) process at the next minor cut.

---

## Tier 6 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `integration.md` | 2026-11-04 | ✅ Fresh | §3–§7 are one program built against `dist/t-ron.cyr` in a clean-room consumer. **Re-run at 2.2.4** on bote-core 3.8.9 (6 deps, 0 undefined, 0 warnings): the §4 and §7 outputs match byte for byte, §5's signed load and §6's SIGHUP setup return 0. Header and tag → 2.2.4 |
| `testing.md` | 2026-11-04 | ✅ Fresh | 2.2.4: **902 assertions across 231 groups**, the suite table, six benches, and a new section on testing failure paths (`ALLOC_MAX`, guard pages, the lock re-vendoring `lib/`) |

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
| `01-minimal-gate.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18 / bote-core 3.8.9 (re-run at 2.2.4): `web-agent tarang_probe -> allow`, unknown agent `-> deny` |
| `02-signed-policy.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18 / bote-core 3.8.9 (re-run at 2.2.4): Ed25519 signed policy loaded and enforced |
| `03-audit-export.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18 / bote-core 3.8.9 (re-run at 2.2.4): ChaCha20 + Ed25519 AEAD round-trip, 456-byte envelope |
| `04-safety-check.cyr` | 2026-11-03 | ✅ Fresh | Builds + **runs** on 6.7.18 / bote-core 3.8.9 (re-run at 2.2.4): `ls -la /tmp` allowed, `rm -rf /` blocked |
| `README.md` | 2026-09-23 | ✅ Fresh | Examples index. 2.1.11: the build note still named `cyrius.toml`; now `cyrius.cyml` |

---

## Tier 8 — Sources / benchmarks (`docs/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-11-04 | ✅ Fresh | 2.2.3: RFC 8439 (obsoletes 7539) with the counter limit; RFC 8259 §7 for `json_text`. 2.2.4: a Unicode section — Table 3-7 / RFC 3629 for `require_utf8`, UTS #39 confusables and UAX #15 NFKC for the lookalike fold |
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

*Last refresh: 2026-11-04 (2.2.4 release — bote-core 3.8.9 and four
audit follow-ups; every doc fresh, every executable doc rebuilt and
re-run on 6.7.18 / bote-core 3.8.9.)
Refresh in place when docs are touched.*
