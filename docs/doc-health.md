---
name: t-ron Documentation Health
description: Living state of doc currency in the t-ron repo — fresh / stale / archived / read-through-outstanding, refreshed as docs are touched
type: state
---

# Documentation Health — t-ron

> **Last refresh**: 2026-06-10 (2.1.5 release — cyrius major-toolchain jump 5.10.44 → 6.1.24 + libro 2.7.2 + bote 2.7.3; transitive sigil 3.7.8 / patra 1.11.0 / agnosys 1.4.1 / majra 2.4.5 / sakshi 2.2.10; `atomic`/`thread`/`thread_local` added to stdlib + includes to clear the libro `chain_append` SIGILL on sigil 3.7.8's TLS-scratch hash path; 401 assertions hold; `code_size` 100.6 % → 120 % on the larger 6.x stdlib bundle. CHANGELOG + roadmap refreshed in place). Prior 2026-05-11 (2.1.4 — pattern-analyzer refinements) | **Refresh cadence**: when docs are touched, update the affected row.
> **Scope**: This repo only (`t-ron`) — root-level files (README, CHANGELOG, CLAUDE.md, etc.) plus the entire `docs/` tree. Cross-repo dep pin drift lives in CHANGELOG entries and the [roadmap](development/roadmap.md), not here.

This is a **ledger**, not a one-time audit. Rewrite-in-place as
docs change. t-ron is an MCP security monitor consumed by daimon,
bote middleware, and phylax — stale API / threat-model / safety-
policy docs propagate downstream, so doc currency carries weight.
The doc surface is modest (~17 files) and most are load-bearing.

Pattern lifted from the libro ledger ([`libro/docs/doc-health.md`](https://github.com/MacCracken/libro/blob/main/docs/doc-health.md))
— same buckets, t-ron-shaped tiers.

---

## At a glance — 2026-05-11 inventory

**~18 markdown files** total (8 root + 10 under `docs/`). Bucket
counts after the 2.1.4 refresh:

| Bucket | Count | What it means |
|---|---|---|
| ✅ **Fresh — touched in the 2.1.x cycle** | 13 | CHANGELOG, README, roadmap, doc-health (this file), `DEPS-PATTERN.md` (new in 2.1.1), CONTRIBUTING.md (Cyrius-era rewrite, post-2.1.2 docs commit), CLAUDE.md (Cyrius-era discipline rewrite, post-2.1.2 docs commit), `docs/examples/01..04-*.cyr` (all four rewritten + verified end-to-end at 2.1.0), `docs/examples/README.md` (no edit needed) |
| 🟡 **Stale — refresh in place** | 1 | docs/guides/integration.md + testing.md (last touched at 2.0.0 — verify code samples still build against the **2.1.5 floor**: cyrius 6.1.24 stdlib + libro 2.7.2 + bote 2.7.3, and that any sigil-using sample carries the `atomic`/`thread`/`thread_local` includes before `sigil`). Bundled count because they're a related pair |
| 🟠 **Read-through outstanding** | 1 | docs/architecture/overview.md (last touched 2.0.0 — verify module map matches src/ post-2.1.x; no shape change is expected but the pre-2.1.0 ABI prose for handlers needs a "see 2.1.0" note, and the 2.1.1 `dist/t-ron.cyr` distribution surface should land a one-sentence reference) |
| 🔵 **No version-tied claims today** | 3 | `SECURITY.md`, `CODE_OF_CONDUCT.md`, `LICENSE`. None reference current version numbers or moving APIs |
| 📦 **Date-stamped historical record** | 1 | `docs/audit/2026-04-14.md` (2.0.0 audit). Point-in-time report; the date is in the filename |
| 📝 **ADRs** | 6 | All six ADRs (001–006) reflect decisions made in the 1.0 → 2.0 era. None retired. ADRs 002 (default-deny) and 003 (bote middleware) gain a 2.1.0 note about the handler-ABI plumbing |

---

## Tier 1 — Root files

| File | Last touched | Status | Notes |
|---|---|---|---|
| `README.md` | 2026-05-10 | 🟡 Stale | Version badge / pins reflect 2.1.0; needs a refresh for the 2.1.3 cyrius 5.10.44 / libro 2.6.3 / bote 2.7.2 (`dist/bote-core.cyr`) lineup and the new perf row. Defer to next release-worthy touch — README pins rot quickly and a single refresh covering 2.1.1 → 2.1.3 keeps the diff readable |
| `CHANGELOG.md` | 2026-05-11 | ✅ Fresh | 2.1.4 entry lands the pattern-analyzer refinements (directed-sequence detector #3 + `pattern_off_hours_score_bp` continuous basis-point scoring); 2.1.3 entry's capacity table re-baselined against the actual 5.10.44 doubled caps (8 192 / 262 144) that the original entry had wrong (numbers came from a stale-cap 5.11.18 binary) |
| `CLAUDE.md` | 2026-05-11 | ✅ Fresh | 2.1.3 touch: cyrius pin bumped to 5.10.44; `.cyrius-toolchain` retirement noted; `src/_libro_compat.cyr` reference replaced with the parenthetical "dropped at 2.1.3" callout. Otherwise the Cyrius-era rewrite from the previous touch holds |
| `CONTRIBUTING.md` | 2026-05-10 | ✅ Fresh | Cyrius-era rewrite, mirroring bote 2.7.1's shape. Drops cargo / make / MSRV refs; new Common Commands table; Release Discipline section; Adding-a-New-Security-Check / Code Style / Testing sections aligned with the 3-file test split + `[lib] modules` + `dist/t-ron.cyr` regen flow. No 2.1.3-specific edits needed |
| `SECURITY.md` | 2026-04-14 | 🔵 No version-tied claims | Reporting policy + scope |
| `CODE_OF_CONDUCT.md` | 2026-04-14 | 🔵 No version-tied claims | Standard |
| `DEPS-PATTERN.md` | 2026-05-11 | ✅ Fresh | 2.1.3 refresh: module list 19 → 18 (compat shim retired); minimal-consumer manifest snippet bumped to libro 2.6.3 + bote 2.7.2 `dist/bote-core.cyr` + `slice` / `keccak` / `random` stdlib + t-ron tag 2.1.3 |
| `VERSION` | 2026-05-11 | ✅ Fresh | `2.1.4` — single source of truth, read into `cyrius.cyml` via `${file:VERSION}` |
| `LICENSE` | (initial commit) | 🔵 No version-tied claims | GPL-3.0-only |

---

## Tier 2 — Project state (`docs/development/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `roadmap.md` | 2026-05-11 | ✅ Fresh | 2.1.4 refresh: 2.1.4 row added to Shipped table and 2.1.x arc table (pattern-analyzer refinements: directed-sequence detector + continuous bp scoring); Phase 2 entries updated in place to mark the two refinement deltas as ✅ shipped at 2.1.4; preamble re-stated against the 5.10.44 doubled caps. **Prior 2.1.3 pass:** Shipped table through 2.1.3, cyrius-language-deps table marks both prior 🔴 / 🟡 rows ✅ Resolved, Future row recast as "optional flip to `dist/bote.cyr`" |
| `threat-model.md` | 2026-04-14 | 🟠 Read-through outstanding | Verify post-2.1.0 — the bote 2.0 handler-ABI now-observed change does not change the threat model but should land a note that audit-tool authorization (gating `tron_audit` / `tron_policy` on caller identity) is a 2.2.x candidate |

---

## Tier 3 — Architecture (`docs/architecture/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `overview.md` | 2026-04-14 | 🟠 Read-through outstanding | Module map matches src/ post-2.1.0 (no module added or removed; `src/_libro_compat.cyr` is the only new file and lives under a "compat shim" subsection). Bote 2.0 handler-ABI prose should reference the 2.1.0 plumbing |

---

## Tier 4 — ADRs (`docs/architecture/adr-*.md`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `adr-001-dual-audit.md` | 2026-04-14 | ✅ Fresh | Accepted. Ring buffer + libro chain duality. Holds |
| `adr-002-default-deny.md` | 2026-04-14 | ✅ Fresh | Accepted. Deny-wins-over-allow semantics. Holds — 2.1.0 doesn't touch this surface |
| `adr-003-bote-middleware.md` | 2026-04-14 | ✅ Fresh | Accepted. SecurityGate wraps bote Dispatcher. 2.1.0 plumbs `claims = 0` to `dispatcher_dispatch` per bote 2.0 ABI; the ADR rationale (gate-not-shim) carries unchanged. A 2.2.x amendment may add a "claims-aware authorization" subsection |
| `adr-004-cyrius-port.md` | 2026-04-14 | ✅ Fresh | Accepted. Rust → Cyrius port rationale. Historical decision, holds |
| `adr-005-chacha20-ed25519-aead.md` | 2026-04-14 | ✅ Fresh | Accepted. ChaCha20 + Ed25519 AEAD over ChaCha20-Poly1305. Holds |
| `adr-006-safety-submodule.md` | 2026-04-14 | ✅ Fresh | Accepted. AGNOS safety engine design (severity / enforcement / 7 rule types / circuit breaker). Holds |

**ADR posture today**: low decision-velocity. Architecturally
significant calls earn an ADR; minor decisions ride CHANGELOG +
in-source comments. Notable judgement calls during 2.1.0 that
landed in CHANGELOG / `src/_libro_compat.cyr` header rather than
an ADR: the per-module-bote vs dist-libro split (forced by the
cyrius 2 MB compile-source cap), and the `ct_eq` compat shim.

---

## Tier 5 — Audit reports (`docs/audit/`)

Date-stamped point-in-time reports. Each P(-1) hardening pass per
CLAUDE.md cadence lands a new report; existing reports are not
edited (the date is in the filename).

| File | Date | Status | Notes |
|---|---|---|---|
| `2026-04-14.md` | 2026-04-14 | 📦 Historical record | 2.0.0 P(-1) audit; 10 CVE-class fixes (F2 / F3 / F4a-d / F5 / F6 / F7 / F11) closed in the same release |

A 2.1.x audit will land when the modernization arc closes — likely
co-dated with the close of 2.1.4.

---

## Tier 6 — Guides (`docs/guides/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `integration.md` | 2026-04-14 | 🟡 Stale | Last touched at 2.0.0. Verify code samples build against the 2.1.0 stdlib + bote 2.7.1 surface. The handler-ABI change at bote 2.0 was already documented (this repo's 2.0.0 did *not* observe it end-to-end, which is what 2.1.0 fixes); the guide may need a "see 2.1.0 CHANGELOG" reference |
| `testing.md` | 2026-04-14 | 🟡 Stale | Same vintage as integration.md. Test-suite split (`t-ron` / `-crypto` / `-safety`) hasn't changed; assertion counts also unchanged at 390. Refresh the cyrius pin reference |

---

## Tier 7 — Examples (`docs/examples/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `01-minimal-gate.cyr` | 2026-05-10 | ✅ Fresh | Include rewrite for the 2.1.0 surface (lib/libro.cyr dist bundle + lib/ct.cyr + src/_libro_compat.cyr shim). Builds + runs clean |
| `02-signed-policy.cyr` | 2026-05-10 | ✅ Fresh | Same include rewrite. Builds + runs clean (Ed25519 sign + verify round-trip) |
| `03-audit-export.cyr` | 2026-05-10 | ✅ Fresh | Same include rewrite. Builds + runs clean (ChaCha20 + Ed25519 AEAD envelope round-trip, 456 bytes) |
| `04-safety-check.cyr` | 2026-05-10 | ✅ Fresh | No libro/bote include — safety module is self-contained. Verified to build + run under 2.1.0 |
| `README.md` | 2026-04-14 | ✅ Fresh | Examples index — text-only, no version-tied claims |

---

## Tier 8 — Sources / benchmarks (`docs/`)

| File | Last touched | Status | Notes |
|---|---|---|---|
| `sources.md` | 2026-04-14 | ✅ Fresh | Algorithm + spec citations (RFC 7539, sigil API, etc). Holds |
| `benchmarks-rust-v-cyrius.md` | 2026-04-14 | 🟡 Stale | 2.0.0 baseline. Refresh with a 2.1.0 column in a near-term touch — `bench-history.csv` already has the 2026-05-11 row |

---

## Open strategic questions

None outstanding for the 2.1.0 cut. This section will repopulate
when:

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

*Last refresh: 2026-05-11 (2.1.4 release — pattern-analyzer
refinements: directed-sequence detector + continuous off-hours
bp score; +11 test assertions to 401 total; 2.1.3 capacity
baselines re-stated against the actual 5.10.44 doubled caps).
Refresh in place when docs are touched.*
