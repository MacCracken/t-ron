# T-Ron — Claude Code Instructions

## Project Identity

**T-Ron** (Tron: security program that fights the MCP) — MCP
security monitor — tool call auditing, rate limiting, injection
detection, anomaly analysis.

- **Type**: Flat Cyrius library crate (consumed via
  `dist/t-ron.cyr` per `DEPS-PATTERN.md`).
- **Language**: Cyrius (pin in `cyrius.cyml`,
  `cyrius = "5.10.44"` as of 2.1.3). `cyrius.cyml
  [package].cyrius` is the single source of truth — the legacy
  `.cyrius-toolchain` file was retired at 2.1.3.
- **License**: GPL-3.0-only.
- **Version**: SemVer (2.x line, stable post-Cyrius-port). Source
  of truth is `VERSION`; `cyrius.cyml` reads it via
  `${file:VERSION}`.
- **Genesis repo**: [agnosticos](https://github.com/MacCracken/agnosticos)
- **Philosophy**: [AGNOS Philosophy & Intention](https://github.com/MacCracken/agnosticos/blob/main/docs/philosophy.md)
- **Standards**: [First-Party Standards](https://github.com/MacCracken/agnosticos/blob/main/docs/development/applications/first-party-standards.md)
- **Recipes**: [zugot](https://github.com/MacCracken/zugot) —
  takumi build recipes (verify recipe version on each release).

## Consumers

bote (middleware), daimon (security gate), phylax (output
scanning complement). Consumers wire via:

```toml
[deps.t-ron]
git = "https://github.com/MacCracken/t-ron.git"
tag = "<t-ron version>"
modules = ["dist/t-ron.cyr"]
```

**Note**: T.Ron (SY personality) queries t-ron for security
intelligence.

## Development Process

### P(-1): Scaffold Hardening (before any new features)

0. Read roadmap, CHANGELOG, doc-health, and open issues — know
   what was intended before auditing what was built.
1. Test + benchmark sweep of existing code:
   `cyrius test tests/t-ron.tcyr`, `-crypto.tcyr`, `-safety.tcyr`;
   `./scripts/bench-history.sh`.
2. Cleanliness check:
   - `cyrius deps --verify` (lockfile hash match)
   - `cyrius build src/main.cyr build/t-ron` (clean compile under
     `CYRIUS_DCE=1`)
   - `CYRIUS_STATS=1 cyrius build ...` (capacity meter — fn_table
     / identifiers / code_size)
   - `cyrius distlib` + `git diff --exit-code dist/t-ron.cyr`
     (bundle matches source)
3. Get baseline benchmarks — record `bench-history.csv` row.
4. Initial refactor + audit (performance, memory, security, edge
   cases).
5. Cleanliness check — must be clean after audit.
6. Additional tests/benchmarks from observations.
7. Post-audit benchmarks — prove the wins.
8. Repeat audit if heavy.
9. Documentation audit — ADRs, source citations, guides, examples
   (see Documentation Standards in first-party-standards.md);
   refresh `docs/doc-health.md` rows in place.

### Development Loop (continuous)

1. Work phase — new features, roadmap items, bug fixes.
2. Cleanliness check (see P(-1) step 2).
3. Test + benchmark additions for new code.
4. Run benchmarks (`./scripts/bench-history.sh`).
5. Audit phase — review performance, memory, security,
   throughput, correctness.
6. Cleanliness check — must be clean after audit.
7. Deeper tests/benchmarks from audit observations.
8. Run benchmarks again — prove the wins.
9. If audit heavy → return to step 5.
10. Documentation — update CHANGELOG, roadmap, doc-health, ADRs
    for design decisions, source citations for algorithms /
    formulas in `docs/sources.md`, guides and examples for new
    API surface, verify recipe version in zugot.
11. Version check — `VERSION` is the single source of truth.
    `cyrius.cyml` reads it via `${file:VERSION}` (no separate
    edit needed). Verify recipe version in zugot tracks the
    release.
12. Return to step 1.

### Release Discipline

- **Docs-only changes do NOT earn a version bump.** They land on
  `main` as commits and accumulate under `## [Unreleased]` in
  `CHANGELOG.md` until the next release-worthy patch ships, at
  which point the unreleased notes ride along. Release-worthy =
  code, CI, release-flow, dep-pin, manifest, tests.
- Use `./scripts/version-bump.sh <X.Y.Z>` to bump (one-line; the
  manifest doesn't need editing thanks to `${file:VERSION}`).
- Always regenerate `dist/t-ron.cyr` (`cyrius distlib`) on release
  cuts — the CI freshness gate enforces this on every push.

### Key Principles

- **Never skip benchmarks.** Numbers don't lie. The CSV history
  is the proof.
- **Tests + benchmarks are the way.** Minimum 80 % coverage
  target; the 390-assertion baseline (312 + 30 + 48) is the
  current floor.
- **Own the stack.** If an AGNOS crate wraps an external lib,
  depend on the AGNOS crate.
- **No magic.** Every operation is measurable, auditable,
  traceable.
- **`#[non_exhaustive]`-equivalent**: cyrius enums always allow
  tail-extension. Public enum chains (`VK_*`, `DENY_*`,
  `SAFETY_*`) must rely on default-case handling, not exhaustive
  match.
- **`#[must_use]`-equivalent**: treat every constructor /
  pure-function return as load-bearing; never call for side
  effect and discard.
- **`#[inline]`-equivalent**: cyrius inlines aggressively under
  `CYRIUS_DCE=1`. Keep hot-path fns short.
- **Avoid temporary allocations** — write bytes directly into a
  pre-sized `alloc(...)` + `store8/memcpy` instead of building
  intermediate `String`s. The codebase has the pattern (e.g.
  `_audit_details` in `src/audit.cyr`).
- **Cow-equivalent — borrow when you can, allocate only when you
  must.** Owned-copy `_audit_dup_cstr`-style helpers exist
  exactly because some flows demand it; do not gratuitously dup
  in the hot path.
- **Vec arena over HashMap** — when indices are known, direct
  access beats hashing.
- **Feature-gate optional deps** — consumers pull only what they
  need.
- **`sakshi_debug` / `sakshi_info` / `sakshi_warn`** on all
  operations — structured logging for the audit trail until
  proper tracing lands upstream.
- **Constant-time compares** for any token / signature / secret
  material. Use `ct_eq_bytes` / `ct_eq_bytes_lens` from
  `lib/ct.cyr`. (The `src/_libro_compat.cyr` shim that wrapped
  the retired `ct_eq` for libro 2.6.2 was dropped at 2.1.3 —
  libro 2.6.3's dist bundle calls `ct_eq_bytes_lens` directly.)
- **Bote handler ABI**: tool handlers are
  `fn h(args, claims)` per bote 2.0; pipe `claims` through even
  if the handler ignores it today.

## Documentation Structure

```
Root files (required):
  README.md, CHANGELOG.md, CLAUDE.md, CONTRIBUTING.md,
  SECURITY.md, CODE_OF_CONDUCT.md, LICENSE, VERSION,
  DEPS-PATTERN.md, cyrius.cyml, cyrius.lock

docs/ (required):
  doc-health.md — living ledger; refresh in place as docs are touched
  architecture/overview.md — module map, data flow, consumers
  development/roadmap.md — Shipped table, 2.1.x arc, forward items

docs/ (when earned):
  adr/ — architectural decision records
  guides/ — usage guides, integration patterns
  examples/ — worked examples
  standards/ — external spec conformance
  compliance/ — regulatory, audit, security compliance
  sources.md — source citations for algorithms / formulas
```

## CHANGELOG Format

Follow [Keep a Changelog](https://keepachangelog.com/). The
`## [Unreleased]` section at the top accumulates entries between
releases (adopted in 2.1.0; mirrors bote 2.7.0). Performance
claims MUST include benchmark numbers. Breaking changes get a
**Breaking** section with migration guide.

## DO NOT

- **Do not commit or push** — the user handles all git operations
  (commit, push, tag).
- **NEVER use `gh` CLI** — use `curl` to GitHub API only.
- Do not add unnecessary dependencies — keep it lean.
- Do not write to `dist/t-ron.cyr` by hand — always
  `cyrius distlib` to regenerate; CI enforces freshness.
- Do not raw-syscall-exit / out-of-bounds / unguarded-fail in
  library code. Security checks fail-closed; deny on doubt.
- Do not skip benchmarks before claiming performance improvements.
- Do not commit `target/`, `lib/`, or `build/` (all gitignored;
  `cyrius deps` populates `lib/` from the lockfile pin).
- Do not invent a new distribution mechanism — see
  `DEPS-PATTERN.md` for the contract.
- Do not bump VERSION for docs-only commits — see Release
  Discipline above.
