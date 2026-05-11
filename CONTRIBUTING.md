# Contributing to t-ron

Thank you for your interest in contributing to t-ron. This
document covers the development workflow, code standards, and
project conventions.

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Create a branch** from `main` for your work.
3. **Make your changes**, ensuring all checks pass.
4. **Open a pull request** against `main`.

## Prerequisites

- **Cyrius toolchain** — version pinned in `cyrius.cyml`
  (`cyrius = "5.10.34"` at time of writing). Install per the
  [cyrius README](https://github.com/MacCracken/cyrius). The
  `.cyrius-toolchain` file is kept as a local-dev convenience;
  CI reads the pin from `cyrius.cyml`.
- Sibling-checkout the local AGNOS deps (`libro`, `bote`) under
  `../` if you want `cyrius deps` to resolve via path overrides
  instead of fetching git tags.

## Common Commands

| Command | Description |
|---|---|
| `cyrius deps` | Populate `./lib/` from the version-pinned stdlib + tagged libro/bote modules. Run before any build/test/check. `./lib/` is gitignored — the contract is the `cyrius.lock` pin, not the bytes on disk. |
| `cyrius deps --verify` | Enforce `cyrius.lock` hash match on every resolved dep. |
| `cyrius build src/main.cyr build/t-ron` | Build the production binary. |
| `cyrius test tests/t-ron.tcyr` | Run the main test compile unit (312 assertions). |
| `cyrius test tests/t-ron-crypto.tcyr` | Run the crypto / signing / audit-export suite (30 assertions). |
| `cyrius test tests/t-ron-safety.tcyr` | Run the AGNOS safety engine suite (48 assertions). |
| `cyrius bench tests/t-ron.bcyr` | Run the 5-bench pipeline harness. |
| `./scripts/bench-history.sh` | Run benches + append a row to `bench-history.csv` tagged with the current commit. |
| `cyrius distlib` | Regenerate `dist/t-ron.cyr` for downstream consumers (daimon / phylax / bote middleware). |
| `CYRIUS_STATS=1 cyrius build src/main.cyr build/t-ron` | Print the capacity meter (`fn_table` / `identifiers` / etc.) at the tail of stdout. |
| `CYRIUS_DCE=1 ...` | Whole-program dead-code elimination on the emitted binary. |
| `CYRIUS_NO_WARN_SHADOW_LIB=1 ...` | Silence the cwd-shadows-version-snapshot informational note (set by default in CI). |

Before opening a PR:

```sh
cyrius deps --verify
cyrius test tests/t-ron.tcyr
cyrius test tests/t-ron-crypto.tcyr
cyrius test tests/t-ron-safety.tcyr
cyrius distlib
git diff --exit-code dist/t-ron.cyr   # bundle must match src/
```

CI runs the same gates plus a manifest-completeness check
(`[lib]` modules ⊇ `main.cyr` `src/` includes), a capacity gate
(fail if `fn_table` or `identifiers` cross 95 %), a smoke test of
the built binary, and benchmark capture. See
`.github/workflows/ci.yml`.

## Release Discipline

Docs-only changes do **not** earn a version bump. They land on
`main` as regular commits and accumulate under `## [Unreleased]`
in `CHANGELOG.md` until the next release-worthy patch (code, CI,
release-flow, dep-pin, manifest, tests) ships, at which point the
unreleased notes ride into that release's section.

Release-worthy changes follow Keep a Changelog under
[`CHANGELOG.md`](CHANGELOG.md); performance claims must include
benchmark numbers (`tests/t-ron.bcyr` / `bench-history.csv`).

## Adding a New Security Check

1. Create `src/<check>.cyr` with your implementation.
2. Add `include "src/<check>.cyr"` to `src/main.cyr` at the right
   position (Cyrius is single-pass: includes must appear before
   any forward references).
3. Add `"src/<check>.cyr"` to the `[lib] modules` list in
   `cyrius.cyml` — otherwise the manifest-completeness CI gate
   fails. The 19-module list in 2.1.x order is the reference.
4. Wire the check into `tron_check()` in `src/tron.cyr` at the
   appropriate pipeline stage (policy → rate → scanner →
   pattern → score → correlation).
5. Add tests:
   - General pipeline + module tests go in `tests/t-ron.tcyr`.
   - Crypto / signing / audit-export goes in
     `tests/t-ron-crypto.tcyr`.
   - AGNOS safety engine work goes in
     `tests/t-ron-safety.tcyr`.
   - Add a 4th test file only if a new domain emerges; existing
     splits hit a parser-state threshold, not an organizational
     preference.
6. Update `docs/architecture/overview.md` (module map),
   `docs/development/roadmap.md` (Shipped row when the patch
   tags), and `docs/doc-health.md` (touch the relevant row).
7. Run `cyrius distlib` and commit the updated `dist/t-ron.cyr`.

## Code Style

- **No raw panics / unguarded exits in library code.** Cyrius
  doesn't have `unwrap()` or `panic!`, but the analogue is an
  unguarded `syscall(60, ...)` or implicit out-of-bounds — guard
  at the boundary. Security checks fail-closed; deny on doubt.
- **Constant-time comparisons** for any token / signature /
  secret material. Use `ct_eq_bytes` / `ct_eq_bytes_lens` from
  `lib/ct.cyr` (the `src/_libro_compat.cyr` shim aliases the
  retired `ct_eq` name for libro 2.6.2's bundle internals).
- **Structured tracing** is not yet available in cyrius; use
  `sakshi_debug` / `sakshi_info` / `sakshi_warn` consistently
  where logs already exist.
- **`#[non_exhaustive]`-equivalent**: cyrius enums always allow
  tail-extension; rely on default-case handling in any
  `if (tag == VK_X)` / `if (kind == DENY_X)` chain.
- **`#[must_use]`-equivalent**: treat every constructor /
  pure-function return as load-bearing; never call for side
  effect and discard the result.
- **`#[inline]`-equivalent**: cyrius inlines aggressively under
  `CYRIUS_DCE=1`. Keep hot-path fns short.
- **Bote handler ABI**: handlers are `fn h(args, claims)` per
  bote 2.0; the `claims` arg may be ignored by handlers that
  expose project-wide state but the parameter must be present so
  bote's `fncall2(fp, args, claims)` dispatch resolves correctly.

## Testing

- Unit tests go in the three-file split (`t-ron.tcyr` /
  `-crypto.tcyr` / `-safety.tcyr`) — the splits are forced by
  the cyrius compile-state threshold per compile unit, not by
  organizational preference.
- The default test runner is the harness in `lib/assert.cyr`
  (`assert`, `assert_eq`, `assert_summary`).
- All new security checks require tests for both detection
  (true-positive) and false-positive avoidance.
- After any audit-path change, verify the libro chain stays
  intact under `audit_verify_chain()` — the
  `test_chain_integrity_many_writes` pattern is the contract.
- Run the full three-file matrix locally before pushing; CI runs
  the same matrix plus benchmarks, the dist-freshness gate, and
  the manifest-completeness gate.

## License

t-ron is licensed under **GPL-3.0-only**. All contributions must
be compatible with this license. By submitting a pull request,
you agree that your contribution is licensed under the same
terms.
