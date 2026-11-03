# T-RON IS A CYRIUS DEP — READ THIS BEFORE TOUCHING BUILD / RELEASE

**This file is non-negotiable. Do not invent an alternative
distribution mechanism. Do not ignore it because "it seems to
work without it". libro / bote are the reference. Copy them.**

---

## Who consumes t-ron

t-ron is the **MCP security monitor** sitting between bote (MCP
protocol layer) and tool handlers. Known-intended consumers per
t-ron's `CLAUDE.md`:

- **bote** — embeds t-ron's SecurityGate as middleware in front of
  its Dispatcher.
- **daimon** — security gate for the agent runtime.
- **phylax** — output-scanning complement; pairs with t-ron's
  input-side scanning.

Any of them (or any future project) wires t-ron in like this:

```toml
[deps.t-ron]
git = "https://github.com/MacCracken/t-ron.git"
tag = "<t-ron version>"
modules = ["dist/t-ron.cyr"]
```

`cyrius deps` clones t-ron at the tag and copies
`dist/t-ron.cyr` into the consumer's `lib/t-ron.cyr` (or
`lib/t_ron_t_ron.cyr` depending on the cyrius release; the file
path the consumer `include`s is whatever `cyrius deps` writes).
That's the entry point they `include` from.

**t-ron is NOT a dep of the cyrius compiler itself.** It does
not need to appear in `cyrius/cyrius.cyml` to be consumed — the
dep relationship is downstream-to-t-ron. But the distribution
contract (below) is exactly the same either way.

## The contract

`dist/t-ron.cyr` is **the** distribution artifact. That's it.

- Every tagged release must have `dist/t-ron.cyr` committed.
- The bundle must be a self-contained, include-free single
  `.cyr` file containing every public function / struct / global
  t-ron exports.
- The file path and name are fixed: `dist/t-ron.cyr`. Not
  `dist/t-ron-2.1.1.cyr`. Not `build/t-ron.cyr`. Not
  `t-ron.cyr` at the repo root. **`dist/t-ron.cyr`.**

If `dist/t-ron.cyr` is missing at the tag, every downstream
consumer's `cyrius deps` step breaks at git-archive-fetch time.

## How to produce it

Use `cyrius distlib` — it reads `[package]` / `[lib]` from
`cyrius.cyml` and emits `dist/<name>.cyr` deterministically.

```sh
cyrius distlib
```

That command lands `dist/t-ron.cyr`. Run it:

1. **Locally** whenever `src/*.cyr` or `[lib] modules` changes —
   verify the bundle is up to date, then commit it.
2. **In CI** (`.github/workflows/ci.yml`) — a "dist freshness"
   step regenerates the bundle and fails the build if the
   committed `dist/t-ron.cyr` no longer matches.
3. **In the release workflow** (`.github/workflows/release.yml`)
   before any `git archive` / asset-upload step — uploads
   `dist/t-ron.cyr` as a release asset.

## What's in the bundle

`cyrius distlib` concatenates every file in `cyrius.cyml`'s
`[lib] modules` array in declaration order. For t-ron 2.1.3+
that's 18 files, in this order:

```
src/error.cyr
src/gate.cyr
src/policy.cyr
src/rate.cyr
src/scanner.cyr
src/pattern.cyr
src/audit.cyr
src/score.cyr
src/query.cyr
src/correlation.cyr
src/tron.cyr
src/tools.cyr
src/middleware.cyr
src/llm_scan.cyr
src/signing.cyr
src/signal.cyr
src/crypto_chacha20.cyr
src/safety.cyr
```

The order matches `src/main.cyr` — critical for Cyrius's
single-pass forward-reference resolution.

> **Compat shim retired at 2.1.3.** 2.1.0–2.1.2 shipped
> `src/_libro_compat.cyr` as the first module — a one-symbol
> `ct_eq → ct_eq_bytes_lens` shim for libro 2.6.2's bundle.
> libro 2.6.3 calls `ct_eq_bytes_lens` directly, so the shim
> has no remaining caller and the file is gone.

## What's NOT in the bundle

- **stdlib modules** (`lib/string.cyr`, `lib/sigil.cyr`, …) —
  the consumer supplies those via their own `[deps] stdlib`
  list. Bundling stdlib would lock t-ron to one cyrius version
  for every consumer.
- **libro / bote / sigil bundles** (`lib/libro.cyr`,
  `lib/bote-core.cyr`, `lib/sigil.cyr`) — these are *named deps*,
  declared in t-ron's own `cyrius.cyml`. Since cyrius 6.5.x they
  are resolved for the consumer automatically (see below).
- **Tests / benches / examples** — not part of the consumer
  surface; live under `tests/` and `docs/examples/`.

## The consumer manifest — one block is enough (6.5.x)

`cyrius distlib` emits **`dist/t-ron.deps`** alongside the bundle: a
sidecar listing the stdlib leaves the fold needs in scope. Since
cyrius 6.5.x, `cyrius deps` reads that sidecar and resolves the whole
tree itself — stdlib *and* t-ron's own named deps. Since 6.6.18 the
sidecar holds exactly the leaves `distlib`'s compile-verify proves the
bundle needs — `regex`, `net`, `syscalls` at 2.2.0, mirrored by a
`# Requires` include block at the top of `dist/t-ron.cyr` — and the
named deps' own `# Requires` blocks supply the rest. A consumer
therefore declares only:

```toml
[deps.t-ron]
git = "https://github.com/MacCracken/t-ron.git"
tag = "2.2.0"
modules = ["dist/t-ron.cyr"]
```

⚠️ **t-ron 2.2.0 needs cyrius ≥ 6.7.2 in the consumer**, because its
bote-core 3.4.10 dep does. Measured: a consumer pinned at 6.6.20 fails
to build; at 6.7.2 it builds and runs.

✅ **Re-verified at 2.2.0** (cyrius 6.7.9), not assumed: a
clean-room project declaring only the block above — with no sibling
checkouts, so every transitive dep is cloned at its tag, and t-ron
itself supplied through a `path` override because the tag did not
exist yet (from cyrius 6.7.6 a `path` is read only in local mode, so
the probe ran with `CYRIUS_LOCAL=t-ron`) — runs `cyrius deps` (**6
deps resolved, 0 errors**): t-ron, `libro`, `bote-core` and `sigil`,
plus `majra` (via bote) and `patra` (via libro), with the stdlib
coming from the sidecar and the deps' `# Requires` blocks. It
then compiles against `dist/t-ron.cyr` and executes, returning a
correct `deny` verdict for `ark_install` from an unregistered agent.

⚠️ **The sidecar shrank from 29 leaves to 3 at 2.1.12.** Through 2.1.11
it was a copy of t-ron's whole `[deps] stdlib`, so `cyrius deps`
vendored and locked modules like `fs` or `args` for the consumer.
It no longer does. A hand-written `include "lib/fs.cyr"` still
compiles (the compiler falls back to the toolchain snapshot), but the
file is not in your `lib/` or `cyrius.lock`. If your code calls a
stdlib module directly, list it in your own `[deps] stdlib`.

No `[deps] stdlib` list, and no `[deps.libro]` / `[deps.bote-core]` /
`[deps.sigil]` blocks, are required. Add an explicit `[deps.*]` pin
only if your own code calls that library directly and you want to
control its version independently — and then pin the **same tag**
t-ron does, or you will get two copies.

> **Superseded.** Releases through 2.1.8 documented a long
> `[deps] stdlib = [...]` array plus explicit `[deps.libro]` /
> `[deps.bote]` blocks here. That snippet had also rotted — it still
> listed `bigint` / `json` / `base64`, retired into `bayan` by the
> 2.1.6 carve. Delete it from consumer manifests; the sidecar covers
> it.

### ⚠️ The sidecar must be correct, and that is not automatic

Because the consumer now declares almost nothing, **`dist/t-ron.deps`
is the entire contract.** One bad line breaks every downstream build.

`cyrius distlib` excludes a bundled dep from the sidecar only when the
**module basename matches the dep name**. It does not match on the
git URL or the path. So this — shipped in t-ron 2.1.3 through 2.1.8 —
is wrong:

```toml
[deps.bote]                          # dep name:        bote
modules = ["dist/bote-core.cyr"]     # module basename: bote-core   ✗
```

The mismatch put `bote-core` into `dist/t-ron.deps` as a required
*stdlib* leaf. It is not one, so every consumer got:

```
error: dep t-ron requires 'bote-core' but it is not in the cyrius stdlib
```

The fix is to make the section name match the basename:

```toml
[deps.bote-core]                     # dep name:        bote-core
modules = ["dist/bote-core.cyr"]     # module basename: bote-core   ✓
```

⛔ **This defect shipped twice.** 2.1.8 diagnosed the identical
mechanism for `sigil`, fixed that instance, and validated the result
by confirming the sidecar was *byte-identical to the previous
release* — which is precisely why it missed the `bote-core` line
already sitting in that file. **A regression check cannot catch a
defect older than its baseline.** CI now validates every sidecar leaf
against the toolchain stdlib directory itself (`ci.yml` → "Dist
sidecar validity gate"), which is mutation-tested: re-adding the
`bote-core` line turns it red.

## The reference — bote and libro

Two upstream first-party libraries with the same contract:

- `~/Repos/libro/dist/libro.cyr` — single-file bundle, committed.
  See `libro/DEPS-PATTERN.md` (this file is modelled on it).
- `~/Repos/bote/dist/bote.cyr` — single-file bundle, committed.
  bote's `cyrius.cyml [lib] modules` lists 23 source files;
  `dist/bote.cyr` is what daimon / phylax / sutra / jalwa / rasa
  / mneme pull.

If t-ron's build/release deviates from this shape, either the
deviation is documented in t-ron's CHANGELOG with a clear reason,
or it is a bug.

## What will break if you ignore this file

- Any downstream consumer wiring `[deps.t-ron]` sees a 404 when
  `cyrius deps` tries to pull `dist/t-ron.cyr` from the tagged
  commit.
- Consumer CI turns red. The user tags a t-ron release, asks why
  daimon / phylax / bote-middleware broke, and finds out
  `dist/t-ron.cyr` wasn't produced.
- This has happened on other deps in the ecosystem. It wastes a
  release cycle every time.

## If you think you have a reason to deviate

You don't. Ask first. The distribution contract is an ecosystem
concern, not a t-ron-local decision.

---

## Verification checklist before any t-ron release

- [ ] `dist/t-ron.cyr` exists, is non-empty.
- [ ] `dist/t-ron.cyr` is committed at the tagged commit
      (`git log --oneline dist/t-ron.cyr | head` shows a commit
      at or before the tag).
- [ ] `dist/t-ron.cyr` is up-to-date with `src/*.cyr` — regenerate
      with `cyrius distlib` and `git diff dist/t-ron.cyr` shows
      no delta. CI enforces this via the "dist freshness" gate.
- [ ] The version header at the top of `dist/t-ron.cyr` matches
      `VERSION` (the bundle stamps `# Version: <VERSION>`).
- [ ] The release workflow (`.github/workflows/release.yml`)
      runs `cyrius distlib` before any asset-upload step, and
      uploads `dist/t-ron.cyr` as a release asset.

If any box is unchecked, the release is not ready.
