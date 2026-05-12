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
- **libro / bote bundles** (`lib/libro.cyr`, `lib/bote_*.cyr`) —
  the consumer pulls those via their own `[deps.libro]` /
  `[deps.bote]` declarations, the same way t-ron does.
- **Tests / benches / examples** — not part of the consumer
  surface; live under `tests/` and `docs/examples/`.

A consumer using `dist/t-ron.cyr` must therefore have at minimum:

```toml
[deps]
stdlib = ["string", "fmt", "alloc", "vec", "str", "slice", "syscalls",
          "io", "args", "tagged", "assert", "fnptr", "hashmap", "regex",
          "chrono", "freelist", "bigint", "json", "base64", "net",
          # ct / keccak / random must precede sigil — sigil 3.1.1's
          # ML-DSA + AES-GCM surfaces reference ct / keccak / random.
          "ct", "keccak", "random"]

[deps.libro]
git = "https://github.com/MacCracken/libro.git"
tag = "2.6.3"
modules = ["dist/libro.cyr"]

[deps.bote]
git = "https://github.com/MacCracken/bote.git"
tag = "2.7.2"
# Opt-in transport-free profile — t-ron only needs bote's Dispatcher
# + tool-registry surface. Keeps consumer compile-source size down.
# Flip to "dist/bote.cyr" if your consumer also wires bote transports.
modules = ["dist/bote-core.cyr"]

[deps.t-ron]
git = "https://github.com/MacCracken/t-ron.git"
tag = "2.1.3"
modules = ["dist/t-ron.cyr"]
```

(sigil / sakshi come transitively from libro — do not list them
in your stdlib alongside this dep chain, see CHANGELOG 2.1.0.)

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
