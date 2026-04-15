# ADR-004: Port from Rust to Cyrius

## Status

Accepted · Landed in t-ron 2.0.0 (2026-04-14)

## Context

t-ron 0.90.0 was a Rust library crate. It depended on tokio, serde,
dashmap, regex, chrono, uuid, ed25519-dalek, chacha20poly1305,
thiserror, libro, and bote — plus their transitive closure. The
release artifact for a typical deployment exceeded 190 MB of `.rlib`
files plus the application host binary.

AGNOS ecosystem policy (`agnosticos/docs/philosophy.md`) prefers
in-family Cyrius implementations over external-language deps for
anything in the security path. libro and bote had already ported to
Cyrius. sigil (Ed25519 + SHA-256) was stdlib. The remaining blockers
— hoosh (LLM inference gateway) and the WebSocket edge of bote —
cleared through 2026-04.

## Decision

Port t-ron in full to Cyrius, archiving the Rust sources in
`rust-old/` as a reference and benchmark target. Cyrius target
version: 4.8.4 (pinned via `.cyrius-toolchain`). Deps:

- `libro` 1.0.3 (git/path)
- `bote` 2.5.1 (git/path)
- `sigil` (Cyrius stdlib)

### Translation conventions

Rust idioms map to Cyrius as follows:

| Rust | Cyrius |
|---|---|
| `struct Foo { a: u64, b: u64 }` | heap alloc + offset accessors (`foo_a(p) = load64(p)`) |
| `enum E { A, B(String), C{x,y} }` | tagged union: `alloc(32); store64(v, TAG_X)` |
| `f64 [0.0, 1.0]` | basis points `i64 [0, 1000]` |
| `HashMap<String, T>` | `hashmap.cyr` — keys are cstrings, values `i64` (store pointer) |
| `async fn` | synchronous; concurrency moves to the embedding layer |
| `Vec<u8>` | `alloc(n)` + explicit length |
| `#[cfg(feature = "x")]` | deferred module inclusion in `main.cyr` / `cyrius.toml` |
| regex | hand-rolled keyword matchers (see `scanner.cyr`) |
| serde derives | manual JSON builders (small, local, readable) |

### What stayed the same

- Module boundaries (one `src/*.cyr` per Rust `src/*.rs`).
- Pipeline order: size → policy → rate → scanner → pattern →
  correlation → audit.
- Verdict semantics (Allow / Deny{reason,code} / Flag{reason}).
- Policy TOML DSL: `[agent."NAME"]` + `[agent."NAME".rate_limit]`.
- libro chain wiring and verdict-to-severity mapping.

### What improved in the port

- **Identifier hardening** (F3): `tron_is_safe_identifier` at the
  pipeline entry, closing rate-bucket / overlong-UTF-8 / newline
  smuggling in one gate.
- **Scanner coverage**: MySQL `/*!…*/`, null-byte keyword splits,
  overlong UTF-8, double-encoded `%252e%252e`, shell `${IFS}` / `$9`
  / brace-expansion filler, Jinja block statements `{%…%}`, FreeMarker
  `<#…>`, ERB `#{…}`.
- **Template O(N²) → O(N)**: close scan bails out when no `}}`
  remains, eliminating a ReDoS-analog.
- **libro UUID fail-closed** (F2): vendored patch aborts on
  `/dev/urandom` short read instead of emitting predictable UUIDs.

## Consequences

**Good**

- Release artifact: 193 MB → **375 KB static ELF** (~500× shrinkage).
- Total LOC (src + tests + benches): 10 221 → 6 637 (−35 %).
- External runtime deps: removed. Only libro + bote + sigil remain,
  all Cyrius in-family.
- Reproducible builds: `cyrius build` produces byte-identical output
  from a committed toolchain tag.
- Supply-chain surface: drastically smaller.

**Bad**

- **~20× slower per-operation** on all benchmarked paths. Absolute
  throughput is still 19 k full checks/sec/thread — well above any
  realistic MCP load. See `docs/benchmarks-rust-v-cyrius.md` for
  details.
- Cyrius is single-threaded at the value level; async concurrency
  moved to the embedding layer. Consumers who relied on
  `tokio::spawn(gate.dispatch(…))` must wrap their own threading
  above t-ron.
- `f64` → basis points is a breaking API change. Confidence and risk
  scores are now `i64 [0, 1000]` instead of `f64 [0.0, 1.0]`. Callers
  divide by 1000 for the original scale.

## Verification

- 390 tests across 3 suites (`t-ron.tcyr`, `t-ron-crypto.tcyr`,
  `t-ron-safety.tcyr`), all green.
- Full CVE-class audit with 10 fixes and regression tests (see
  `docs/audit/2026-04-14.md`).
- Side-by-side benchmark run captured in
  `docs/benchmarks-rust-v-cyrius.md`.
