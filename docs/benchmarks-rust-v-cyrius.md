# Rust vs. Cyrius — Benchmark & Size Comparison

Side-by-side measurements of the same t-ron pipeline in both
implementations. Both runs were taken on the same box, minutes apart,
under comparable load.

## Environment

| | |
|---|---|
| CPU | AMD Ryzen 7 5800H |
| Kernel | Linux 6.18.19-1-lts x86_64 |
| Date | 2026-04-14 |
| Rust | rustc from `rust-old/rust-toolchain.toml` (criterion `--output-format=bencher`) |
| Cyrius | 4.8.4 (`cyrius bench tests/t-ron.bcyr`) |
| t-ron | 2.0.0 (Cyrius) · 0.90.0 (Rust, archived in `rust-old/`) |

## Same-op benchmarks

Time per iteration, nanoseconds, averaged. The Rust and 2.0.0 columns
are fresh runs from 2026-04-14; see the note under the table for 2.2.3.

| Operation | Rust | Cyrius 2.0.0 | Ratio | Cyrius 2.2.3 | Ratio |
|---|---:|---:|---:|---:|---:|
| `policy_check` (ACL glob match) | 38 ns | 719 ns | 19× | 222 ns | **5.8×** |
| `scanner_clean` (no-threat string) | 269 ns | 4 000 ns | 15× | 382 ns | **1.4×** |
| `scanner_injection` (SQL detect) | 36 ns | 1 000 ns | 28× | 360 ns | **10×** |
| `audit_log` (ring buffer + libro chain + SHA-256) | 1 773 ns | 41 000 ns | 23× | 10 462 ns | **5.9×** |
| `tron_check` — full pipeline, allow path | 2 412 ns | 52 000 ns | 22× | 17 291 ns | **7.2×** |

⚠️ **The 2.2.3 column was not measured alongside the other two.** It is
the mean of three interleaved rounds on 2026-11-03 (cyrius 6.7.18,
against a same-session 2.2.2 baseline), on a different day and toolchain
from the 2026-04-14 Rust and 2.0.0 runs. Read its ratios as an order of
magnitude, not a controlled comparison. The 2.2.3 scanner is a
single-pass rewrite that also decodes every JSON string first, so it
does more work per call than 2.0.0's and still runs 10× faster.

## Rust-only benches

Counterparts not yet ported to `tests/t-ron.bcyr` (straightforward
additions — the underlying functions all exist in the Cyrius port):

| Operation | Rust |
|---|---:|
| `rate_limiter_check` | 111 ns |
| `pattern_record` | 94 ns |
| `risk_score` (over 100 events) | 3 607 ns |
| `pipeline_deny_injection` | 1 784 ns |
| `pipeline_large_params` (64 KB payload) | 27 866 ns |

## Size comparison

### Binary artifact

| | Rust | Cyrius 2.0.0 | Cyrius 2.2.3 |
|---|---:|---:|---:|
| Library artifact | `libt_ron.rlib` 2.59 MB | — | — |
| Full standalone binary | (needs app host) | **`build/t-ron` 375 KB** | **684 KB** |
| Transitive dep closure | `target/release/deps/` 193 MB of `.rlib` files | — | — |

The 2.2.3 binary carries libro's audit chain, bote's core, and the full
sigil bundle; cyrius 6.7.18 drops the dead code (2.06 MB of it).

The Rust column lists library + closure because `t-ron 0.90.0` was a
crate — an actual deployable needed tokio, serde, chrono, dashmap,
regex, uuid, ed25519-dalek, chacha20poly1305, thiserror, libro, bote,
and their transitive deps. Cyrius inlines libro + bote + sigil into a
single static ELF.

### Lines of code

| | Rust | Cyrius 2.0.0 | Δ | Cyrius 2.2.3 |
|---|---:|---:|---:|---:|
| Source (`src/`) | 6 611 | 4 546 | **−31 %** | 6 862 |
| Tests | 3 431 | 1 968 | −43 % |
| Benches | 179 | 123 | −31 % |
| **Total** | **10 221** | **6 637** | **−35 %** |

Cyrius code is smaller despite the i64-everything translation (tagged
unions, heap-allocated structs, manual byte packing) because the
verbose parts of the Rust (serde derives, `#[cfg(test)]`, generic
trait bounds, async plumbing) vanish entirely.

## Why is Cyrius ~20× slower?

Not a secret, and not a bug. Cyrius is a **single-pass, 303 KB,
self-hosting compiler** with **no LLVM, no register allocator beyond
spill-slot bookkeeping, no inlining heuristics, no SIMD**. Rust via
rustc+LLVM gets:

- Whole-program optimization across the crate graph
- Aggressive inlining, loop unrolling, vectorization
- SIMD-accelerated SHA-256 in libro's `sha2` crate
- Branch layout tuned to PGO profiles baked into the stdlib

Cyrius's SHA-256 (inside libro) is pure Cyrius — one block at a time,
no intrinsics. That's most of the `audit_log` delta: every verdict
writes one libro entry, which hashes the entry fields. **41 µs
includes a full software SHA-256 pass plus an Ed25519 commit step
where applicable.**

## Why it doesn't matter (much) for t-ron

Absolute throughput, not ratios:

- **`tron_check` at 52 µs per call = 19 200 full security checks per
  second per thread.** A busy MCP deployment running hundreds of
  tools at interactive rates (dozens of calls/sec per agent) never
  comes near that ceiling.
- **`policy_check` at 719 ns** is still sub-microsecond. The glob
  matcher handles ACLs for thousands of agents without breaking stride.
- **Binary size: 375 KB static ELF** versus Rust's 193 MB dep closure.
  No runtime, no libc, no dynamic loader, no allocator surprises.
- **Zero external deps** beyond libro + bote + sigil (all Cyrius).
- **No tokio worker pool, no serde codegen, no trait vtable soup.**
  The bump allocator is the whole memory story.

The trade is raw throughput for **~500× smaller artifact**,
**35 % fewer LOC**, and a drastically smaller supply-chain surface.
For a security program that fights the MCP, that trade makes sense.

## Raw output

### Cyrius (`./scripts/bench-history.sh`)

```
policy_check        avg=719ns  min=691ns  max=11us  iters=100000
scanner_clean_text  avg=4us    min=3us    max=15us  iters=100000
scanner_sql_detect  avg=1us    min=1us    max=9us   iters=100000
audit_log           avg=41us   min=39us   max=82us  iters=1000
tron_check_allow    avg=52us   min=38us   max=76us  iters=1000
```

### Rust (`cargo bench --bench pipeline -- --output-format=bencher`)

```
pipeline_allow           2,412 ns/iter (+/-    225)
pipeline_deny_injection  1,784 ns/iter (+/-  4,971)
scanner_clean              269 ns/iter (+/-      3)
scanner_injection           36 ns/iter (+/-      0)
policy_check_allow          38 ns/iter (+/-      1)
rate_limiter_check         111 ns/iter (+/-      1)
pattern_record              94 ns/iter (+/-      0)
audit_log                1,773 ns/iter (+/- 52,969)
risk_score               3,607 ns/iter (+/-     67)
pipeline_large_params   27,866 ns/iter (+/- 13,679)
```

## Re-running

```sh
# Cyrius
./scripts/bench-history.sh          # appends to bench-history.csv

# Rust (archived — still builds against rust-old/Cargo.toml)
cd rust-old && cargo bench --bench pipeline -- --output-format=bencher
```

Historical runs are recorded in `bench-history.csv` (Cyrius) and
`rust-old/benches/history.csv` (Rust). Both share the columns
`date, commit, bench_name, …` so a joint trend plot is a `concat` away.

## Size recipe (how to reproduce)

```sh
# Rust rlib
cd rust-old && cargo build --release --lib
ls -la target/release/libt_ron.rlib

# Rust deps closure
du -sh target/release/deps

# Cyrius binary
cyrius build src/main.cyr build/t-ron
ls -la build/t-ron

# LOC
wc -l src/*.cyr tests/*.tcyr tests/*.bcyr           # Cyrius
wc -l rust-old/src/**/*.rs rust-old/benches/*.rs    # Rust
```
