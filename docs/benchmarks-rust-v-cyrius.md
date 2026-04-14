# Rust vs. Cyrius — Benchmark Comparison

Side-by-side measurements of the same t-ron pipeline implemented in Rust
(archived in `rust-old/`, tag 0.90.0, criterion) and Cyrius (1.0.0,
`tests/t-ron.bcyr`). **Both runs were taken on the same box, minutes
apart, under comparable load.**

## Environment

| | |
|---|---|
| CPU | AMD Ryzen 7 5800H |
| Kernel | Linux 6.18.19-1-lts x86_64 |
| Date | 2026-04-14 |
| Rust | rustc from `rust-toolchain.toml` (criterion `--output-format=bencher`) |
| Cyrius | 4.5.0 (`cyrius bench tests/t-ron.bcyr`) |
| t-ron | 1.0.0 (Cyrius) · 0.90.0 (Rust, `rust-old/`) |

## Same-op comparison

Benches that have a direct counterpart in both implementations. Times are
nanoseconds per iteration, averaged.

| Operation | Rust | Cyrius | Ratio (C/R) |
|---|---:|---:|---:|
| `policy_check` (ACL glob match) | 38 ns | 727 ns | **19×** |
| `scanner_clean` (no-threat scan) | 268 ns | 3 000 ns | **11×** |
| `scanner_injection` (SQL detect) | 37 ns | 1 000 ns | **27×** |
| `audit_log` (ring buffer + libro SHA-256) | 1 770 ns | 44 000 ns | **25×** |
| `tron_check` (full pipeline, allow path) | 2 425 ns | 54 000 ns | **22×** |

## Rust-only benches

Counterparts not yet ported to `t-ron.bcyr` (trivial to add — just
wire-up work):

| Operation | Rust |
|---|---:|
| `rate_limiter_check` | 112 ns |
| `pattern_record` | 89 ns |
| `risk_score` (over 100 events) | 3 496 ns |
| `pipeline_deny_injection` | 1 825 ns |
| `pipeline_large_params` | 27 843 ns |

## Why is Cyrius ~20× slower?

Not a secret, and not a bug. Cyrius is a **single-pass, 303 KB,
self-hosting compiler** with **no LLVM, no register allocator beyond
spill-slot bookkeeping, no inlining heuristics, no SIMD**. Rust via
rustc+LLVM gets:

- Whole-program optimization across the crate graph
- Aggressive inlining, loop unrolling, vectorization
- SIMD-accelerated SHA-256 in libro's `sha2` crate
- Branch layout tuned to PGO profiles baked into the stdlib

Cyrius's SHA-256 (inside libro) is pure Cyrius — one block at a time, no
intrinsics. That's most of the `audit_log` delta: every verdict writes
one libro entry, which hashes the entry fields. **44 µs includes a full
software SHA-256 pass.**

## Why it doesn't matter (much) for t-ron

Absolute numbers, not ratios:

- **`tron_check` at 54 µs per call = 18 500 checks / sec / thread.** A
  busy MCP deployment running hundreds of tools at human-interactive
  rates (dozens of calls/sec per agent) never comes near that ceiling.
- **`policy_check` at 727 ns** is still sub-microsecond. The glob
  matcher handles ACLs for thousands of agents without breaking stride.
- **Binary size: 320 KB static ELF** (vs. Rust + deps ≈ several MB
  dynamic / tens of MB fully statically linked).
- **Zero runtime**. No tokio worker threads, no libc, no allocator
  surprises — the Cyrius bump allocator is the whole story.
- **Zero external deps** beyond libro + bote (both also Cyrius + pure
  Cyrius stdlib).

The trade is throughput for supply-chain surface area and auditability.
For a security program that fights the MCP, that trade makes sense.

## Raw output

### Cyrius (`cyrius bench tests/t-ron.bcyr`)

```
policy_check:        727ns avg (min=681ns  max=8us)   [100000 iters]
scanner_clean_text:  3us  avg (min=3us    max=33us)  [100000 iters]
scanner_sql_detect:  1us  avg (min=1us    max=34us)  [100000 iters]
audit_log:           44us avg (min=40us   max=119us) [1000   iters]
tron_check_allow:    54us avg (min=37us   max=157us) [1000   iters]
```

### Rust (`cargo bench --bench pipeline --output-format=bencher`)

```
pipeline_allow              2,425 ns/iter (+/-    230)
pipeline_deny_injection     1,825 ns/iter (+/-  5,196)
scanner_clean                 268 ns/iter (+/-      3)
scanner_injection              37 ns/iter (+/-      0)
policy_check_allow             38 ns/iter (+/-      0)
rate_limiter_check            112 ns/iter (+/-      1)
pattern_record                 89 ns/iter (+/-      0)
audit_log                   1,770 ns/iter (+/- 54,319)
risk_score                  3,496 ns/iter (+/-     90)
pipeline_large_params      27,843 ns/iter (+/- 14,889)
```

## Re-running

```sh
# Cyrius
./scripts/bench-history.sh         # appends to bench-history.csv

# Rust (archived)
cd rust-old && cargo bench --bench pipeline -- --output-format=bencher
```

Historical runs are recorded in `bench-history.csv` (Cyrius) and
`rust-old/benches/history.csv` (Rust). Both share the columns
`date, commit, bench_name, …` so a joint trend plot is a `concat` away.
