# Testing Guide

**Current for t-ron 2.1.12** (cyrius 6.6.20).

> ⚠️ **Rewritten at 2.1.9.** Every prior revision of this file was the
> **Rust-era** guide — `cargo test`, `make clippy`, `serde` round-trips,
> `TRon::new(...)` with `.await`. None of it applies: t-ron has been
> Cyrius since 2.0.0 and there is no `Cargo.toml` or `Makefile` in the
> tree. The Rust sources are archived under `rust-old/` at git tag
> `0.90.0`. The commands and idioms below are the ones this repo
> actually runs.

## Running tests

Three suites, run separately:

```sh
cyrius test tests/t-ron.tcyr          # 323 assertions — core pipeline
cyrius test tests/t-ron-crypto.tcyr   #  30 assertions — signal, crypto, export
cyrius test tests/t-ron-safety.tcyr   #  48 assertions — AGNOS safety engine
```

**401 assertions total** (323 + 30 + 48) across 144 groups. That total
is the **floor**, per `CLAUDE.md`: a change may raise it, never lower
it. Coverage target is 80 %.

Benchmarks are a separate harness:

```sh
cyrius bench tests/t-ron.bcyr         # 5 pipeline benchmarks
./scripts/bench-history.sh            # same, and appends to bench-history.csv
```

## Suite layout

| Suite | Groups | Assertions | Covers |
|---|---:|---:|---|
| `tests/t-ron.tcyr` | 113 | 323 | error codes, gate verdicts, policy engine, rate limiter, scanner, pattern analyzer, audit ring buffer + libro chain, risk scoring, query API, correlation, middleware |
| `tests/t-ron-crypto.tcyr` | 10 | 30 | SIGHUP signalfd reload, ChaCha20, Ed25519 policy signing, encrypted audit export round-trip + tamper rejection |
| `tests/t-ron-safety.tcyr` | 21 | 48 | safety policies, severity, enforcement, 7 rule types, circuit breaker |

## Writing tests

Each suite is a `.tcyr` file that includes the same lib set as
`src/main.cyr`, then `src/*.cyr` directly. Group with `test_group`,
assert with `assert_eq` from `lib/assert.cyr`:

```cyrius
test_group("error codes");
assert_eq(TRON_ERR_NONE,   0, "err_none=0");
assert_eq(TRON_ERR_POLICY, 1, "err_policy=1");
assert_eq(streq(tron_error_label(TRON_ERR_POLICY), "policy"), 1, "label policy");
```

Every assertion takes a message — it is what prints on failure, so make
it identify the case, not restate the operator.

### Testing policy

```cyrius
var eng = policy_engine_new();
policy_grant(eng, "test-agent", "my_tool");

var call = tool_call_new("test-agent", "my_tool", "{}", 0);
var v    = tron_check(t, call);
assert_eq(verdict_is_allowed(v), 1, "granted tool allowed");
```

### Verifying chain integrity

```cyrius
var log = audit_logger_new();
# ... log events ...
assert_eq(audit_verify_chain(log), 1, "chain verifies");
assert_eq(audit_chain_len(log), 3,   "three entries");
```

## ⚠️ Include order is load-bearing in test harnesses too

Cyrius resolves forward references in a **single pass**, and the test
harnesses carry their own include lists — they do not inherit
`src/main.cyr`'s. Two ordering rules have caused real, non-obvious
breakage:

- **`atomic` / `thread` / `thread_local` and `ct` / `keccak` / `random`
  must precede `sigil`.** sigil's hash path self-installs a per-thread
  TLS scratch bank. Get this wrong and the SHA-256 inside libro's
  `chain_append` traps with **SIGILL** — at *runtime*, not compile time,
  so a harness can compile green and die when run. `tests/t-ron.bcyr`
  shipped with exactly this defect until 2.1.6; its header comment
  documents the trap.
- **`fs` / `process` / `sync` must precede `libro`** — declared by
  libro's dist sidecar since the 6.3.x carve.

Harnesses have also gone **latently stale**: through 2.1.5 all three
still included the retired `src/_libro_compat.cyr` and nine per-module
`lib/bote_*.cyr` files, so they had not compiled since 2.1.3 without
anyone noticing. When you change `src/main.cyr`'s include list, change
the harnesses' too, and actually run them.

## Cleanliness check

Per the `CLAUDE.md` development loop, tests are one leg of a four-part
check that must be green before and after any audit phase:

```sh
cyrius deps --verify                                  # lockfile hashes match
CYRIUS_DCE=1 cyrius build src/main.cyr build/t-ron    # clean compile
CYRIUS_STATS=1 cyrius build src/main.cyr build/t-ron  # capacity meter
cyrius distlib && git diff --exit-code dist/t-ron.cyr # bundle matches source
```

CI runs all four plus a capacity gate (fails at ≥95 % on `fn_table` or
`identifiers`) and a dist-sidecar validity gate.

## See also

- [integration.md](integration.md) — embedding t-ron in a bote service
- [`docs/examples/`](../examples/) — four runnable end-to-end examples
- [`DEPS-PATTERN.md`](../../DEPS-PATTERN.md) — the consumer contract
