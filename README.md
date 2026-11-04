# T-Ron

> **T-Ron** (the security program that fights the MCP) — MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Language: Cyrius](https://img.shields.io/badge/Language-Cyrius-brightgreen.svg)](https://github.com/MacCracken/cyrius)
[![Version: 2.2.4](https://img.shields.io/badge/Version-2.2.4-informational.svg)](VERSION)

T-Ron is a [Cyrius](https://github.com/MacCracken/cyrius) security-middleware module set that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, anomaly detection, and auditing every verdict to a tamper-proof [libro](https://github.com/MacCracken/libro) hash chain. Named after Tron, the security program that fights the Master Control Program.

> **2.2.4 — bote-core 3.8.9, and four of the audit's follow-ups.** The safety injection detector folds Cyrillic, Greek and fullwidth lookalike letters to Latin, output validation gains `require_utf8`, the identifier check reads no further than its 256-byte cap, and a buffer that cannot be allocated now fails closed instead of crashing the host. See the [CHANGELOG](CHANGELOG.md).
>
> **2.2.3 — the P(-1) audit.** Four independent reviews of every module found 74 items, 3 critical and 16 high, all fixed: an escaped tool name could pass a deny entry, SIGHUP reload skipped the signature check, the scanner never decoded JSON escapes, `DA_FLAG` skipped every later check, the policy loader read comments as content, and more. See the [audit report](docs/audit/2026-11-03.md). **Upgrade if you run 2.2.2 or earlier.** Signed mode and the strict policy loader change behaviour; the [CHANGELOG](CHANGELOG.md) lists every change callers will see.
>
> **Note — audit-chain hashes changed upstream.** libro 2.8.11 alters the entry-hash preimage, so a chain written by libro ≤ 2.8.10 will not verify against 2.8.12; there is no migration path, because the old preimage was unsound. **No known deployment is affected** — t-ron has no production consumer with a live chain as of 2.1.9, which is why this landed as a routine patch. If you are carrying a chain from an older build, re-export and re-anchor before upgrading.

## Rust vs. Cyrius — at a glance

Same t-ron pipeline, two implementations. Full methodology in
[`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md).

⚠️ **The Rust and Cyrius-2.0.0 columns were measured same-box,
same-day; the 2.2.3 column was not** — it is this box on 2026-11-03.
Treat the `Δ vs Rust` column as an order-of-magnitude read, not a
controlled comparison.

| | Rust 0.90.0 | Cyrius 2.0.0 (4.8.4) | Cyrius 2.2.3 (6.7.18) | Δ vs Rust |
|---|---:|---:|---:|---:|
| **Binary (what ships)** | 2.59 MB rlib + 193 MB dep closure | 375 KB static ELF | 684 KB static ELF | ~290× smaller |
| **Source LOC** (`src/`) | 6 611 | 4 546 | 6 862 | +4 % |
| External runtime deps | tokio, serde, dashmap, regex, chrono, uuid, ed25519-dalek, chacha20poly1305, thiserror, libro, bote … | libro + bote + sigil (all Cyrius) | libro + bote-core + sigil (all Cyrius) | — |
| `policy_check` | 38 ns | 719 ns | **222 ns** | 6× slower |
| `tron_check` (full pipeline) | 2.4 µs | 52 µs | **17.3 µs** | 7× slower (was 22×) |
| Throughput per thread | ~ 415 k checks/sec | ~ 19 k checks/sec | **~ 58 k checks/sec** | Still far above real-world MCP load |

**The binary is 684 KB at 2.2.3, down from 2.28 MB at 2.2.0, with
nothing removed from t-ron.** cyrius 6.7.18 deletes the dead code that
earlier toolchains only NOPed in place (1.99 MB of it in this build).
t-ron still pins the **full** `dist/sigil.cyr` bundle rather than
inheriting libro's thin sigil sub-bundles: only the full bundle carries
the `verify_data()` that policy signing uses, and the pin makes it
t-ron's declared dependency rather than whatever another dep's sidecar
happens to pull in. Whatever of it t-ron cannot reach is now dropped
at build time with the rest of the dead code, so the pin costs far less
artifact size than it did. (The binary peaked at 2.66 MB at 2.1.11.)

Cyrius gives up raw throughput (no LLVM, no SIMD, software SHA-256)
in exchange for a two-orders-of-magnitude smaller shipped closure,
zero runtime, zero external deps, and a drastically smaller
supply-chain surface. For a security program that fights the MCP,
that trade makes sense.

## Architecture

```
Agent -> bote (MCP protocol) -> t-ron SecurityGate -> tool handler
                                 |-- parameter size guard
                                 |-- policy check (per-agent ACLs, glob)
                                 |-- rate limiting (token bucket)
                                 |-- payload scanning (injection detection)
                                 |-- pattern analysis (anomaly detection)
                                 |-- cross-agent correlation (coordinated-access)
                                 '-- audit logging (ring buffer + libro chain)
```

T-Ron is a **module set** — no HTTP server, no CLI. Consumers include
the relevant `src/*.cyr` modules and call `tron_check()` / wrap a bote
`Dispatcher` with `security_gate_new()`. The SecureYeoman T.Ron
personality queries it through the `query_*` API.

See [`docs/architecture/overview.md`](docs/architecture/overview.md)
for the full module map.

## Quick Start

```cyrius
include "lib/string.cyr"
include "lib/alloc.cyr"
include "lib/tagged.cyr"
include "lib/hashmap.cyr"
include "lib/fnptr.cyr"
include "lib/chrono.cyr"

# libro + bote modules (auto-vendored via cyrius.cyml)
include "lib/libro.cyr"           # single dist bundle (#derive accessors)
include "lib/bote-core.cyr"       # opt-in transport-free profile

# t-ron
include "src/tron.cyr"
include "src/middleware.cyr"
include "src/tools.cyr"

fn main() {
    alloc_init();

    # Build a TRon with deny-by-default and scan/pattern enabled.
    var tron = tron_new(tron_config_default());

    # Load per-agent ACLs from TOML.
    tron_load_policy(tron,
        "[agent.\"web-agent\"]\n"
        "allow = [\"tarang_*\", \"rasa_*\"]\n"
        "deny  = [\"aegis_*\", \"phylax_*\"]\n");

    # Register t-ron's tool definitions alongside your app tools.
    var reg = registry_new();
    var defs = tron_tool_defs();
    for (var i = 0; i < vec_len(defs); i = i + 1) {
        registry_register(reg, vec_get(defs, i));
    }
    # ... registry_register(reg, your app tool defs) ...

    var d = dispatcher_new(reg);
    # dispatcher_handle(d, "your_tool", &your_handler);

    # Wrap with the security gate.
    var gate = security_gate_new(tron, d);
    security_gate_register_tool_handlers(gate);

    # Every tools/call is now security-checked before reaching the handler.
    # var response = security_gate_dispatch(gate, request, "web-agent");
    return 0;
}
```

Build and run:

```sh
cyrius deps                              # resolve deps from cyrius.cyml
cyrius build src/main.cyr build/t-ron    # compile (689 KB static x86_64 ELF)
cyrius test tests/t-ron.tcyr             # 407 assertions
cyrius test tests/t-ron-crypto.tcyr      # 64 assertions (signing, signal, crypto, export)
cyrius test tests/t-ron-safety.tcyr      # 239 assertions (safety engine)
cyrius test tests/t-ron-detect.tcyr      # 192 assertions (scanner, pattern, correlation, LLM scan)
cyrius bench tests/t-ron.bcyr            # 6 benchmarks (pipeline + safety injection check)
```

More walkthroughs in [`docs/guides/`](docs/guides/) and runnable
demos in [`docs/examples/`](docs/examples/).

## Features

- **SecurityGate** — wraps a bote `Dispatcher` with pre-dispatch checks on every `tools/call`; `initialize` / `tools/list` pass through unmodified
- **Policy engine** — per-agent ACLs, glob patterns (`tarang_*`), deny-wins-over-allow, TOML configuration with `[agent."NAME"]` and `[agent."NAME".rate_limit]` sections
- **Rate limiter** — per-agent-per-tool token bucket, per-agent overrides from policy, millitoken storage (fractional refill without f64 at the value level), default 60 cpm
- **Payload scanner** — hand-rolled keyword + case-insensitive pattern scans: SQL (union/select + from, `--`, `; drop`, `/*!…*/` MySQL versioned comments, null-byte splitters), shell (`;&|$` + rm/curl/wget/…, `${IFS}`/`$9`/brace-expansion filler), template (`{{…}}`, `{%…%}`, `<%…%>`, `<#…>`, `${…}`, `#{…}`), path traversal (`../`, `..\`, `%2e%2e`, `%252e%252e`, overlong UTF-8). JSON walker with 64-level depth cap.
- **Pattern analyzer** — 100-entry per-agent ring buffer + 24-hour histogram. Detects tool enumeration, privilege escalation, off-hours activity
- **Correlation detector** — cross-agent coordinated access within a time window
- **Risk scoring** — per-agent rolling score, basis points `0..=1000`
- **Audit logger** — dual-write to a 10 000-event ring buffer (fast operational queries) and a libro cryptographic hash chain (tamper-proof, SHA-256 linked). `audit_verify_chain()` confirms integrity.
- **Encrypted export** — `audit_export_encrypted` uses ChaCha20 + Ed25519 AEAD (RFC 7539 ChaCha20; Ed25519 via sigil's constant-time impl replaces Poly1305). Wire format: `nonce(12) ‖ sig(64) ‖ ciphertext(N)`.
- **Policy signing** — `PolicyVerifier` holds trusted Ed25519 keys; `.sig` files alongside policy TOML; `tron_verify_and_load_policy` gates the existing load path.
- **SIGHUP hot-reload** — non-blocking `signalfd` + `sighup_drain_and_reload(fd, tron)` integrated into any event loop.
- **LLM-assisted scan** — optional `llm_scan` module targets hoosh's HTTP `/infer` endpoint for deeper semantic classification.
- **AI safety submodule** — 6-pattern prompt-injection detector (Unicode-normalized), per-agent circuit breaker (Closed→Open→HalfOpen), 7 rule types (ForbiddenAction, RequireApproval, RateLimit, ContentFilter, ScopeRestriction, EscalationRequired, ResourceLimit, OutputValidation), 5 default AGNOS policies.
- **MCP tools** — `tron_status`, `tron_risk`, `tron_audit`, `tron_policy` registered as bote tool handlers for the T.Ron personality
- **Default deny** — unknown agents and tools are denied by default (each configurable to allow, deny, or flag)

## T.Ron Personality Integration

The query API is designed for the T.Ron personality in SecureYeoman:

```cyrius
var audit = tron_audit(tron);

# "What's the risk level for web-agent?"
var score_bp = query_agent_risk_score(audit, "web-agent");   # 0..=1000

# "Show me the 20 most recent security events."
var events = query_recent_events(audit, 20);

# "How many calls have been blocked?"
var denials = query_total_denials(audit);

# "What happened with agent data-pipeline?"
var trail = query_agent_audit(audit, "data-pipeline", 50);

# "Is the audit chain intact?"
var rc = audit_verify_chain(audit);                          # 0 = ok

# "Give me a security summary."
var review = audit_chain_review(audit);
```

The same queries are exposed as MCP tools (`tron_status`,
`tron_risk`, `tron_audit`, `tron_policy`) for agents to call through
bote.

## Benchmarks

Cyrius 6.7.18, x86_64, 2026-11-04, t-ron 2.2.4 (see
[`bench-history.csv`](bench-history.csv) for full history and
[`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md)
for the side-by-side):

| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | **213 ns** | 211 ns | 100 000 |
| `scanner_clean_text` | **394 ns** | 388 ns | 100 000 |
| `scanner_sql_detect` | **368 ns** | 362 ns | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | 10.6 µs | 10.4 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **17.5 µs** | 15.9 µs | 1 000 |
| `safety_injection_check` (117-byte clean prompt) | 26.7 µs | 26.2 µs | 10 000 |

Measured with the box under load (load average about 4). Against a
**same-session** 2.2.3 baseline (three interleaved rounds each, both on
bote-core 3.8.9) every bench is within ±2 % except `policy_check`
(+4 %), whose code did not change — see the 2.2.4 CHANGELOG entry. The
2.2.3 release made the scanner **−89 %** faster on clean text and
**−68 %** on a SQL payload.

⚠️ Do not compare these absolutes against rows recorded on other
dates — this box's speed drifts between sessions, so only
same-session comparisons are like-for-like.

## Roadmap

See [`docs/development/roadmap.md`](docs/development/roadmap.md) for
the full roadmap. Highlights:

- **Done in 2.0.0** — full pipeline, libro chain integration, signing,
  SIGHUP reload, ChaCha20+Ed25519 encrypted export, LLM-assisted scan,
  AI safety submodule, security audit with 10 CVE-class fixes.
- **2.1.x — modernization arc** (closed at 2.1.12) — cyrius 5.10 →
  6.6 as thirteen patches on an unchanged wire shape: `cyrius.cyml` +
  `cyrius.lock`, the `dist/t-ron.cyr` consumer bundle, CI gates for the
  bundle, the sidecar and capacity, and the `docs/doc-health.md` ledger.
- **2.2.x — current line.** 2.2.0 moved to cyrius 6.7.x and CI to
  `cyrius deps --locked`; 2.2.1 fixed the tool handlers' buffer
  overrun; 2.2.2 was a quick-item bundle; **2.2.3 was the P(-1)
  audit** ([report](docs/audit/2026-11-03.md)); 2.2.4 moved bote-core
  to 3.8.9 and closed four of the audit's five patch-sized follow-ups.
- **2.3.x onward — one feature line per minor**: MCP tool titles and
  output schemas, and claims-based authorization (2.3.x); daimon
  alerts, agnoshi intents and the aethersafha dashboard (2.4.x);
  capability-source policy, L3 of agent-injection defense (2.5.x);
  ML anomaly detection and edge-fleet policy (2.6.x+).

## Reference Code

| Source | Relevance | Location |
|---|---|---|
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer — t-ron wraps its Dispatcher via SecurityGate | `../bote` (tag 3.8.9, `dist/bote-core.cyr`) |
| [libro](https://github.com/MacCracken/libro) | Cryptographic audit chain — t-ron writes every verdict to libro | `../libro` (tag 2.11.3) |
| [cyrius](https://github.com/MacCracken/cyrius) | Language toolchain | 6.7.18 |
| [hoosh](https://github.com/MacCracken/hoosh) | LLM-assisted prompt injection detection | `../hoosh` (HTTP API, tag 2.0.0) |
| [sigil](https://github.com/MacCracken/sigil) | Ed25519 + SHA-256 primitives — first-party pin since 2.1.8 | `../sigil` (tag 3.13.15, `dist/sigil.cyr`) |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API and MCP tools | `../SecureYeoman` |

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
