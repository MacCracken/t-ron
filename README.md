# T-Ron

> **T-Ron** (the security program that fights the MCP) — MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Language: Cyrius](https://img.shields.io/badge/Language-Cyrius-brightgreen.svg)](https://github.com/MacCracken/cyrius)
[![Version: 2.1.1](https://img.shields.io/badge/Version-2.1.1-informational.svg)](VERSION)

T-Ron is a [Cyrius](https://github.com/MacCracken/cyrius) security-middleware module set that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, anomaly detection, and auditing every verdict to a tamper-proof [libro](https://github.com/MacCracken/libro) hash chain. Named after Tron, the security program that fights the Master Control Program.

> **2.1.0 — modernization arc opens.** Cyrius 5.10.34, libro 2.6.2, bote 2.7.1; bote 2.0 handler-ABI fully observed; `cyrius.cyml` + `${file:VERSION}` + `cyrius.lock`. Full pipeline 3× faster vs 2.0.0 thanks to libro 2.6.x + cyrius 5.10.x. See [CHANGELOG.md](CHANGELOG.md) for the entry and [`docs/development/roadmap.md`](docs/development/roadmap.md) for the rest of the 2.1.x arc.

## Rust vs. Cyrius — at a glance

Same t-ron pipeline, two implementations, same box, same day. Full
methodology in [`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md).

| | Rust 0.90.0 | Cyrius 2.0.0 (4.8.4) | Cyrius 2.1.0 (5.10.34) | Δ vs Rust |
|---|---:|---:|---:|---:|
| **Binary (what ships)** | 2.59 MB rlib + 193 MB dep closure | 375 KB static ELF | **1.12 MB static ELF** | **~170× smaller** |
| **Source LOC** (`src/`) | 6 611 | 4 546 | 4 565 | −31 % |
| External runtime deps | tokio, serde, dashmap, regex, chrono, uuid, ed25519-dalek, chacha20poly1305, thiserror, libro, bote … | libro + bote + sigil (all Cyrius) | libro + bote + sigil (all Cyrius) | — |
| `policy_check` | 38 ns | 719 ns | 489 ns min / 1 µs avg | 13–25× slower |
| `tron_check` (full pipeline) | 2.4 µs | 52 µs | **17 µs** | **7× slower** (was 22×) |
| Throughput per thread | ~ 415 k checks/sec | ~ 19 k checks/sec | **~ 59 k checks/sec** | Still far above real-world MCP load |

Cyrius gives up raw throughput (no LLVM, no SIMD, software SHA-256)
in exchange for **500× artifact shrinkage**, zero runtime, zero
external deps, and a drastically smaller supply-chain surface. For a
security program that fights the MCP, that trade makes sense.

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
include "lib/bote_dispatch.cyr"   # per-module — bote dist + libro dist
                                  # together exceed the 2 MB compile cap

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
cyrius deps                              # resolve libro + bote from cyrius.cyml
cyrius build src/main.cyr build/t-ron    # compile (1.12 MB static x86_64 ELF)
cyrius test tests/t-ron.tcyr             # 312 assertions across 72 groups
cyrius test tests/t-ron-crypto.tcyr      # 30 assertions (signal + crypto + export)
cyrius test tests/t-ron-safety.tcyr      # 48 assertions (safety engine)
cyrius bench tests/t-ron.bcyr            # 5 pipeline benchmarks
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

Cyrius 5.10.34, x86_64, 2026-05-10 (see
[`bench-history.csv`](bench-history.csv) for full history and
[`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md)
for the side-by-side):

| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | 1 µs | **489 ns** | 100 000 |
| `scanner_clean_text` | 4 µs | 3 µs | 100 000 |
| `scanner_sql_detect` | 2 µs | 978 ns | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | **13 µs** | 10 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **17 µs** | 13 µs | 1 000 |

Full pipeline is ~3× faster vs 2.0.0 (52 µs → 17 µs) thanks to
libro 2.6.2's chain optimizations + cyrius 5.10.34 codegen.

## Roadmap

See [`docs/development/roadmap.md`](docs/development/roadmap.md) for
the full roadmap. Highlights:

- **Done in 2.0.0** — full pipeline, libro chain integration, signing,
  SIGHUP reload, ChaCha20+Ed25519 encrypted export, LLM-assisted scan,
  AI safety submodule, security audit with 10 CVE-class fixes.
- **2.1.x — modernization arc** (in progress) — cyrius 5.10.34 +
  libro 2.6.2 + bote 2.7.1 floor, bote 2.0 handler-ABI fully observed,
  manifest modernization, CI/release installer parity with bote/libro,
  `docs/doc-health.md` ledger, `dist/t-ron.cyr` consumer bundle
  via `cyrius distlib`.
- **Phase 2 — Advanced detection** (post-2.1.x) — ML-based anomaly
  detection, privilege escalation, time-of-day, capability-source
  policy / L3 agent-injection defense.
- **Phase 3 — Hardening** (post-2.1.x) — daimon event-bus alerts,
  aethersafha dashboard, edge fleet policy distribution.

## Reference Code

| Source | Relevance | Location |
|---|---|---|
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer — t-ron wraps its Dispatcher via SecurityGate | `../bote` (tag 2.7.1) |
| [libro](https://github.com/MacCracken/libro) | Cryptographic audit chain — t-ron writes every verdict to libro | `../libro` (tag 2.6.2) |
| [cyrius](https://github.com/MacCracken/cyrius) | Language toolchain | 5.10.34 |
| [hoosh](https://github.com/MacCracken/hoosh) | LLM-assisted prompt injection detection | `../hoosh` (HTTP API, tag 2.0.0) |
| [sigil](https://github.com/MacCracken/cyrius) | Ed25519 + SHA-256 primitives (Cyrius stdlib dep) | `lib/sigil.cyr` |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API and MCP tools | `../SecureYeoman` |

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
