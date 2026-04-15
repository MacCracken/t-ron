# T-Ron

> **T-Ron** (the security program that fights the MCP) — MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Language: Cyrius](https://img.shields.io/badge/Language-Cyrius-brightgreen.svg)](https://github.com/MacCracken/cyrius)
[![Version: 2.0.0](https://img.shields.io/badge/Version-2.0.0-informational.svg)](VERSION)

T-Ron is a [Cyrius](https://github.com/MacCracken/cyrius) security-middleware module set that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, anomaly detection, and auditing every verdict to a tamper-proof [libro](https://github.com/MacCracken/libro) hash chain. Named after Tron, the security program that fights the Master Control Program.

> **2.0.0 — Cyrius port complete.** A ground-up rewrite from Rust with a layered security audit, signed policy loading, SIGHUP hot-reload, encrypted audit export, and the full AGNOS safety submodule on top. The Rust sources remain archived in `rust-old/` for reference and benchmarking. See [CHANGELOG.md](CHANGELOG.md) for the port log.

## Rust vs. Cyrius — at a glance

Same t-ron pipeline, two implementations, same box, same day. Full
methodology in [`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md).

| | Rust 0.90.0 | Cyrius 2.0.0 | Δ |
|---|---:|---:|---:|
| **Binary (what ships)** | 2.59 MB rlib + 193 MB dep closure | **375 KB static ELF** | **~500× smaller** |
| **Source LOC** (`src/`) | 6 611 | 4 546 | −31 % |
| **Test LOC** | 3 431 | 1 968 | −43 % |
| **Total LOC** | 10 221 | 6 637 | **−35 %** |
| External runtime deps | tokio, serde, dashmap, regex, chrono, uuid, ed25519-dalek, chacha20poly1305, thiserror, libro, bote … | libro + bote + sigil (all Cyrius) | — |
| `policy_check` | 38 ns | 719 ns | 19× slower |
| `tron_check` (full pipeline) | 2.4 µs | 52 µs | 22× slower |
| Throughput per thread | ~ 415 k checks/sec | **~ 19 k checks/sec** | Still far above real-world MCP load |

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

# libro + bote modules (auto-vendored via cyrius.toml)
include "lib/libro_chain.cyr"
include "lib/bote_dispatch.cyr"

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
cyrius deps                              # resolve libro + bote from cyrius.toml
cyrius build src/main.cyr build/t-ron    # compile (375 KB static x86_64 ELF)
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

Cyrius 4.8.4, x86_64, 2026-04-14 (see
[`bench-history.csv`](bench-history.csv) for full history and
[`docs/benchmarks-rust-v-cyrius.md`](docs/benchmarks-rust-v-cyrius.md)
for the side-by-side):

| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | **719 ns** | 691 ns | 100 000 |
| `scanner_clean_text` | 4 µs | 3 µs | 100 000 |
| `scanner_sql_detect` | 1 µs | 1 µs | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | 41 µs | 39 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **52 µs** | 38 µs | 1 000 |

## Roadmap

See [`docs/development/roadmap.md`](docs/development/roadmap.md) for
the full roadmap. Highlights:

- **Done in 2.0.0** — full pipeline, libro chain integration, signing,
  SIGHUP reload, ChaCha20+Ed25519 encrypted export, LLM-assisted scan,
  AI safety submodule, security audit with 10 CVE-class fixes.
- **Pending** — description-hash pinning in bote registry (F1 follow-up;
  lives upstream).
- **Phase 2** — ML-based anomaly detection, multi-signature policy
  approval, daimon event-bus alerts, aethersafha dashboard.

## Reference Code

| Source | Relevance | Location |
|---|---|---|
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer — t-ron wraps its Dispatcher via SecurityGate | `../bote` (tag 2.5.1) |
| [libro](https://github.com/MacCracken/libro) | Cryptographic audit chain — t-ron writes every verdict to libro | `../libro` (tag 1.0.3) |
| [cyrius](https://github.com/MacCracken/cyrius) | Language toolchain | 4.8.4 |
| [hoosh](https://github.com/MacCracken/hoosh) | LLM-assisted prompt injection detection | `../hoosh` (HTTP API, tag 2.0.0) |
| [sigil](https://github.com/MacCracken/cyrius) | Ed25519 + SHA-256 primitives (Cyrius stdlib dep) | `lib/sigil.cyr` |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API and MCP tools | `../SecureYeoman` |

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
