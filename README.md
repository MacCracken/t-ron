# T-Ron

> **T-Ron** (the security program that fights the MCP) — MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Language: Cyrius](https://img.shields.io/badge/Language-Cyrius-brightgreen.svg)](https://github.com/MacCracken/cyrius)

T-Ron is a [Cyrius](https://github.com/MacCracken/cyrius) security-middleware module set that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, anomaly detection, and auditing every verdict to a tamper-proof [libro](https://github.com/MacCracken/libro) hash chain. Named after Tron, the security program that fights the Master Control Program.

> **Cyrius port:** 1.0.0 is a ground-up rewrite from Rust. The Rust sources are archived in `rust-old/` for reference. See [CHANGELOG.md](CHANGELOG.md) for migration notes.

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

T-Ron is a **module set** — no HTTP server, no CLI. Consumers include the relevant `src/*.cyr` modules and call `tron_check()` / wrap a bote `Dispatcher` with `security_gate_new()`. The SecureYeoman T.Ron personality queries it through the `query_*` API.

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
cyrius deps                            # resolve libro + bote from cyrius.toml
cyrius build src/main.cyr build/t-ron  # compile (320 KB x86_64 binary)
cyrius test tests/t-ron.tcyr           # 245 assertions, 62 groups
cyrius bench tests/t-ron.bcyr          # 5 pipeline benchmarks
```

## Features

- **SecurityGate** — wraps a bote `Dispatcher` with pre-dispatch checks on every `tools/call`; `initialize` / `tools/list` pass through unmodified
- **Policy engine** — per-agent ACLs, glob patterns (`tarang_*`), deny-wins-over-allow, TOML configuration with `[agent."NAME"]` and `[agent."NAME".rate_limit]` sections
- **Rate limiter** — per-agent-per-tool token bucket, per-agent overrides from policy, millitoken storage (fractional refill without f64 at the value level), default 60 cpm
- **Payload scanner** — hand-rolled keyword + case-insensitive pattern scans: SQL (union/select + from, `--`, `; drop`), shell (`;&|$` + rm/curl/wget/…), template (`{{..}}`, `<% %>`, `${..}`), path traversal (`../`, `..\`, `%2e%2e`). JSON walker with 64-level depth cap.
- **Pattern analyzer** — 100-entry per-agent ring buffer + 24-hour histogram. Detects tool enumeration (≥ 15 distinct tools in last 20 calls), privilege escalation (3+ sensitive tools in last 5, mixed with benign), off-hours activity (≥ 50-call baseline + < 2 % active-hour threshold)
- **Correlation detector** — cross-agent coordinated access: N distinct agents calling the same tool inside a time window
- **Risk scoring** — per-agent rolling score, weighted `(denies × 2 + flags) / (total × 2)` over the last 100 events, returned as integer basis points (0 = trusted, 1000 = hostile)
- **Audit logger** — dual-write to a 10 000-event ring buffer (fast operational queries) and a libro cryptographic hash chain (tamper-proof, SHA-256 linked). `audit_verify_chain()` confirms integrity.
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

The same queries are exposed as MCP tools (`tron_status`, `tron_risk`, `tron_audit`, `tron_policy`) for agents to call through bote.

## Benchmarks

Cyrius 4.5.0, x86_64, 2026-04-14 (see `bench-history.csv` for full history):

| Operation | Avg | Min | Iters |
|---|---|---|---|
| `policy_check` | **727 ns** | 681 ns | 100 000 |
| `scanner_clean_text` | 3 µs | 3 µs | 100 000 |
| `scanner_sql_detect` | 1 µs | 1 µs | 100 000 |
| `audit_log` (ring buffer + libro chain + SHA-256) | 44 µs | 40 µs | 1 000 |
| `tron_check_allow` (full pipeline) | **54 µs** | 37 µs | 1 000 |

## Roadmap

### Pending
- [ ] description-hash pinning in bote registry (audit follow-up F1)

### Recently landed
- `src/safety.cyr` — AI safety submodule: severity/enforcement enums, 6-pattern prompt injection detector (with Unicode zero-width normalization), per-agent circuit breaker (closed/open/half-open sliding window), policy engine with 7 rule types (ForbiddenAction, RequireApproval, RateLimit, ContentFilter, ScopeRestriction, EscalationRequired, ResourceLimit, OutputValidation), 5 default AGNOS policies
- `src/signal.cyr` — SIGHUP hot-reload via signalfd (non-blocking, consumer-polled). `tron_load_policy_file` + `tron_reload_policy` plumbing.
- `src/crypto_chacha20.cyr` — RFC 7539 ChaCha20 stream cipher, verified against the standard test vector
- `audit_export_json` + `audit_export_encrypted` / `audit_decrypt_export` — operational JSON dump and ChaCha20 + Ed25519 AEAD envelope (Ed25519 replaces Poly1305 to reuse sigil's constant-time impl)
- `src/llm_scan.cyr` — LLM-assisted prompt injection detection via hoosh 2.0 HTTP API (self-contained, stdlib-only)
- `src/signing.cyr` — Ed25519 policy signature verification via sigil
- bote bump to 2.2.0 (JWT HS256 verifier)

### Phase 2 — Advanced Detection
- [ ] ML-based anomaly detection (train on normal patterns, flag deviations)
- [ ] Multi-signature / quorum policy approval

### Phase 3 — Hardening
- [ ] Real-time alerts via daimon event bus
- [ ] Dashboard integration (aethersafha security panel)
- [ ] Edge fleet policy distribution

### Done in 1.0.0
- Full check pipeline (size → policy → rate → scanner → pattern → correlation → audit)
- libro cryptographic chain on every verdict
- Cross-agent correlation detector
- Time-of-day anomaly detection
- Privilege escalation detection
- Per-agent rate-limit policy
- Policy file loading + TOML `[agent."NAME"]` parser

## Reference Code

| Source | Relevance | Location |
|---|---|---|
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer — t-ron wraps its Dispatcher via SecurityGate | `../bote` (tag 2.0.0) |
| [libro](https://github.com/MacCracken/libro) | Cryptographic audit chain — t-ron writes every verdict to libro | `../libro` (tag 1.0.3) |
| [cyrius](https://github.com/MacCracken/cyrius) | Language toolchain | 4.5.0 |
| [hoosh](https://github.com/MacCracken/hoosh) | LLM-assisted prompt injection detection (ported, awaiting bote integration) | `../hoosh` |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API and MCP tools | `../SecureYeoman` |

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
