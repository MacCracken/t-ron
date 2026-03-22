# T-Ron

> **T-Ron** (the security program that fights the MCP) -- MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

T-Ron is a security middleware library that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, pattern analysis, and auditing every call to a tamper-proof [libro](https://github.com/MacCracken/libro) hash chain. Named after Tron, the security program that fights the Master Control Program.

## Architecture

```
Agent --> bote (MCP protocol) --> t-ron (security gate) --> tool handler
                                    |-- policy check (per-agent ACLs)
                                    |-- rate limiting (token bucket)
                                    |-- payload scanning (injection detection)
                                    |-- pattern analysis (anomaly detection)
                                    '-- audit logging (libro hash chain)
```

T-Ron is a **library crate** -- no HTTP server, no CLI, no binary. Consumers embed it as middleware in their MCP tool dispatch pipeline via `SecurityGate`. The SecureYeoman T.Ron personality queries it for security insights.

## Quick Start

```rust
use t_ron::{TRon, TRonConfig, middleware::SecurityGate, tools};
use bote::{Dispatcher, registry::ToolRegistry};

// Create monitor with deny-by-default policy
let tron = TRon::new(TRonConfig::default());

// Load per-agent ACLs from TOML
tron.load_policy(r#"
[agent."web-agent"]
allow = ["tarang_*", "rasa_*"]
deny = ["aegis_*", "phylax_*"]
"#)?;

// Register t-ron's tool definitions alongside your app tools
let mut registry = ToolRegistry::new();
for def in tools::tool_defs() {
    registry.register(def);
}
// ... register your app tools ...

// Wrap bote dispatcher with security gate
let dispatcher = Dispatcher::new(registry);
let mut gate = SecurityGate::new(tron, dispatcher);
gate.register_tool_handlers();

// Every tools/call is now security-checked before reaching your handler
let response = gate.dispatch(&request, "web-agent").await;
```

## Features

- **SecurityGate Middleware** -- wraps bote `Dispatcher` with pre-dispatch security checks on every `tools/call`; non-tool methods pass through unmodified
- **Policy Engine** -- per-agent ACLs with glob pattern matching (`tarang_*`), deny-wins-over-allow semantics, TOML configuration
- **Rate Limiter** -- per-agent, per-tool token bucket with configurable rates (default 60 calls/minute)
- **Payload Scanner** -- regex-based injection detection: SQL injection, shell injection, template injection, path traversal
- **Pattern Analyzer** -- anomaly detection on tool call sequences: tool enumeration detection, privilege escalation monitoring
- **Risk Scoring** -- rolling per-agent threat score (0.0 = trusted, 1.0 = hostile) based on audit history
- **Audit Logger** -- dual-write to an in-memory ring buffer (fast operational queries) and a libro cryptographic hash chain (tamper-proof audit trail with integrity verification)
- **MCP Tools** -- `tron_status`, `tron_risk`, `tron_audit`, `tron_policy` registered as bote tool handlers for the T.Ron personality
- **Query API** -- read-only interface for the T.Ron personality in SecureYeoman: security events, risk scores, chain verification
- **Default Deny** -- unknown agents and tools are denied by default (configurable: allow, deny, or flag)

## T.Ron Personality Integration

The `TRonQuery` API is designed for the T.Ron personality in SecureYeoman to query security state:

```rust
let query = tron.query();

// "What's the risk level for agent web-agent?"
let risk = query.agent_risk_score("web-agent").await;

// "Show me recent security events"
let events = query.recent_events(20).await;

// "How many calls have been blocked?"
let denials = query.total_denials().await;

// "What happened with agent data-pipeline?"
let trail = query.agent_audit("data-pipeline", 50).await;

// "Is the audit chain intact?"
query.verify_chain()?;

// "Give me a security summary"
let review = query.chain_review();
```

The same queries are available as MCP tools (`tron_status`, `tron_risk`, `tron_audit`, `tron_policy`) for agents to call directly through bote.

## Roadmap

### Post-release -- agnosticos integration
- [ ] Load policy from `/etc/agnos/t-ron.toml` at startup
- [ ] Hot-reload policy on SIGHUP
- [ ] agnoshi intents for natural language security queries

### Phase 2 -- Advanced Detection
- [ ] ML-based anomaly detection (train on normal patterns, flag deviations)
- [ ] Privilege escalation pattern detection (benign -> sensitive tool sequences)
- [ ] Cross-agent correlation (detect coordinated attacks)
- [ ] Prompt injection detection in tool parameters (LLM-assisted via hoosh)
- [ ] Time-of-day anomaly detection

### Phase 3 -- Hardening
- [ ] Policy signing (sigil trust verification)
- [ ] Encrypted audit log export
- [ ] Real-time alerts via daimon event bus
- [ ] Dashboard integration (aethersafha security panel)
- [ ] Edge fleet policy distribution

## Reference Code

| Source | Relevance | Location |
|--------|-----------|----------|
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer -- t-ron wraps its Dispatcher via SecurityGate | `/home/macro/Repos/bote` |
| [libro](https://github.com/MacCracken/libro) | Cryptographic audit chain -- t-ron writes every verdict to libro | `/home/macro/Repos/libro` |
| [aegis](https://github.com/MacCracken/agnosticos) `aegis.rs` | System security daemon -- t-ron is the MCP-specific complement | `userland/agent-runtime/src/aegis.rs` |
| [phylax](https://github.com/MacCracken/agnosticos) `phylax.rs` | Threat detection engine -- t-ron focuses on MCP layer | `userland/agent-runtime/src/phylax.rs` |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API and MCP tools | `/home/macro/Repos/SecureYeoman` |

## License

GPL-3.0 -- see [LICENSE](LICENSE) for details.
