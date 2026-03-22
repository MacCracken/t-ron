# T-Ron

> **T-Ron** (the security program that fights the MCP) -- MCP security monitor for AGNOS

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)

T-Ron is a security middleware library that sits between [bote](https://github.com/MacCracken/bote) (MCP protocol layer) and tool handlers, enforcing per-agent permissions, rate limiting, payload scanning, pattern analysis, and auditing every call. Named after Tron, the security program that fights the Master Control Program.

## Architecture

```
Agent --> bote (MCP protocol) --> t-ron (security gate) --> tool handler
                                    |-- policy check (per-agent ACLs)
                                    |-- rate limiting (token bucket)
                                    |-- payload scanning (injection detection)
                                    |-- pattern analysis (anomaly detection)
                                    '-- audit logging (libro chain)
```

T-Ron is a **library crate** -- no HTTP server, no CLI, no binary. Consumers embed it as middleware in their MCP tool dispatch pipeline. The SecureYeoman T.Ron personality queries it for security insights.

## Quick Start

```rust
use t_ron::{TRon, TRonConfig, DefaultAction, gate::ToolCall};

// Create monitor with deny-by-default policy
let tron = TRon::new(TRonConfig::default());

// Load per-agent ACLs from TOML
tron.load_policy(r#"
[agent."web-agent"]
allow = ["tarang_*", "rasa_*"]
deny = ["aegis_*", "phylax_*"]
"#)?;

// Check every tool call before dispatch
let call = ToolCall {
    agent_id: "web-agent".to_string(),
    tool_name: "tarang_probe".to_string(),
    params: serde_json::json!({"path": "/media/video.mp4"}),
    timestamp: chrono::Utc::now(),
};

let verdict = tron.check(&call).await;
if verdict.is_denied() {
    // Block the call
}

// Query API for the T.Ron SecureYeoman personality
let query = tron.query();
let risk = query.agent_risk_score("web-agent").await;
let events = query.recent_events(50).await;
```

## Features

- **Policy Engine** -- per-agent ACLs with glob pattern matching (`tarang_*`), deny-wins-over-allow semantics, TOML configuration
- **Rate Limiter** -- per-agent, per-tool token bucket with configurable rates (default 60 calls/minute)
- **Payload Scanner** -- regex-based injection detection: SQL injection, shell injection, template injection, path traversal
- **Pattern Analyzer** -- anomaly detection on tool call sequences: tool enumeration detection, privilege escalation monitoring
- **Risk Scoring** -- rolling per-agent threat score (0.0 = trusted, 1.0 = hostile) based on audit history
- **Audit Logger** -- every call and verdict logged with UUID, timestamp, agent, tool, verdict, and reason
- **Query API** -- read-only interface for the T.Ron personality in SecureYeoman to query security state
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
```

## Roadmap

### Phase 1 -- Integration (current)
- [ ] libro audit chain integration (cryptographic hash chain)
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
| [bote](https://github.com/MacCracken/bote) | MCP protocol layer -- t-ron sits as middleware | `/home/macro/Repos/bote` |
| [libro](https://github.com/MacCracken/libro) | Audit chain -- t-ron will write to libro | `/home/macro/Repos/libro` |
| [aegis](https://github.com/MacCracken/agnosticos) `aegis.rs` | System security daemon -- t-ron is the MCP-specific complement | `userland/agent-runtime/src/aegis.rs` |
| [phylax](https://github.com/MacCracken/agnosticos) `phylax.rs` | Threat detection engine -- t-ron focuses on MCP layer | `userland/agent-runtime/src/phylax.rs` |
| [SecureYeoman](https://github.com/MacCracken/SecureYeoman) | T.Ron personality consumes query API | `/home/macro/Repos/SecureYeoman` |

## License

GPL-3.0 -- see [LICENSE](LICENSE) for details.
