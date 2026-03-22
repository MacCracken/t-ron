# Architecture Overview

## Module Map

```
t-ron
├── gate            — ToolCall, Verdict, VerdictKind, DenyCode
├── policy          — PolicyEngine, AgentPolicy, glob ACLs, TOML config
├── rate            — RateLimiter, per-agent/tool token bucket
├── scanner         — PayloadScanner (SQL, shell, template, path traversal)
├── pattern         — PatternAnalyzer (tool enumeration, privilege escalation)
├── score           — RiskScorer (rolling 0.0–1.0 per agent)
├── audit           — AuditLogger (ring buffer + libro hash chain)
├── query           — TRonQuery (read-only API for SecureYeoman)
├── middleware      — SecurityGate (wraps bote Dispatcher)
├── tools           — MCP tool definitions + handlers (tron_status/risk/audit/policy)
└── error           — TRonError
```

## Design Principles

- **Default deny** — unknown agents and tools are blocked unless explicitly allowed
- **Deny wins** — a deny pattern overrides any matching allow pattern
- **Library, not binary** — t-ron is embedded as middleware, never runs standalone
- **Dual audit** — in-memory ring buffer for fast queries, libro chain for tamper-proof trail
- **Zero unsafe** — no `unsafe` blocks anywhere
- **Thread-safe** — all public types are `Send + Sync`

## Data Flow

```
Agent request
      │
      ▼
bote Dispatcher ──► SecurityGate.dispatch(request, agent_id)
                          │
                          ▼
                    tools/call? ──no──► pass through to inner dispatcher
                          │
                         yes
                          │
                          ▼
                    TRon::check(ToolCall)
                          │
              ┌───────────┼───────────┬──────────────┬─────────────┐
              ▼           ▼           ▼              ▼             ▼
         param size    policy      rate limit    scanner       pattern
          check        ACL         (token        (injection    (anomaly
                       check       bucket)       detection)    detection)
              │           │           │              │             │
              └───────────┼───────────┴──────────────┴─────────────┘
                          ▼
                    Verdict (Allow / Deny / Flag)
                          │
                    ┌─────┴─────┐
                    ▼           ▼
              AuditLogger    response
              (ring buf +    to caller
               libro chain)
```

## Security Pipeline Order

Each check runs in sequence. A denial at any stage short-circuits — later checks are skipped.

| Step | Module | Result on Failure |
|------|--------|-------------------|
| 1 | Parameter size check | `Deny(ParameterTooLarge)` |
| 2 | Policy ACL check | `Deny(Unauthorized)` or `Flag` or pass |
| 3 | Rate limit check | `Deny(RateLimited)` |
| 4 | Payload scanning | `Deny(InjectionDetected)` |
| 5 | Pattern analysis | `Flag` (informational, allowed through) |
| 6 | Audit logging | Always runs (logs the final verdict) |

## Concurrency Model

| Component | Lock Type | Rationale |
|-----------|-----------|-----------|
| `PolicyEngine` | `std::sync::RwLock` | Read-heavy; writes only on policy reload |
| `RateLimiter` | `DashMap` (lock-free) | Per-key concurrent access, no global lock |
| `PatternAnalyzer` | `DashMap` | Per-agent histories, independent access |
| `AuditLogger` events | `tokio::sync::RwLock` | Async context; read-heavy queries |
| `AuditLogger` chain | `std::sync::Mutex` | Sync lock; fast append, no await points |

## Integration Points

| System | Integration | Direction |
|--------|------------|-----------|
| bote | `SecurityGate` wraps `Dispatcher` | t-ron intercepts bote requests |
| libro | `AuditLogger` writes to `AuditChain` | t-ron appends to libro |
| SecureYeoman | `TRonQuery` + MCP tools | SecureYeoman reads from t-ron |

## Consumers

| Personality | Usage |
|------------|-------|
| T.Ron (SecureYeoman) | Queries risk scores, audit trails, chain integrity via `TRonQuery` or MCP tools |
