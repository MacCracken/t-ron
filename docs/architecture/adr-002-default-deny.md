# ADR-002: Default Deny Policy

## Status

Accepted

## Context

MCP tool dispatch systems must decide what happens when an agent or tool is not explicitly listed in the policy configuration. The two common postures are default-allow (permissive) and default-deny (restrictive).

## Decision

t-ron defaults to **deny** for both unknown agents and unknown tools. This is configured via `TRonConfig`:

```rust
TRonConfig {
    default_unknown_agent: DefaultAction::Deny,
    default_unknown_tool: DefaultAction::Deny,
    ..
}
```

Consumers can override to `Allow` or `Flag` per their threat model.

## Consequences

- **Pro**: Fail-secure — new agents/tools are blocked until explicitly permitted
- **Pro**: Forces explicit policy authoring — no accidental access
- **Pro**: `Flag` mode available as a middle ground for monitoring without blocking
- **Con**: Requires upfront policy configuration before any agent can operate
- **Con**: Can cause confusion during development if agents are unexpectedly denied

## Rationale

In a multi-agent system, the blast radius of an over-permissive default is unbounded — any compromised or misbehaving agent could call any tool. The cost of a deny-by-default is bounded: legitimate agents need explicit policy entries, which is a one-time configuration task. The `Flag` mode provides a safe path for progressive policy development.
