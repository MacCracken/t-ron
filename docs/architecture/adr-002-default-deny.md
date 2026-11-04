# ADR-002: Default Deny Policy

## Status

Accepted

## Context

MCP tool dispatch systems must decide what happens when an agent or tool is not explicitly listed in the policy configuration. The two common postures are default-allow (permissive) and default-deny (restrictive).

## Decision

t-ron defaults to **deny** for both unknown agents and unknown tools. This is configured via `TRonConfig`:

```cyrius
var cfg = tron_config_default();          # both defaults are DA_DENY
tron_config_set_default_unknown_agent(cfg, DA_FLAG);   # or DA_ALLOW
```

Consumers can override to `DA_ALLOW` or `DA_FLAG` per their threat
model. A value that is none of `DA_ALLOW`, `DA_DENY` or `DA_FLAG` denies.

## Consequences

- **Pro**: Fail-secure — new agents/tools are blocked until explicitly permitted
- **Pro**: Forces explicit policy authoring — no accidental access
- **Pro**: `Flag` mode available as a middle ground for monitoring without blocking. A flagged call still goes through every later check (rate limit, payload scan, pattern, correlation), and any of them can still deny it
- **Con**: Requires upfront policy configuration before any agent can operate
- **Con**: Can cause confusion during development if agents are unexpectedly denied

## Rationale

In a multi-agent system, the blast radius of an over-permissive default is unbounded — any compromised or misbehaving agent could call any tool. The cost of a deny-by-default is bounded: legitimate agents need explicit policy entries, which is a one-time configuration task. The `Flag` mode provides a safe path for progressive policy development.

## Amendment — 2.2.3

Through 2.2.2 a `DA_FLAG` verdict for an unknown agent or tool returned
at once, so the rate limiter, payload scanner, pattern analyzer and
correlation detector never saw the call: an unknown agent under
`DA_FLAG` could send injection payloads at any rate. Since 2.2.3 a flag
is a pending verdict and the pipeline continues; a later deny wins.
Only with that is `Flag` the safe middle ground the Rationale describes.
