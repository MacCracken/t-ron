# ADR-001: Dual Audit Storage (Ring Buffer + Libro Chain)

## Status

Accepted

## Context

t-ron's audit logger needs to serve two distinct use cases:

1. **Operational queries** — risk scoring, recent events, per-agent filtering. These need fast iteration over typed `SecurityEvent` structs with `VerdictKind` fields. Called on every tool dispatch cycle.

2. **Tamper-proof audit trail** — cryptographic proof that no events have been modified or deleted. Required for compliance and forensic analysis.

libro provides the tamper-proof hash chain but its `AuditEntry` is a generic struct (source/action/details JSON). Extracting `VerdictKind` from JSON on every risk score calculation would be fragile and slow.

## Decision

Use dual storage:

- **`VecDeque<SecurityEvent>`** (tokio RwLock) — in-memory ring buffer capped at 10k entries for fast operational queries. Typed fields (`VerdictKind`, `tool_name`) enable direct iteration without JSON parsing.

- **`libro::AuditChain`** (std Mutex) — append-only hash-linked chain for tamper-proof audit trail. Maps verdicts to libro severity (Allow→Info, Flag→Warning, Deny→Security) with tool details in JSON.

Every `log()` call writes to both stores atomically.

## Consequences

- **Pro**: Risk scoring stays O(n) on typed fields, no JSON parsing
- **Pro**: Chain integrity verification available via `verify_chain()`
- **Pro**: Ring buffer eviction doesn't affect chain integrity
- **Con**: ~2x memory for audit data (acceptable at 10k event cap)
- **Con**: Two lock acquisitions per log (mitigated: std Mutex for chain is fast, no await points)

## Alternatives Considered

- **libro only**: Would require parsing VerdictKind from action strings or details JSON on every risk score call. Rejected for performance and fragility.
- **Ring buffer only**: No tamper detection. Rejected for security requirements.
- **libro with typed wrapper**: Would require upstream changes to libro to support generic typed payloads. Over-engineered for current needs.
