# Security Policy

## Scope

t-ron is a security middleware library for MCP tool call dispatch. It enforces
per-agent permissions, rate limiting, payload scanning, pattern analysis, and
tamper-proof audit logging via libro hash chains.

The primary security-relevant surface areas are:

- **Injection detection** — regex-based scanning for SQL, shell, template
  injection and path traversal in tool parameters.
- **Policy enforcement** — per-agent ACLs with glob matching; deny-wins
  semantics.
- **Audit integrity** — libro cryptographic hash chain for tamper detection.
- **Concurrency safety** — concurrent access to rate limiter, pattern analyzer,
  and audit logger via `DashMap`, `RwLock`, and `Mutex`.
- **Serialisation boundaries** — TOML policy parsing, JSON parameter scanning.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.22.x  | Yes       |
| < 0.22  | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in t-ron, please report it
responsibly:

1. **Email** [security@agnos.dev](mailto:security@agnos.dev) with a description
   of the issue, steps to reproduce, and any relevant context.
2. **Do not** open a public issue for security vulnerabilities.
3. You will receive an acknowledgment within **48 hours**.
4. We follow a **90-day disclosure timeline**. We will work with you to
   coordinate public disclosure after a fix is available.

## Security Design

- No `unsafe` code in the library.
- All public types are `Send + Sync` (enforced by usage in async contexts).
- Default deny posture — unknown agents and tools are blocked unless explicitly
  allowed.
- Deny-wins semantics — a deny pattern always overrides a matching allow.
- Payload scanner uses the `regex` crate which guarantees linear-time matching
  (no ReDoS).
- Audit chain uses libro's SHA-256 hash linking with length-prefixed fields
  and canonical JSON for deterministic, tamper-evident logging.
- `cargo-deny` enforces license allowlist and denies unknown registries.
