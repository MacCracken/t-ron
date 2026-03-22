# Threat Model

## Trust Boundaries

t-ron operates at the **library boundary**. It trusts the calling application to:
- Authenticate agents and provide a trusted `agent_id` to `SecurityGate::dispatch()`
- Register tool definitions correctly in bote's `ToolRegistry`
- Protect the `tron_policy` MCP tool from unauthorized callers (via policy ACLs)

t-ron does NOT trust:
- Agent-provided tool parameters (scanned for injection)
- Tool call patterns (monitored for anomalies)
- Unknown agents or tools (denied by default)

## Attack Surface

| Component | Risk | Mitigation |
|-----------|------|------------|
| Policy engine | Malformed TOML crashes loader | `toml::from_str` returns `Result`; errors propagated |
| Policy engine | Empty TOML wipes all policy | `tron_policy` handler rejects empty input |
| Rate limiter | Bucket exhaustion via flooding | Per-agent, per-tool isolation; legitimate agents unaffected |
| Payload scanner | Regex bypass via encoding | Case-insensitive URL decoding; multi-pattern coverage |
| Payload scanner | ReDoS via crafted input | Regex patterns avoid catastrophic backtracking; `regex` crate has linear-time guarantee |
| Pattern analyzer | History memory exhaustion | Ring buffer capped at 100 entries per agent |
| Audit logger | Ring buffer overflow | Capped at 10k; oldest events evicted (libro chain retains all) |
| Audit logger | Chain tampering | libro SHA-256 hash chain; `verify_chain()` detects any modification |
| MCP tools | `tron_policy` privilege escalation | Tool calls go through security pipeline; unauthorized agents are denied |
| SecurityGate | Missing tool name | Rejected at gate level before pipeline |
| SecurityGate | Agent ID spoofing | Out of scope — caller must authenticate (transport layer responsibility) |

## Scanner Coverage

| Injection Type | Patterns | Case Sensitive |
|----------------|----------|----------------|
| SQL injection | UNION/SELECT/INSERT/DROP + FROM/INTO/TABLE/WHERE/SET | No (`(?i)`) |
| Shell injection | `; & \| \` $` + dangerous commands (rm, curl, bash, etc.) | Yes (command names) |
| Template injection | Jinja2 `{{...}}`, ERB `<% %>`, `${...}` with builtins | Mixed |
| Path traversal | `../`, `..\`, `%2e%2e` (any case) | No (`(?i)`) |

## Known Limitations

- Scanner uses regex heuristics, not AST parsing. Sophisticated obfuscation may bypass detection.
- Pattern analyzer uses fixed thresholds (15/20 distinct tools, 3/5 sensitive tools). Not ML-based.
- Rate limiter uses in-memory token buckets. State is lost on restart.
- `RateLimitPolicy` in TOML config is parsed but not yet wired to the rate limiter (commented out, planned for future).

## Unsafe Code

None. The crate contains zero `unsafe` blocks.

## Supply Chain

- `cargo-deny` configured in `deny.toml` — license allowlist, unknown registry/git source denial
- `make audit` runs `cargo audit` for known vulnerabilities
- Minimal dependency surface; heaviest deps (bote, libro) are first-party
