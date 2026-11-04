# Architecture Overview

t-ron is a Cyrius library: an MCP security gate that sits between bote's
Dispatcher and the tool handlers. Consumers take the single-file bundle
`dist/t-ron.cyr` (see [DEPS-PATTERN.md](../../DEPS-PATTERN.md)).
`src/main.cyr` also builds a small binary, `build/t-ron`, which CI uses as a
smoke test; it is not how t-ron is deployed.

## Module map

The 19 modules, in the order `cyrius.cyml [lib]` bundles them. Cyrius is
single-pass, so each module may call only those above it.

| Module | Role |
|---|---|
| `error` | `TRON_ERR_*` codes and their labels |
| `json_text` | JSON string escaping into pre-sized buffers, used everywhere t-ron writes JSON |
| `gate` | `ToolCall`, `Verdict` (allow / deny / flag), `VK_*` kinds, `DENY_*` codes |
| `policy` | Per-agent allow / deny glob lists, deny wins; the policy TOML loader |
| `rate` | Per-agent, per-tool token buckets |
| `scanner` | Payload scanning: SQL, shell, template and path-traversal injection |
| `pattern` | Per-agent call history: tool enumeration, privilege escalation (count and directed sequence), time of day |
| `audit` | The in-memory event ring buffer plus the libro hash chain; JSON and encrypted export |
| `score` | Risk score in basis points (0–1000) from an agent's audit history |
| `query` | Read-only queries over the audit log, for the T.Ron personality |
| `correlation` | Cross-agent correlation: many agents hitting one tool in a time window |
| `tron` | `TRon`, its config, and `tron_check`, the pipeline below |
| `tools` | The four MCP tools (`tron_status`, `tron_risk`, `tron_audit`, `tron_policy`): definitions and handlers |
| `middleware` | `SecurityGate`: wraps a bote Dispatcher and runs `tron_check` on every `tools/call` |
| `llm_scan` | Optional LLM-assisted scan over HTTP to a local hoosh |
| `signing` | Ed25519-signed policy files (`tron_verify_and_load_policy`) |
| `signal` | SIGHUP policy reload through a signalfd (Linux and agnos) |
| `crypto_chacha20` | The ChaCha20 keystream behind the encrypted audit export |
| `safety` | The AGNOS safety submodule: policies, rule types, the injection detector, the circuit breaker |

## Design principles

- **Default deny.** Unknown agents and unknown tools are denied unless the
  config's `default_unknown_agent` / `default_unknown_tool` say otherwise
  ([ADR-002](adr-002-default-deny.md)).
- **Deny wins.** A tool matching both an allow and a deny pattern is denied.
- **Fail closed on malformed input.** An agent ID or tool name that is
  empty, longer than 256 bytes, or holds a control byte, DEL or a non-ASCII
  byte is denied before any other check, whatever the defaults say. The
  denied call is still audited, with the identifier as sent.
- **Every verdict is audited**, allows included, to the ring buffer and the
  libro chain ([ADR-001](adr-001-dual-audit.md)).
- **No transport.** t-ron takes bote's transport-free core profile; the
  embedding service owns sockets, framing and authentication
  ([ADR-003](adr-003-bote-middleware.md)).

## Data flow

```
JSON-RPC request ──► security_gate_dispatch(gate, request, agent_id)
                              │
                   tools/call? ──no──► inner dispatcher, unchanged
                              │yes
                              ▼
                   tron_check(tron, tool_call)  ──► verdict, audited
                              │
                deny ◄────────┴────────► allow / flag
                  │                           │
   JSON-RPC error -32001                inner dispatcher → handler
   "security: <reason> [<code>]"
```

## The pipeline: `tron_check`

Checks run in order, and the first that decides returns. Every return writes
its verdict to the audit log first.

| Step | Check | Decides |
|---|---|---|
| 0 | `tron_is_safe_identifier` on agent ID and tool name | Deny (`unauthorized`) when empty, over 256 bytes, or holding a byte outside printable ASCII |
| 1 | Parameter size against `max_param_size` | Deny (`parameter_too_large`) |
| 2 | Policy: deny list, then allow list | Deny (`unauthorized`); an unknown agent or tool gets its configured default action |
| 3 | Rate limit, per agent and tool | Deny (`rate_limited`) |
| 4 | Payload scan, if `scan_payloads` | Deny (`injection_detected`) |
| 5 | Pattern analysis, if `analyze_patterns` | Flag (the call proceeds) |
| 6 | Cross-agent correlation, if `enable_correlation` | Flag (the call proceeds) |
| — | Nothing decided | Allow |

A flag from step 5 returns before step 6 runs.

## Concurrency

**t-ron is single-threaded.** Nothing in `src/` takes a lock, and several
modules keep process-wide state: lazily built keyword tables in `scanner` and
`pattern`, shared read buffers in `tron`, `signing` and `signal`, the
ChaCha20 state in `crypto_chacha20`, and the one `TRon` the MCP tool handlers
use (`tools_bind`). Drive a `TRon`, and the tool handlers, from one thread.
Running two `TRon`s on two threads still shares those buffers.

## Integration points

| System | Integration | Direction |
|---|---|---|
| bote | `SecurityGate` wraps its `Dispatcher`; t-ron's tools register in its `ToolRegistry` | t-ron intercepts bote's requests |
| libro | `audit` appends every verdict to a libro chain | t-ron writes to libro |
| sigil | Ed25519 for signed policies and the encrypted export's signature | t-ron calls sigil |
| hoosh | `llm_scan` posts payloads for an LLM verdict | optional, t-ron calls hoosh |
| SecureYeoman | The T.Ron personality reads `query_*` and calls the MCP tools | SecureYeoman reads t-ron |

## Consumers

bote (middleware), daimon (security gate), phylax (output scanning
complement), and the T.Ron personality in SecureYeoman. The integration
guide walks through wiring one: [guides/integration.md](../guides/integration.md).
