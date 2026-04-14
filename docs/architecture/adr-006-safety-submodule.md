# ADR-006: AGNOS Safety Submodule — separate from the MCP gate

## Status

Accepted · Landed in t-ron 2.0.0 as `src/safety.cyr`

## Context

t-ron's MCP gate (`middleware.cyr` + `tron_check`) is a **per-
tool-call filter**: it sees one `tools/call` request at a time and
decides allow / deny / flag based on policy, rate, injection
patterns, and historical anomalies.

The Rust code tree also carried a `safety/` submodule (900 LOC
across `types.rs`, `injection.rs`, `guardrails.rs`, `policy.rs`) that
operated at a **higher semantic layer**: given an abstract
`SafetyAction { action_type, target, parameters }`, does it violate
a set of `SafetyPolicy` rules? Rule types include forbidden actions
(`rm -rf /`), privilege escalation (user→root), resource limits
(CPU/memory), scope restrictions (deny `/etc/shadow`), content
filters, and output validation.

These are two different jobs. The MCP gate sees JSON-RPC requests;
the safety engine sees action intents that may or may not originate
from an MCP tool call. An agent can intend `rm -rf /` without ever
invoking an MCP tool — for example through a shell out of a
successfully-approved tool.

## Decision

Port the safety submodule as a single **separate** Cyrius file,
`src/safety.cyr`. It is:

- **Not invoked by `tron_check`.** The MCP gate does not call the
  safety engine; they are independent layers.
- **Used by higher-level orchestrators** (e.g. the T.Ron personality
  in SecureYeoman) that want to cross-check an action independently
  of MCP dispatch.
- **Shares nothing with the gate's state.** Safety has its own
  policy list, its own rate buckets, its own violation log.

### Structure

One file for a cross-cutting module (rather than the Rust four-file
split) because:

- Cyrius has no module visibility; everything is global. Splitting
  doesn't buy encapsulation.
- The four Rust files were <300 LOC each; consolidated into one
  file the footprint is ~800 LOC of mostly-linear code.
- Fewer include lines in `main.cyr`.

### API surface

- **Types**: `SafetySeverity`, `SafetyEnforcement`, `ActionType`,
  `SafetyRuleType`, `SafetyRule`, `SafetyPolicy`, `SafetyAction`,
  `SafetyVerdict` (tagged), `SafetyViolation`.
- **Injection detector**: `injection_detector_check(input)` returns
  a 6-pattern classifier with Unicode zero-width / directional-
  override normalization.
- **Circuit breaker**: `circuit_breaker_new(threshold, window_secs,
  cooldown_secs)` and Closed → Open → HalfOpen state machine.
- **Policy engine**: `safety_engine_new()` + `safety_engine_add_policy`
  / `safety_engine_check_action` / `safety_engine_check_output` /
  `safety_engine_agent_score_bp` / `safety_engine_record_violation`.
- **Defaults**: `safety_default_policies()` returns 5 AGNOS-standard
  policies.

## Consequences

**Good**

- Consumers pick the layer they need. `middleware.cyr` alone is
  enough for "block bad MCP tool calls." `safety.cyr` alone is
  enough for "block bad agent intents." Both together give defense
  in depth.
- The gate's latency budget (~50 µs per check) is not polluted by
  the heavier safety-engine policy sweep.
- New rule types can be added to safety without touching the MCP
  pipeline, and vice versa.

**Bad**

- Two "policy engines" in the codebase risk operator confusion. Docs
  and naming use `policy_*` for the MCP gate and `safety_*` for the
  safety engine to keep them distinct.
- A consumer that wires both must manage two independent policy
  files.

## Future work

If operational experience shows consumers always pair the two,
adding a convenience layer (`tron_plus_safety_check(tron, safety,
call)`) that funnels MCP calls through both is a straightforward
follow-up. Not in scope for 2.0.0.
