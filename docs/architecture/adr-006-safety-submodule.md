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
- **Circuit breaker**: `safety_circuit_breaker_new(threshold, window_secs,
  cooldown_secs)` and Closed → Open → HalfOpen state machine. A half-open
  breaker closes only on `safety_circuit_breaker_record_success(b)`; a
  violation while half-open re-opens it (2.2.3).
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

## Amendment — 2.2.3

The 2.2.3 audit found the engine failing open in several ways, and the
repair changed what some rules mean:

- **Fail closed everywhere.** An enforcement other than warn / audit-only
  blocks; `enabled` is tested `!= 0`; an unknown rule type or a malformed
  rule blocks; an unknown severity weighs 1000; an engine with no enabled
  policy blocks. Before, each of these ended in "allowed".
- **The strongest verdict wins** across all enabled policies (Blocked >
  RequiresApproval > RateLimited > Warning), in priority order, for
  actions and outputs alike.
- **Destructive commands are detected, not substring-matched.** A new
  tail rule type, `SRT_DESTRUCTIVE_COMMAND`, names a built-in detector
  ("rm-root", "mkfs", "dd-device") that tokenises the command (quotes,
  escapes, `$IFS`, brace expansion, `sh -c`, wrapper words) and checks
  flags and operands. The default forbidden policy uses them, so
  `rm -fr /` and `rm -r -f /` block and `rm -rf /tmp/build` does not.
  `rm` / `dd` are matched anywhere in a command, so `echo rm -rf /`
  blocks too: a deliberate false positive. Custom substring rules now
  see the command whitespace- and quote-normalised, parameters included.
- **Scope rules normalise paths** (`//`, `.`, `..`) and match on `/`
  boundaries; they also check path arguments of commands against the
  denied list. A relative file path is blocked by any scope rule.
  `/proc/self/root/…` aliases cannot be resolved without the filesystem.
- **Rules can filter by action type** (`safety_rule_set_action_filter`),
  and the default rate rule counts system commands by type, not by the
  substring "system".
- **Memory is bounded.** Rate buckets and the breaker's failure window
  are pruned in place and capped; rate-limited calls are not recorded.

Still open: Unicode confusable mapping in the injection detector, idle
rate-bucket eviction, and the `require_utf8` output check the Rust
original had.

## Amendment — 2.2.4

Two of those three are done, and the engine fails closed on memory too:

- **Lookalike letters fold to Latin.** `injection_normalize` maps 59
  Cyrillic, Greek, Latin-extension and IPA letters that UTS #39's
  confusables data pairs with one Latin letter, and the fullwidth Latin
  letters, to ASCII before the phrase checks.
- **`require_utf8` is real.** An output-validation rule with
  `safety_rule_set_require_utf8(rule, 1)` blocks output that is not
  well-formed UTF-8. The Rust flag never acted, since a `&str` is always
  UTF-8. `SafetyRule` grows to 88 bytes (`require_utf8` at +80), default 0.
- **A failed allocation blocks.** A helper that cannot build an
  input-sized buffer returns a harmless value and counts the failure;
  `safety_evaluate_rule`, both `safety_engine_check_*` and
  `injection_detector_check` then return a Blocked verdict, "safety:
  allocation failed", built with the engine (or an unsafe result,
  pattern `allocation_failed`). The verdict is shared: callers must not
  modify it.

Still open: bounding the rate buckets. With an allocator that never
frees, evicting idle buckets reclaims nothing; a cap does, and what a
full table does is a policy decision.
