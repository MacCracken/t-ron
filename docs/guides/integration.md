# Integration Guide

Step-by-step walkthrough for embedding t-ron in a bote-based MCP
service. Current for t-ron 2.0.0 (Cyrius port) + bote 2.4.0.

## 1. Add t-ron to your project

In a Cyrius project (one with a `cyrius.toml` at the root), add
t-ron to your dep set. Pin every dep to a tag for reproducibility:

```toml
[package]
name = "your-service"
version = "0.1.0"
language = "cyrius"
cyrius = "4.8.1"

[build]
entry = "src/main.cyr"
output = "your-service"

[deps]
stdlib = [
    "string", "fmt", "alloc", "vec", "str", "syscalls", "io", "args",
    "assert", "tagged", "hashmap", "regex", "fnptr", "chrono",
    "freelist", "sakshi", "bigint", "json", "base64", "sigil", "net"
]

[deps.libro]
git = "https://github.com/MacCracken/libro"
path = "../libro"
tag = "1.0.3"
modules = [
    "src/error.cyr", "src/hasher.cyr", "src/entry.cyr",
    "src/verify.cyr", "src/chain.cyr", "src/query.cyr",
    "src/retention.cyr", "src/review.cyr",
]

[deps.bote]
git = "https://github.com/MacCracken/bote"
path = "../bote"
tag = "2.4.0"
modules = [
    "src/error.cyr", "src/protocol.cyr", "src/jsonx.cyr",
    "src/codec.cyr", "src/registry.cyr", "src/events.cyr",
    "src/audit.cyr", "src/dispatch.cyr", "src/schema.cyr",
]

[deps.t-ron]
git = "https://github.com/MacCracken/t-ron"
path = "../t-ron"
tag = "2.0.0"
modules = [
    "src/error.cyr", "src/gate.cyr", "src/policy.cyr",
    "src/rate.cyr", "src/scanner.cyr", "src/pattern.cyr",
    "src/audit.cyr", "src/score.cyr", "src/query.cyr",
    "src/correlation.cyr", "src/tron.cyr", "src/tools.cyr",
    "src/middleware.cyr",
]
```

Then resolve:

```sh
cyrius deps                    # vendors everything to ./lib/
```

## 2. Wire the gate

Your `src/main.cyr` needs the stdlib includes, the libro + bote
modules (vendored with `libro_` / `bote_` prefixes by the deps
resolver), and the t-ron modules in the right order:

```cyrius
include "lib/string.cyr"
include "lib/fmt.cyr"
include "lib/alloc.cyr"
include "lib/vec.cyr"
include "lib/str.cyr"
include "lib/syscalls.cyr"
include "lib/io.cyr"
include "lib/tagged.cyr"
include "lib/fnptr.cyr"
include "lib/hashmap.cyr"
include "lib/regex.cyr"
include "lib/chrono.cyr"
include "lib/freelist.cyr"
include "lib/sakshi.cyr"
include "lib/bigint.cyr"
include "lib/json.cyr"
include "lib/base64.cyr"
include "lib/sigil.cyr"

# libro
include "lib/libro_error.cyr"
include "lib/libro_hasher.cyr"
include "lib/libro_entry.cyr"
include "lib/libro_verify.cyr"
include "lib/libro_chain.cyr"
include "lib/libro_query.cyr"
include "lib/libro_retention.cyr"
include "lib/libro_review.cyr"

# bote
include "lib/bote_error.cyr"
include "lib/bote_protocol.cyr"
include "lib/bote_jsonx.cyr"
include "lib/bote_codec.cyr"
include "lib/bote_registry.cyr"
include "lib/bote_events.cyr"
include "lib/bote_audit.cyr"
include "lib/bote_dispatch.cyr"
include "lib/bote_schema.cyr"

# t-ron (via dep vendor these are lib/tron_*.cyr; shown here as src/
# for the in-tree case)
include "src/error.cyr"
include "src/gate.cyr"
include "src/policy.cyr"
include "src/rate.cyr"
include "src/scanner.cyr"
include "src/pattern.cyr"
include "src/audit.cyr"
include "src/score.cyr"
include "src/query.cyr"
include "src/correlation.cyr"
include "src/tron.cyr"
include "src/tools.cyr"
include "src/middleware.cyr"
```

## 3. Construct the gate

```cyrius
fn your_echo_handler(args) { return args; }

fn build_gate() {
    alloc_init();

    # Default config: deny unknown agents, scan payloads, analyze patterns.
    var cfg = tron_config_default();
    var tron = tron_new(cfg);

    # Load your policy TOML.
    tron_load_policy(tron,
        "[agent.\"web-agent\"]\n"
        "allow = [\"tarang_*\", \"rasa_*\"]\n"
        "deny  = [\"aegis_*\", \"phylax_*\"]\n"
        "\n"
        "[agent.\"web-agent\".rate_limit]\n"
        "calls_per_minute = 60\n");

    # Build a bote registry with t-ron's tool defs + yours.
    var reg = registry_new();
    var defs = tron_tool_defs();
    var i = 0;
    while (i < vec_len(defs)) {
        registry_register(reg, vec_get(defs, i));
        i = i + 1;
    }
    registry_register(reg, tool_def_new(
        "echo", "Echo the arguments back",
        schema_new(str_from("object"), vec_new(), vec_new())));

    # Wire handlers on the dispatcher.
    var d = dispatcher_new(reg);
    dispatcher_handle(d, "echo", &your_echo_handler);

    # Wrap everything with the security gate.
    var gate = security_gate_new(tron, d);
    security_gate_register_tool_handlers(gate);
    return gate;
}
```

## 4. Dispatch

```cyrius
fn handle_request(gate, agent_id, request) {
    return security_gate_dispatch(gate, request, agent_id);
}
```

Allowed calls reach your handler; denied calls return a JSON-RPC
error with code `-32001` and message `security: <reason>
[<deny_code>]`. Deny codes: `unauthorized`, `rate_limited`,
`injection_detected`, `tool_disabled`, `anomaly_detected`,
`parameter_too_large`.

## 5. Signed policies (optional but recommended)

For production, load a signed policy file instead of a TOML string:

```cyrius
include "src/signing.cyr"

# Build the verifier with one or more trusted Ed25519 public keys.
var verifier = policy_verifier_new();
policy_verifier_add_key(verifier, your_trusted_pk);

# This verifies /etc/t-ron.toml.sig against /etc/t-ron.toml before
# touching the policy engine.
var rc = tron_verify_and_load_policy(tron, verifier, "/etc/t-ron.toml");
if (rc != TRON_ERR_NONE) {
    # fail-closed: do NOT start the gate on signature failure
    return 1;
}
```

Sign the policy offline with any Ed25519 tool that produces raw
64-byte signatures (sigil's `ed25519_sign` is fine).

## 6. SIGHUP hot-reload (optional)

```cyrius
include "src/signal.cyr"

var fd = sighup_init();      # blocks SIGHUP, returns non-blocking signalfd

# ... in your event loop, wake on fd readable:
sighup_drain_and_reload(fd, tron);
```

A SIGHUP re-reads the previously loaded file path. If you used
`tron_verify_and_load_policy`, wrap the reload with the same
verifier.

## 7. Query from the T.Ron personality

```cyrius
var audit = tron_audit(tron);

var score_bp = query_agent_risk_score(audit, "web-agent");  # 0..=1000
var events   = query_recent_events(audit, 20);
var denials  = query_total_denials(audit);
var trail    = query_agent_audit(audit, "data-pipeline", 50);
```

Or via MCP: call the `tron_status` / `tron_risk` / `tron_audit` /
`tron_policy` tools through bote.

## Policy TOML reference

Policies are TOML with per-agent `[agent."NAME"]` sections. Rules:

- **Deny wins** — a tool matching both allow and deny is denied.
- **Glob suffix only** — `tarang_*` matches anything starting with
  `tarang_`. Infix and prefix globs are not supported.
- **Exact match** — `tarang_probe` matches only `tarang_probe`.
- **Wildcard** — `*` matches everything.
- **Unknown tool** — if an agent exists but the tool matches neither
  allow nor deny, the `default_unknown_tool` config applies.
- **Rate limit** — optional `[agent."NAME".rate_limit]` block with
  `calls_per_minute = N`.

```toml
[agent."reader"]
allow = ["tarang_*", "rasa_read"]

[agent."admin"]
allow = ["*"]
deny = ["ark_remove"]

[agent."restricted"]
allow = ["tarang_probe"]
deny  = ["*"]                     # deny-all except tarang_probe

[agent."limited"]
allow = ["*"]

[agent."limited".rate_limit]
calls_per_minute = 30
```

## DefaultAction table

| Value | Behavior |
|---|---|
| `DA_DENY` | Block the call, return JSON-RPC error, record audit deny |
| `DA_FLAG` | Allow through, record audit flag, does NOT block |
| `DA_ALLOW` | Allow through, record audit allow |

The default for both unknown agents and unknown tools is `DA_DENY`.

## Build + verify

```sh
cyrius deps
cyrius build src/main.cyr build/your-service

# Tests against the embedded t-ron
cyrius test tests/your-service.tcyr
```

## See also

- [testing.md](testing.md) — writing t-ron-facing tests
- [../architecture/overview.md](../architecture/overview.md) — module map and data flow
- [../examples/](../examples/) — runnable demos (01 minimal gate,
  02 signed policy, 03 encrypted export, 04 safety check)
- [../architecture/adr-003-bote-middleware.md](../architecture/adr-003-bote-middleware.md) — why the gate wraps bote rather than hooks into it
