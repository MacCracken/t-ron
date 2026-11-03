# Integration Guide

Step-by-step walkthrough for embedding t-ron in a bote-based MCP
service. **Current for t-ron 2.2.1** (cyrius 6.7.18 · libro 2.11.3 ·
bote-core 3.8.0 · sigil 3.13.15).

> ⚠️ **Rewritten at 2.1.9.** Through 2.1.8 this guide still described
> the 2.0.0 shape: a `cyrius.toml` manifest, cyrius 4.8.4, and
> per-module source pulls (`lib/libro_chain.cyr`, `lib/bote_dispatch.cyr`,
> `lib/json.cyr`, …). None of that resolves any more — the manifest is
> `cyrius.cyml`, libro and bote ship single-file dist bundles, and
> `json` / `base64` / `bigint` folded into `bayan` at the 2.1.6 carve.
> The §1–§2 sample is **verified**: it was built and run against
> t-ron 2.2.1 on cyrius 6.7.18, in a clean-room project, before being
> written down. (Re-verifying it at 2.1.11 caught that its `if`
> condition lacked the parentheses cyrius requires.) §3 is **not** —
> see the warning there.

## 1. Add t-ron to your project

Add one block to your `cyrius.cyml`:

```toml
[package]
name = "your-service"
version = "0.1.0"
language = "cyrius"
# t-ron 2.2.x needs cyrius >= 6.7.2
cyrius = "6.7.18"

[build]
entry = "src/main.cyr"
output = "build/your-service"

[deps.t-ron]
git = "https://github.com/MacCracken/t-ron.git"
tag = "2.2.1"
modules = ["dist/t-ron.cyr"]
```

That is the whole dep declaration. `cyrius distlib` ships
`dist/t-ron.deps` alongside the bundle, and since cyrius 6.5.x
`cyrius deps` reads it to resolve the stdlib **and** t-ron's own named
deps (libro, bote-core, sigil — and through them majra and patra). You do **not**
need a `[deps] stdlib` array, and you do **not** need your own
`[deps.libro]` / `[deps.bote-core]` / `[deps.sigil]` blocks. If your
own code calls stdlib modules directly, list those in a `[deps] stdlib`
of your own: since 2.1.12 t-ron's sidecar names only the three leaves
its bundle needs (see [DEPS-PATTERN.md](../../DEPS-PATTERN.md)).

Add an explicit `[deps.*]` pin only if your service calls that library
directly and wants to control its version — and then pin the **same
tag** t-ron does, or you will vendor two copies.

Then resolve:

```sh
cyrius deps                    # vendors everything to ./lib/
```

Expect `6 deps resolved` and a populated `./lib/`.

## 2. Wire the gate

Cyrius resolves forward references in a **single pass**, so include
order is load-bearing. This is the order t-ron itself uses; copy it:

```cyrius
include "lib/string.cyr"
include "lib/fmt.cyr"
include "lib/alloc.cyr"
include "lib/vec.cyr"
include "lib/str.cyr"
include "lib/slice.cyr"
include "lib/syscalls.cyr"
include "lib/io.cyr"
include "lib/args.cyr"
include "lib/tagged.cyr"
include "lib/assert.cyr"
include "lib/fnptr.cyr"
include "lib/hashmap.cyr"
include "lib/regex.cyr"
include "lib/chrono.cyr"
include "lib/freelist.cyr"
include "lib/sakshi.cyr"
include "lib/bayan.cyr"          # json / base64 / bigint since 2.1.6
include "lib/net.cyr"

# atomic / thread / thread_local MUST precede sigil — sigil's hash path
# self-installs a per-thread TLS scratch bank. Omit them and the SHA-256
# inside libro's chain_append traps with SIGILL at *runtime*, not at
# compile time.
include "lib/atomic.cyr"
include "lib/thread.cyr"
include "lib/thread_local.cyr"

# ct / keccak / random MUST also precede sigil (ML-DSA surface).
include "lib/ct.cyr"
include "lib/keccak.cyr"
include "lib/random.cyr"

# fs / process / sync precede libro (cyrius is single-pass).
include "lib/fs.cyr"
include "lib/process.cyr"
include "lib/sync.cyr"

include "lib/sigil.cyr"
include "lib/libro.cyr"
include "lib/bote-core.cyr"      # transport-free profile
include "lib/t-ron.cyr"          # the dist bundle
```

Then use the gate:

```cyrius
fn main() {
    var cfg = tron_config_default();
    var t   = tron_new(cfg);

    var c = tool_call_new("agent-id", "ark_install", "{}", 1700000000);
    var v = tron_check(t, c);

    if (verdict_is_denied(v) == 1) {
        # refuse the call; verdict_reason(v) explains why
        return 1;
    }
    return 0;
}
```

⚠️ **`tron_check` takes two arguments** — the monitor and a
`tool_call_new(agent_id, tool_name, params, timestamp)` struct, not
loose strings. An unregistered agent calling a sensitive tool returns
`deny`; that is the default-deny posture from
[ADR-002](../architecture/adr-002-default-deny.md), not a
misconfiguration.

## 3. Construct the gate

> ⚠️ **Not verified — at 2.1.11 this sample did not compile as
> written, and it was not re-tested at 2.1.12, 2.2.0 or 2.2.1.** cyrius rejected the multi-line string passed to
> `tron_load_policy` (`expected ')', got string`), and
> `your_echo_handler` predates the bote 2.0 `fn h(args, claims)`
> handler ABI. Build the policy string explicitly and give handlers
> both parameters until this section is rewritten.

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
    var reg = tool_registry_new();   # renamed from registry_new at bote 2.7.4
    var defs = tron_tool_defs();
    var i = 0;
    while (i < vec_len(defs)) {
        registry_register(reg, vec_get(defs, i));
        i = i + 1;
    }
    registry_register(reg, tool_def_new(
        "echo", "Echo the arguments back",
        schema_new("object", vec_new(), vec_new())));

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
