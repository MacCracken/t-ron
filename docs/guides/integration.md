# Integration Guide

Step-by-step walkthrough for embedding t-ron in a bote-based MCP
service. **Current for t-ron 2.2.3** (cyrius 6.7.18 · libro 2.11.3 ·
bote-core 3.8.1 · sigil 3.13.15).

> **Every sample in this guide is verified.** §1–§2 and the §3–§7
> program were built against `dist/t-ron.cyr` in a clean-room project
> declaring only `[deps.t-ron]`, and run, at 2.2.3 on cyrius 6.7.18,
> before being written down. The outputs quoted in §4 and §7 are that
> run's.

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
tag = "2.2.3"
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

# process before sigil (its agnosys helpers call exec_capture); sync
# before libro (cyrius is single-pass).
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

Every snippet from here to §7 is one program, built against
`dist/t-ron.cyr` in a clean-room project and run before being written
down (see the note at the top).

```cyrius
fn echo_handler(args, claims) { return args; }

fn build_gate(policy_toml) {
    var tron = tron_new(tron_config_default());
    if (tron_load_policy(tron, policy_toml) != TRON_ERR_NONE) { return 0; }

    var reg = tool_registry_new();
    var defs = tron_tool_defs();
    for (var i = 0; i < vec_len(defs); i = i + 1) {
        if (registry_register(reg, vec_get(defs, i)) != 0) { return 0; }
    }
    var echo = tool_def_new("echo", "Echo the arguments back",
        schema_new("object", vec_new(), vec_new()));
    if (registry_register(reg, echo) != 0) { return 0; }

    var d = dispatcher_new(reg);
    dispatcher_handle(d, "echo", &echo_handler);
    var gate = security_gate_new(tron, d);
    security_gate_register_tool_handlers(gate);
    return gate;
}
```

- **Check every `registry_register`.** bote 3.4.8 and later refuse a
  malformed definition and return a BoteError; ignoring the return
  leaves the tool missing from `tools/list`. Names, schema types,
  property names and `required` entries are C strings: never pass a
  `Str` (`str_from(…)`).
- **A policy is one C string.** cyrius has no adjacent-literal
  concatenation, so write the TOML with `\n` escapes (§4), or read it
  from a file.
- **The loader is strict.** A stray byte, an unknown key, an unclosed
  array or header, or a file with no `[agent."…"]` section is refused
  with `TRON_ERR_POLICY_CONFIG`, and the policy already loaded stays.
- **One TRon per thread.** t-ron takes no locks and keeps process-wide
  buffers ([overview](../architecture/overview.md#concurrency)), and
  the MCP tool handlers serve the one TRon the last
  `security_gate_register_tool_handlers` bound.

## 4. Dispatch

The embedding service owns the transport. Hand each JSON-RPC line, with
the caller's identity, to the gate:

```cyrius
fn handle_line(gate, agent_id, line) {
    var req = codec_parse_request(line);
    if (req == 0) { return 0; }
    return codec_serialize_response(security_gate_dispatch(gate, req, agent_id));
}
```

With the policy
`"[agent.\"web-agent\"]\nallow = [\"echo\", \"tron_*\"]\ndeny = [\"aegis_*\"]\n"`,
a `tools/call` of `echo` from `web-agent` reaches the handler, and bote
wraps its bare JSON in a text block:

```json
{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"msg\":\"hi\"}"}]}}
```

A denied call returns JSON-RPC error `-32001`, message
`security: <reason> [<deny_code>]`:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"security: unknown agent [unauthorized]"}}
{"jsonrpc":"2.0","id":2,"error":{"code":-32001,"message":"security: tool 'aegis_scan' denied by policy for agent 'web-agent' [unauthorized]"}}
```

Deny codes: `unauthorized`, `rate_limited`, `injection_detected`,
`tool_disabled`, `anomaly_detected`, `parameter_too_large`. The gate
checks the tool name **decoded**, as bote will run it, so an escaped
spelling cannot slip past a deny entry. `agent_id` is trusted as given:
authenticate the caller before you pass it in.

## 5. Signed policies (recommended for production)

Sign the policy offline (any Ed25519 tool producing a raw 64-byte
signature; sigil's `ed25519_sign` is fine) and ship `policy.toml` with
`policy.toml.sig` beside it:

```cyrius
var verifier = policy_verifier_new();
policy_verifier_add_key(verifier, trusted_pk);      # 32-byte Ed25519 key

var tron = tron_new(tron_config_default());
var rc = tron_verify_and_load_policy(tron, verifier, "/etc/t-ron/policy.toml");
if (rc != TRON_ERR_NONE) {
    return 1;                                       # fail closed: do not start
}
```

A verified load puts the TRon in **signed mode**: every reload
re-verifies the file, and the unsigned loaders (`tron_load_policy`,
`tron_load_policy_file`, and so the `tron_policy` MCP tool) return
`TRON_ERR_SIGNATURE` instead of replacing the signed policy. A tampered
file is refused with `TRON_ERR_SIGNATURE` and the loaded policy stays.

## 6. SIGHUP hot-reload (optional)

```cyrius
var fd = sighup_init();      # blocks SIGHUP, returns a non-blocking signalfd

# ... in your event loop, wake on fd readable:
var rc = sighup_drain_and_reload(fd, tron);
```

Call `sighup_init` **before starting any thread**: it blocks SIGHUP for
the calling thread, and only threads created afterwards inherit that.
A reload re-reads the path the last successful load used; in signed
mode it re-verifies it. On any failure (unreadable file, bad signature,
a file that does not parse) `rc` says why and the loaded policy stays.

## 7. Query from the T.Ron personality

```cyrius
var audit = tron_audit(security_gate_tron(gate));

var events  = query_total_events(audit);
var denials = query_total_denials(audit);
var score   = query_agent_risk_score(audit, "web-agent");   # 0..1000
var recent  = query_recent_events(audit, 20);
var trail   = query_agent_audit(audit, "web-agent", 50);
```

Or call the `tron_status` / `tron_risk` / `tron_audit` / `tron_policy`
MCP tools through the gate. Each returns a JSON document in a text
block; `tron_status` after the calls above returns
`{"total_events":4,"total_denials":2,"status":"active"}`.

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
