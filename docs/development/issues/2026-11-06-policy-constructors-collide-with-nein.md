# 2026-11-06 — `agent_policy_new` and `policy_engine_new` collide with nein, so a host cannot link both

**Status:** ✅ RESOLVED in t-ron **2.2.5**: `tron_agent_policy_new` and `tron_policy_engine_new`. *(Was: 🟡 OPEN.)*
*(Filed from daimon **2.5.5**, which hosts nein's tools and needs `tron_check` for its first per-consumer gate.)*
**Checked against:** t-ron **2.2.4** (`dist/t-ron.cyr`) with nein **1.9.1** (`dist/nein-mcp.cyr`), bote-core 3.8.15, on cyrius 6.7.18.
**Severity:** high for daimon: it blocks the item that closes thoth's tool-pin filing. Nothing is wrong in t-ron on its own.

## What happens

Both bundles define the same two top-level functions, with different meanings. Cyrius has one global scope.

| name | t-ron (`src/policy.cyr`) | nein (`src/lib/engine.cyr`) |
|---|---|---|
| `agent_policy_new` | `fn ()`, 24 bytes: allow, deny, rate | `fn (agent_id, agent_addr)`, 56 bytes |
| `policy_engine_new` | `fn ()`, 8 bytes: a hashmap | `fn ()`, 16 bytes: a vec and a table name |

Adding `[deps.t-ron]` to daimon, whose `cyrius.cyml` already declares nein:

```
warning:lib/nein-mcp.cyr:4306:1: duplicate fn 'policy_engine_new' (last definition wins; first defined in lib/t-ron.cyr)
error:lib/nein-mcp.cyr:4010:1: duplicate fn 'agent_policy_new' disagrees about arity: this one takes 2, the one in lib/t-ron.cyr takes 0
FAILED (compiler exit 1)
```

⛔ **The first one is the dangerous one.** Same arity, so alone it would compile, last definition winning. `tron_new`
would store nein's vec-shaped engine where `policy_check` reads a hashmap. Only the second, by luck of arity, stops the build.

## The ask

Rename t-ron's two constructors, for example to `tron_agent_policy_new` and `tron_policy_engine_new`, and tag a
release. t-ron is the right side:
- They are internal to t-ron: its only callers are `src/policy.cyr`, `src/tron.cyr` and its own tests. A search of
  thoth's `src/` finds them only inside its vendored copy of the bundle, and its code calls `tron_check` and
  `tron_load_policy`.
- nein's are public API, used by its integration tests and its consumers' firewall policies.

## Measured: that is the whole of it

In a scratch copy, `sed` renamed the two names in `dist/t-ron.cyr` and daimon took it through a `path` dep. daimon
built with **no duplicate warning of any kind** (2,518,400 bytes). `enum CircuitState` is also in both t-ron and majra, but its
constants differ (`CS_*`, `CIRCUIT_*`), and it did not warn.

## What daimon does meanwhile

daimon 2.5.5 ships per-consumer accept with tokens an operator issues, and every decision passes through one seam,
`_pin_gate` in `src/mcp_pin.cyr`, which cannot be `tron_check` yet. Until a t-ron tag has the rename, an authenticated
consumer can accept a definition for its own view only, and thoth's filing stays open. daimon will add `[deps.t-ron]` at
that tag, and call `tron_check` there.

## Related

- daimon `docs/development/issues/2026-11-06-a-client-that-loses-its-tool-pins-has-nothing-to-repair-from.md`, item 4.
- daimon `docs/adr/009-tool-definition-pins.md`.
