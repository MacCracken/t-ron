# t-ron Examples

Each file in this directory is a self-contained, runnable Cyrius
program that demonstrates one aspect of t-ron. All examples build
against the same `cyrius.toml` at the repo root (`cyrius build
docs/examples/NAME.cyr build/NAME`).

| File | Shows |
|---|---|
| [`01-minimal-gate.cyr`](01-minimal-gate.cyr) | The smallest usable pipeline: build a TRon, load a policy, run one check. |
| [`02-signed-policy.cyr`](02-signed-policy.cyr) | `tron_verify_and_load_policy` end-to-end — generate keypair, sign a policy, verify + load. |
| [`03-audit-export.cyr`](03-audit-export.cyr) | Log a few events, encrypt + sign the export, decrypt + verify. |
| [`04-safety-check.cyr`](04-safety-check.cyr) | AGNOS safety engine: load defaults, check an action, inspect the verdict. |

Running any example:

```sh
cyrius build docs/examples/01-minimal-gate.cyr build/ex01
./build/ex01
```

All examples exit with status 0 on success.
