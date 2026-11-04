# Threat Model

What t-ron defends, what it trusts, and where it stops. Current for
t-ron 2.2.4. The audit behind it is
[docs/audit/2026-11-03.md](../audit/2026-11-03.md).

## Trust boundaries

t-ron is a library inside an MCP service. It **trusts the embedding
service** to:

- **Authenticate the caller** and pass a trusted `agent_id` to
  `security_gate_dispatch`. t-ron checks what an agent may do, not who it
  is.
- **Own the transport**: framing, TLS, message-size limits, and bote's
  JSON-RPC parsing.
- **Drive a TRon from one thread** (see
  [overview](../architecture/overview.md#concurrency)).
- **Protect its keys**: the policy-signing public keys it trusts and the
  export signing key.

It **does not trust**:

- Tool names and arguments. Names are checked decoded, exactly as bote
  will dispatch them; arguments are size-capped and scanned.
- Agent IDs and tool names as text. An identifier that is empty, over
  256 bytes, or holds a byte outside printable ASCII, `"` or `\` is
  denied before any other check, and no more than 257 of its bytes are
  read to decide that.
- Call patterns: per-agent history and cross-agent correlation are
  monitored.
- Unknown agents and tools: denied by default (ADR-002).
- The policy file, when signed mode is on: every load and reload is
  verified.

## Attack surface

| Component | Threat | Mitigation |
|---|---|---|
| SecurityGate | An escaped tool name (`file_delete`) checked as one name and run as another | The name is decoded before the check, the way bote decodes it (2.2.3) |
| SecurityGate | A malformed `tools/call` slipping past the audit | Missing names are denied and audited (2.2.3) |
| SecurityGate | A request that names a key twice, so the check and the handler read different values | The gate checks the first `name`, as bote reads it, and scans every string leaf; bote ≥ 3.8.6 then refuses the request (`-32600`) and no handler runs (pinned by a test at 2.2.4) |
| Pipeline | An identifier with no NUL in reach | Read at most 257 bytes, then denied as too long (2.2.4) |
| Pipeline | Unknown agent under `DA_FLAG` skipping later checks | A flag is a pending verdict; rate limit, scan, pattern and correlation still run, and a later deny wins (2.2.3) |
| Pipeline | Unrecognised config or enum values | An unknown default action denies; config booleans are tested `!= 0`; an unknown verdict kind is a denial |
| Pipeline | Negative or hostile timestamps | A negative timestamp is denied; hours are computed with floor arithmetic and range-checked |
| Policy loader | A file that parses into something other than it says | Strict parser: comments are never read as values, a stray byte, unknown key, unclosed array or header is refused (2.2.3) |
| Policy loader | A truncated, empty or garbage file wiping the policy | Parsed into a fresh engine and swapped only on success; a file with no agent section is refused (2.2.3) |
| Signed policy | An unsigned file installed by SIGHUP after a signed load | Signed mode: reloads re-verify, and every unsigned loader (including the `tron_policy` MCP tool) is refused (2.2.3) |
| Signed policy | A malformed or over-long signature | Exactly 64 bytes, verified constant-time by sigil; the read buffer has room for the over-long check |
| Rate limiter | Flooding, clock skew, overflow | Per-agent, per-tool buckets; refill clamped and overflow-safe; at most 65,536 buckets, new pairs past the cap denied (2.2.3) |
| Rate limiter | A removed override persisting | A reload clears every override before applying the new ones (2.2.3) |
| Payload scanner | Encoding tricks | Each JSON string leaf is decoded before scanning; percent-decoding for traversal; nesting past 64 is a threat (2.2.3) |
| Payload scanner | Algorithmic DoS on the synchronous gate | Linear `;` and `${` scans (2.2.3) |
| Audit log | JSON forged through a crafted name | Every value is escaped (RFC 8259 §7) into the libro details, the export and the tool results (2.2.1, 2.2.3) |
| Audit log | Buffer overruns from long names | Every JSON buffer is sized from the escaped lengths it will hold (2.2.1, 2.2.3); CI fails a literal-size buffer fed by `strlen` |
| Every module | A buffer that cannot be allocated | Each input-sized buffer is checked: a deny keeps a fixed reason, a load or verification is refused, an audit field reads `<unrecorded>`, and the safety engine returns Blocked, "safety: allocation failed" (2.2.4) |
| Audit log | Chain tampering | libro's SHA-256 hash chain; `audit_verify_chain` detects any modification |
| Encrypted export | Tampering | Encrypt-then-sign; verify before decrypt; constant-time signature compare |
| Encrypted export | Nonce reuse | Pass a 0 nonce and t-ron draws one; a caller-supplied nonce must be unique per key |
| MCP tools | `tron_policy` loading arbitrary policy | Gated by the policy ACL like any tool; refused outright in signed mode |
| Safety injection detector | Phrases split or disguised: invisible characters, odd spaces, lookalike letters | Normalised before matching: invisible characters dropped, space runs collapsed (2.2.3), and 59 Cyrillic, Greek and Latin-extension lookalikes plus the fullwidth letters folded to ASCII (2.2.4) |
| Safety output validation | Output that is not well-formed UTF-8 | `require_utf8` blocks it (2.2.4; off by default) |
| LLM scan | A hostile or hung hoosh | Replies are unescaped and parsed strictly; failures are not read as clean; sockets are closed and timed out (2.2.3) |

## Known limitations

- **Pattern detection is evadable** (audit F10, 2.0.0, reconfirmed 2.2.3).
  The detectors look at the last 5, 10 and 20 calls, so spacing
  sensitive calls with benign ones, or keeping distinct tools under the
  threshold, avoids them; calls denied earlier in the pipeline are never
  recorded. A time-decayed redesign is on the roadmap.
- **Per-agent state is unbounded** in the pattern analyzer and the
  correlation detector; an agent allowed to rotate IDs grows it and resets
  its own history.
- **Allocation is never freed.** The default allocator is a bump; every
  `tron_check` allocates about a kilobyte (the libro entry is most of it)
  that a long-running process keeps. Plan restarts, or an arena, for very
  long uptimes.
- **The export envelope is not a full AEAD**: the symmetric key is not
  bound, the signature has no domain separation, and old envelopes
  replay ([ADR-005](../architecture/adr-005-chacha20-ed25519-aead.md)).
  Keep the export signing key apart from the policy-signing keys.
- **SIGHUP reload is Linux / agnos only** (signalfd). On other targets
  `sighup_init` fails and restores the signal mask.
- **The scanner is heuristic**, not a parser: sophisticated obfuscation
  can still evade it.

## Unsafe code and memory safety

Cyrius has no `unsafe` boundary: every module works with raw pointers.
t-ron's discipline is the one CLAUDE.md sets: size every buffer from what
it will hold, check every allocation that is written to, and fail closed.
Since 2.2.4 every input-sized buffer in `src/` meets the second rule; the
fixed-size constructors (a verdict, an event) fail only when the process
is out of memory and are not checked.
CI enforces two parts of it mechanically (no raw `syscall(`, no
literal-size buffer fed by `strlen`).

## Supply chain

- Every dependency is first-party (libro, bote, sigil, majra, patra) and
  pinned by tag in `cyrius.cyml`.
- `cyrius.lock` records a hash for every vendored file and a commit pin
  for every tagged dependency. CI and the release resolve with
  `cyrius deps --locked`, which fails on any difference.
- No `path` override is committed, so a local build compiles the same
  tags CI does.
