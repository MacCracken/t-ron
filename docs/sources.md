# Sources & citations

Where t-ron's algorithms, protocols, and attack classes come from.
This file is required per AGNOS first-party-standards for security
and cryptographic modules; keep it current as specifications evolve.

## Cryptography

- **ChaCha20 stream cipher** — RFC 7539 §2.3 and §2.4. Test vector
  in §2.4.2 ("Ladies and Gentlemen…"). Implemented in
  `src/crypto_chacha20.cyr`; verification in
  `tests/t-ron-crypto.tcyr:test_chacha20_rfc_vector`.
  <https://datatracker.ietf.org/doc/html/rfc7539>
- **Ed25519** — RFC 8032 (Edwards-curve Digital Signature Algorithm).
  Used via sigil's `ed25519_sign` / `ed25519_verify` (Cyrius stdlib).
  sigil is the reviewed constant-time implementation; t-ron does not
  re-implement Ed25519.
  <https://datatracker.ietf.org/doc/html/rfc8032>
- **SHA-256** — FIPS 180-4. Used via libro's hasher (and indirectly
  through sigil where needed).
  <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
- **UUID v4** — RFC 4122. libro's `uuid_v4` uses `/dev/urandom`;
  fail-closed on short read (audit F2).
  <https://datatracker.ietf.org/doc/html/rfc4122>
- **AEAD construction** — Sign-then-Encrypt with Ed25519 + ChaCha20
  as documented in [ADR-005](architecture/adr-005-chacha20-ed25519-aead.md).
  Alternative to ChaCha20-Poly1305 (RFC 7539 §2.8), chosen to reuse
  sigil rather than re-implement Poly1305.

## Protocols

- **MCP (Model Context Protocol)** — the JSON-RPC 2.0 surface t-ron
  protects. Requests include `tools/call`, `tools/list`, `initialize`.
  <https://spec.modelcontextprotocol.io/>
- **JSON-RPC 2.0** — bote's wire format; t-ron denies produce a
  standards-compliant error response (code -32001, server-defined
  range).
  <https://www.jsonrpc.org/specification>
- **RFC 3339 / ISO 8601** — audit-chain timestamps use libro's
  `timestamp_rfc3339`.
  <https://datatracker.ietf.org/doc/html/rfc3339>
- **TOML 1.0** — policy file format (subset: only `[agent."NAME"]`
  and `[agent."NAME".rate_limit]` sections used).
  <https://toml.io/en/v1.0.0>

## Attack classes (security audit)

Every finding in `docs/audit/2026-04-14.md` cites the real-world
advisory or CVE that motivated the check. Reproduced here for quick
reference:

- **Tool poisoning / description smuggling** — Invariant Labs (2025).
  <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- **Cross-server tool shadowing (rug-pull)** — practical-devsecops +
  Netskope hostile-tools piece.
- **CVE-2025-6514** — mcp-remote RCE class (JFrog).
  <https://jfrog.com/blog/2025-6514-critical-mcp-remote-rce-vulnerability/>
- **CVE-2025-53109 / 53110 EscapeRoute** — Anthropic Filesystem MCP
  prefix-check bypass (Cymulate).
  <https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/>
- **libinjection bypass** — WAF.NINJA fuzz + Novikov writeup.
- **JSON-in-SQL (JS-ON) bypass** — Claroty.
  <https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf>
- **Overlong UTF-8** — SEC Consult Airlock advisory; CVE-2024-34078.
- **CVE-2024-38819** — Spring Framework double-encoded path
  traversal (HeroDevs).
- **CVE-2020-28493** — Jinja2 ReDoS (Snyk).
- **CVE-2020-12762** — json-c integer overflow (Red Hat).
- **CVE-2025-52999** — Jackson JSON DoS via stack overflow (HeroDevs).
- **CVE-2015-8851** — UUID predictability class.
- **Tamper-evident logging** — Crosby & Wallach, USENIX 2009.
  <https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf>
- **Trusting Trust** — Thompson + Wheeler's Diverse Double-Compiling.
  <https://research.swtch.com/nih>

## Related AGNOS projects

- **bote** — MCP JSON-RPC dispatcher (Cyrius).
  <https://github.com/MacCracken/bote>
- **libro** — cryptographic audit chain (Cyrius).
  <https://github.com/MacCracken/libro>
- **hoosh** — LLM inference gateway (Cyrius), used by `llm_scan.cyr`.
  <https://github.com/MacCracken/hoosh>
- **sigil** — Ed25519 + SHA-256 primitives (Cyrius stdlib).
- **SecureYeoman / T.Ron personality** — consumer of the query API
  and MCP tools. <https://github.com/MacCracken/SecureYeoman>
- **Cyrius** — language toolchain.
  <https://github.com/MacCracken/cyrius>
- **agnosticos** — AGNOS ecosystem philosophy & standards.
  <https://github.com/MacCracken/agnosticos>
