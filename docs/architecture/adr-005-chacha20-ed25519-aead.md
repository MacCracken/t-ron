# ADR-005: ChaCha20 + Ed25519 as the Encrypted-Export AEAD

## Status

Accepted · Landed in t-ron 2.0.0

## Context

The Rust version of `AuditLogger` exposed an optional
`export_encrypted(key: &[u8; 32]) -> Vec<u8>` gated behind the
`export` feature, backed by the `chacha20poly1305` crate. The Cyrius
port needs the same confidentiality + authenticity properties for
audit export, but:

- Cyrius has no stdlib AEAD implementation.
- The ecosystem's crypto primitives live in `sigil`
  (`lib/sigil.cyr`): Ed25519 (sign/verify) and SHA-256.
- Implementing Poly1305 from scratch requires a constant-time
  130-bit bignum modular-reduction routine — high-risk code to
  write and review without existing library support.
- ChaCha20 alone is well-specified (RFC 7539), ~120 LOC of
  straightforward 32-bit arithmetic, and has public test vectors
  suitable for exact-match verification.

## Decision

Build the audit-export AEAD from **ChaCha20 (confidentiality) +
Ed25519 (authenticity)** instead of ChaCha20-Poly1305. Wire format:

```
offset 0    nonce (12 bytes, caller-supplied, must be unique per key)
offset 12   Ed25519 signature over (nonce || ciphertext) (64 bytes)
offset 76   ciphertext (N bytes, same length as plaintext)
```

### Implementation

- `src/crypto_chacha20.cyr` implements RFC 7539 ChaCha20 in pure
  Cyrius, masking every arithmetic result through `x & 0xFFFFFFFF` to
  stay within 32-bit semantics on the i64 value space. Verified
  against RFC 7539 §2.4.2 test vector (`tests/t-ron-crypto.tcyr:
  test_chacha20_rfc_vector`).

- `audit.cyr::audit_export_encrypted` builds the plaintext via
  `audit_export_json`, encrypts with `chacha20_xor(counter=1)`, then
  signs the `nonce || ciphertext` concatenation with sigil's
  `ed25519_sign`.

- `audit_decrypt_export` verifies the signature **first**, then
  decrypts. Signature check is sigil's constant-time
  `ed25519_verify`.

## Consequences

**Good**

- Authenticity lives in an existing, reviewed, constant-time
  primitive (sigil's Ed25519). No Poly1305 to audit.
- Same AEAD properties: adversary who flips a ciphertext byte cannot
  forge a valid signature, so the envelope rejects on decrypt.
- ChaCha20 is well-specified and RFC-vector-tested in under 130 LOC.

**Bad**

- 64-byte signature vs. Poly1305's 16-byte tag — overhead is
  negligible for audit exports but visible in the wire format.
- Ed25519 sign/verify is orders of magnitude slower than Poly1305
  (~100 µs vs. <1 µs). For infrequent audit exports this is fine;
  for per-event AEAD it would matter.
- Non-standard construction. Wire format is incompatible with the
  Rust 0.90.0 `chacha20poly1305` envelope — cross-reading old
  exports requires keeping `rust-old/` available.

## Alternatives considered

- **Implement Poly1305 in Cyrius.** Rejected: ~200 LOC of prime-field
  arithmetic, very error-prone without existing tests, any bug
  silently breaks authenticity.
- **Skip encryption, rely on libro chain integrity.** Rejected: libro
  guarantees authenticity of individual entries but not the envelope
  around an export; an attacker who intercepts and reads a plain
  JSON dump has won before verify_chain matters.
- **Use an existing C library via CFFI.** Rejected: adds a
  non-Cyrius supply-chain dependency, undermining the whole reason
  for the port (ADR-004).

## Tests

- `test_chacha20_rfc_vector` — RFC 7539 §2.4.2 plaintext → ciphertext
  exact match (6-byte spot-check) + roundtrip.
- `test_audit_export_encrypted_roundtrip` — end-to-end: log events,
  encrypt with one keypair, verify + decrypt yields the same
  plaintext JSON.
- `test_audit_decrypt_rejects_tamper` — flipping one ciphertext byte
  breaks the signature check.
- `test_audit_decrypt_rejects_wrong_key` — decrypting with a
  different verifying key fails.

All in `tests/t-ron-crypto.tcyr`, all passing as of 2.0.0.
