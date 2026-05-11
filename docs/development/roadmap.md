# Roadmap

## Completed

### Phase 0 -- Scaffold
- [x] Core gate types (ToolCall, Verdict, DenyCode)
- [x] Policy engine with glob ACLs and TOML config
- [x] Token bucket rate limiter
- [x] Regex payload scanner (SQL, shell, template, path traversal)
- [x] Pattern analyzer (tool enumeration detection)
- [x] Risk scorer
- [x] Audit logger
- [x] Query API for T.Ron personality

### Phase 1 -- Integration
- [x] SecurityGate middleware wrapping bote Dispatcher
- [x] MCP tools: tron_status, tron_risk, tron_audit, tron_policy
- [x] Streaming dispatch support
- [x] libro audit chain integration (cryptographic hash chain)
- [x] Chain verification and review via TRonQuery

## Upcoming

### Post-release -- agnosticos integration
- [x] Load policy from file path (`load_policy_file`)
- [x] Hot-reload policy support (`reload_policy` for SIGHUP handlers)
- [ ] agnoshi intents for natural language security queries
- [x] Wire `RateLimitPolicy` from TOML config to rate limiter

### Phase 2 -- Advanced Detection
- [ ] ML-based anomaly detection (train on normal patterns, flag deviations)
- [ ] Privilege escalation pattern detection (benign -> sensitive tool sequences)
- [ ] Cross-agent correlation (detect coordinated attacks)
- [ ] Prompt injection detection in tool parameters (LLM-assisted via hoosh)
- [ ] Time-of-day anomaly detection

### Phase 2A -- Agent Injection Defense — Capability-Source Policy

> **Spec**: [`agnosticos/docs/development/planning/agent-injection-defense.md`](https://github.com/MacCracken/agnosticos/blob/main/docs/development/planning/agent-injection-defense.md) — six-layer cross-cutting design. **t-ron owns L3 (MCP boundary).** Triggered by 2026-05 incident (third-party AI agent drained $200K via Morse code in tweet). **Phasing**: post-closed-beta for the schema work; post-public-beta for full enforcement.

L3's job: track the **provenance** of every tool call (which content channel triggered it) and refuse high-privilege calls when provenance is "external."

- [ ] **Capability-source policy schema** — declarative per-tool: which provenance channels can invoke this tool?
  - `system-only` — only agent's own goals (e.g., self-shutdown)
  - `user-or-system` — explicit user request OK (e.g., file ops)
  - `any-source` — fine-grained tools usable from any channel (e.g., date/time)
  - `external-with-confirmation` — external content can request, requires explicit human auth before exec
- [ ] **Provenance chain ingestion** — daimon publishes the source channel that produced each tool call; t-ron evaluates against the per-tool policy
- [ ] **Default policy** — every tool tagged `irreversible: true` requires `user-or-system` minimum (defense-in-depth with kavach's L4 gate)
- [ ] **Audit emission** — every tool-call decision logs `{tool, provenance, decision, reason}` to libro chain
- [ ] **Per-tool annotation sweep** — daimon, ark, hoosh tools get explicit source-policy tags
- [ ] **Backward-compatibility migration** — shadow mode → audit-only mode → enforce mode, configurable per deployment

**Companion repos**:
- L1 (input scanning): `phylax`
- L2 (gateway pre-flight): `hoosh`
- L4 (capability gating + confirmation tokens): `kavach`
- L5 (audit chain): `libro` (already shipped)
- L6 (UntrustedInput<T> shared type): `agnostik`

### Phase 3 -- Hardening
- [ ] Policy signing (sigil trust verification)
- [ ] Encrypted audit log export
- [ ] Real-time alerts via daimon event bus
- [ ] Dashboard integration (aethersafha security panel)
- [ ] Edge fleet policy distribution
