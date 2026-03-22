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
- [ ] Load policy from `/etc/agnos/t-ron.toml` at startup
- [ ] Hot-reload policy on SIGHUP
- [ ] agnoshi intents for natural language security queries
- [ ] Wire `RateLimitPolicy` from TOML config to rate limiter

### Phase 2 -- Advanced Detection
- [ ] ML-based anomaly detection (train on normal patterns, flag deviations)
- [ ] Privilege escalation pattern detection (benign -> sensitive tool sequences)
- [ ] Cross-agent correlation (detect coordinated attacks)
- [ ] Prompt injection detection in tool parameters (LLM-assisted via hoosh)
- [ ] Time-of-day anomaly detection

### Phase 3 -- Hardening
- [ ] Policy signing (sigil trust verification)
- [ ] Encrypted audit log export
- [ ] Real-time alerts via daimon event bus
- [ ] Dashboard integration (aethersafha security panel)
- [ ] Edge fleet policy distribution
