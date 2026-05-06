## Updated PR Summary (3 commits, 9 files, +859 / -44 lines)

Comprehensive documentation audit: compared every Go source file against all doc files, fixed inaccuracies, and added documentation for every previously undocumented subsystem.

---

### Commit 1: `a475006` — Fix inaccuracies and add missing architecture details

- **API.md**: correct default port 18790→18970, add missing `/api/v1/network-egress` endpoint
- **GUARDRAIL.md**: Cisco AI Defense default rules 8→12, fix port references
- **ARCHITECTURE.md**: expand gateway responsibilities (9→18 entries), full 4-stage inspection pipeline, 19 internal packages, dual policy engines, Bifrost SDK, detection strategies, streaming inspection
- **OBSERVABILITY.md**: add missing gatewaylog JSONL structured event log section
- **INSTALL.md, README.md, CONTRIBUTING.md**: Go version 1.25→1.26.2
- **QUICKSTART.md**: fix `--enable-guardrails`→`--enable-guardrail`
- **internal/gateway/SPEC.md**: fix port 18790→18970

---

### Commit 2: `526d17a` — Add 14 undocumented features

- **Multi-turn injection detection** — `ContextTracker` (10-turn/200-session/30-min TTL, `HasRepeatedInjection` threshold=3)
- **Security notification queue** — `NotificationQueue` injecting `[DEFENSECLAW SECURITY ENFORCEMENT]` system messages (2-min TTL, 50 cap)
- **Audit bridge** — `auditBridge` translating SQLite events to JSONL with 7 action-prefix→subsystem mappings
- **Provider fallback chain** — `ChatRequest.Fallbacks`, Bifrost SDK routing to 20+ providers
- **Rule pack system** — JudgeYAML, sensitive tools, suppressions, LRU regex cache (1024), NANP phone heuristic
- **Plugin scanner registry** — `Scanner` interface, `Registry.Discover()` from `plugin.yaml`
- **WebSocket event buffering** — handshake buffer and replay after `hello-ok`
- **Sequence gap detection** — `lastSeq` tracking with stderr warning
- **Bifrost session events** — `session.tool`, `session.message` (Format A/B), `sessions.changed`
- **SSRF protection** — 8 blocked CIDR ranges with DNS resolution
- **HMAC signing** — `X-DefenseClaw-Signature` header
- **Webhook dispatcher internals** — retry/backoff/concurrency, 4 payload formatters
- **7 new gateway files** in SPEC.md Files table

---

### Commit 3: `b030737` — Watcher, scanner, firewall, telemetry, and RPC documentation

- **6 missing RPC methods** — `sessions.list`, `sessions.subscribe`, `sessions.messages.subscribe`, `sessions.send`, `skills.status`, `skills.bins`
- **Watcher subsystem** — 500ms debounce, three-phase admission gate, 6 verdict types, 8-type drift detection, periodic rescan (60-min), TargetSnapshot, policy file watching (2s poll), per-type enforcement
- **9 built-in scanners** — 5 ClawShield (injection/malware/PII/secrets/vuln), CodeGuard (10 rules + custom YAML), MCP/Skill/Plugin (config keys, env vars)
- **Enforcement engine** — `SkillEnforcer`/`PluginEnforcer` quarantine, `MCPEnforcer` endpoint blocking
- **Firewall subsystem** — Compiler interface (5 methods), `RulesHash` drift (SHA-256, 12-char hex), `Observe` (lsof + domain scanning)
- **OPA admission** — 6 evaluation methods, fallback profile (`AllowListBypassScan`, `ScannerOverrides`, `FirstPartyAllow`)
- **Telemetry spans** — `guardrail/{stage}`, `guardrail.{phase}` (6 phases), `inspect/{tool}`, `defenseclaw/startup`
- **20+ OTel metrics** — verdicts, judge, guardrail cache, redaction, egress, sink delivery/circuit, stream lifecycle
- **ForSink redaction** — two-tier functions (Display vs ForSink), placeholder format, idempotency

---

### Files changed

| File | Lines | What changed |
|------|-------|-------------|
| `docs/ARCHITECTURE.md` | +393 | 5 new sections (scanners, enforcement, firewall, watcher, telemetry), expanded package table, OPA fallback |
| `docs/GUARDRAIL.md` | +178 | Scanner catalog, multi-turn detection, notification queue, provider fallback, rule packs |
| `docs/OBSERVABILITY.md` | +199 | OTel span/metric reference, audit bridge, SSRF/HMAC/dispatcher, ForSink redaction |
| `internal/gateway/SPEC.md` | +89 | 6 RPC methods, 3 events, 7 files, watcher internals, handshake buffering |
| Minor fixes | — | API.md, INSTALL.md, QUICKSTART.md, README.md, CONTRIBUTING.md |
