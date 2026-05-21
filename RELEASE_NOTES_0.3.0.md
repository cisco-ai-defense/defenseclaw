## Highlights

- **Externalized rule packs, detection strategies, and full policy TUI** — RFC #111 lands the new pluggable policy surface.
- **Observability v7** — structured gateway events, OTel GenAI semconv spans/metrics, audit sinks, TUI verdicts, and a five-surface fan-out local stack.
- **Hardened enforcement** — centralized admission policy and closed security gaps, including credential-leakage fixes on `/health` and `/status`.
- **Bundled DefenseClaw Splunk in Free mode** for an out-of-the-box trial experience.
- **Provider expansion**, webhook notifications, and an OpenShell standalone sandbox.

## What's Changed

### Features
- Externalized rule packs, detection strategies, and full policy TUI (#111)
- v7 observability — event contract, five-surface fan-out, local stack (#127)
- CLI UX: registry-driven keys, quickstart & lifecycle commands (#117)
- Structured gateway events, generic OTel, audit sinks, TUI verdicts (#114)
- Operator help text + logger concurrency + judge-row dedup (#116)
- OpenShell standalone sandbox (#24)
- Webhook notifications (#91)
- Provider expansion (#23)
- Bundled DefenseClaw Splunk starts in Free mode from day 1 (#36)
- Local Splunk trial and Free mode behavior (#31)
- Consolidated Tier 1 community PRs (#17, #25, #27, #29, #55, #56, #58, #67, #89) (#86)

### Observability & Telemetry
- Align OTel conventions for agent and tool telemetry (#147)
- OTel GenAI Semconv spans, metrics, and delta temporality (#32)
- Wire `defenseclaw.watcher.restarts` + real-time upgrade progress (#132)

### Security & Hardening
- Harden enforcement, centralize admission policy, and close security gaps (#65)
- Remove credential leakage from `/health` and `/status` endpoints; correct ASCII logo in README (#21)

### Fixes
- Resolve issues #92, #96, #98, #99 and add health watchdog (#104)
- Make plugin build resilient to `NODE_ENV=production` (#19)
- Portable version parsing in installer (macOS + Linux) (0b25bf7)
- Update install script for public repo and goreleaser artifacts (e71b0f3)
- Use exact awk field match to avoid checksum concatenation (#144)
- README ASCII typo (#26)

### CI / Build
- Stabilize and require end-to-end DefenseClaw CI (#61)
- Unblock go-lint, pip-audit, and harden e2e runner disk cleanup (#160)
- Remove unused const and update provider fallback test (#68)

### Docs
- Clean up repo documentation (#146)
- Fix OpenClaw repo URL (nvidia/openclaw → openclaw/openclaw) (#129)
- Adding badge links (#28)

**Full Changelog**: https://github.com/cisco-ai-defense/defenseclaw/compare/0.2.0...0.3.0
