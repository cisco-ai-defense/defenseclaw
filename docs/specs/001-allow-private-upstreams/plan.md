# Plan: Allow Private Upstream IPs

## Scope

### In scope
- `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` env var (comma-separated IPs)
- `guardrail.allow_private_upstreams` config.yaml field (list of IPs)
- Validation: reject malformed IPs, reject CIDR notation, reject loopback/link-local/metadata
- Exemption applied at both `isPrivateHost`/`guardUpstreamTargetURL` and `secureDialContext`
- Egress audit event with `reason=private-ip-allowed`
- `defenseclaw doctor` Security Overrides surface
- Python-side parity in `guard_url()`
- Env var registry entry + generated docs

### Out of scope
- CIDR-based allowlisting (explicit design decision: IPs only)
- Per-provider scoping (global allowlist applies to all upstreams)
- UI/TUI for managing the allowlist (config.yaml / env var only)
- Allowlisting for webhook destinations (separate `DEFENSECLAW_WEBHOOK_ALLOW_LOCALHOST` exists)
- Changes to the Ollama loopback exemption logic

## Dependencies

### Internal
- `internal/config` — config struct + hot-reload callback
- `internal/netguard` — shared SSRF library
- `internal/gateway/provider.go` — isUnsafeIP, secureDialContext
- `internal/gateway/shape.go` — isPrivateHost
- `internal/gateway/proxy.go` — guardUpstreamTargetURL
- `internal/envvars/registry.json` — env var documentation
- `cli/defenseclaw/registries/ssrf.py` — Python SSRF guard

### External
- None (pure stdlib; `net/netip` is in Go stdlib since 1.18)

## Rollout Plan

1. Ship behind no feature flag — the feature is inert when the list is empty (default).
2. When `allow_private_upstreams` is empty/absent AND env var is unset, behaviour
   is identical to today (no regression).
3. Operators opt in explicitly by adding IPs to config.yaml or setting the env var.
4. `defenseclaw doctor` immediately surfaces the override so operators are aware.

No migration needed — purely additive config field.

## Observability Plan

- **Logs**: `[guardrail] ALLOWED chat: private-host target %s (operator allowlist)` at INFO
- **Audit events**: Egress event with `decision=allow`, `reason=private-ip-allowed`,
  `target_host=<ip>` in gateway.jsonl
- **Metrics**: Increment existing `defenseclaw_egress_decisions_total{decision="allow",reason="private-ip-allowed"}`
  counter (if metrics are enabled)
- **Doctor**: "Security Overrides" section shows each allowed IP with HIGH impact tag

## Security Plan

- **Auth/Authz**: No change — the allowlist is operator-configured in config.yaml
  (file owned by the operator) or env var (process-level secret).
- **Hardcoded deny**: Loopback, link-local, and cloud metadata IPs are NEVER
  exempted regardless of allowlist contents. This prevents SSRF to IMDS even
  with a misconfiguration.
- **Audit trail**: Every forwarded-to-private-IP request emits an audit event,
  ensuring SOC visibility into private-network LLM traffic.
- **Least privilege**: IP-only (no CIDR) forces explicit per-endpoint trust.
