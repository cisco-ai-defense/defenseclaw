# Requirements: Allow Private Upstream IPs

## Context

DefenseClaw's SSRF protection blocks all outbound connections to private/reserved
IP addresses (RFC 1918, loopback, link-local, CGNAT, cloud metadata, IPv6 ULA).
This is by design — it prevents agents from being weaponized to reach internal
infrastructure via DNS rebinding or crafted prompts.

However, enterprise customers increasingly host their own LLM gateways on
private networks (e.g. 10.50.2.100) that cannot be moved to a public IP due to
security policy or network topology. When an agent's LLM provider is configured
to point at such a gateway and DefenseClaw proxies the request, the SSRF guard
blocks the connection with:

    [guardrail] BLOCKED chat: private-host target 10.50.2.100

The only current workaround is `DEFENSECLAW_ALLOW_CGNAT=1` (which only covers
100.64.0.0/10) or putting a reverse proxy on a public IP — neither is acceptable
for many on-prem deployments.

**Design choice: IP list, not CIDR ranges.** The allowlist accepts individual IP
addresses only — not CIDR notation. This is intentional:
- Forces operators to be explicit about each trusted endpoint
- Prevents accidental exposure of entire subnets (e.g. allowing 10.0.0.0/8
  would defeat the SSRF guard entirely)
- Typical use case is 1-5 on-prem LLM gateways, not hundreds of hosts
- Matches the principle of least privilege for security opt-outs

**Affected enforcement points:**
- `internal/gateway/shape.go:isPrivateHost()` — pre-flight hostname resolution check
- `internal/gateway/provider.go:isUnsafeIP()` — shared IP classification predicate
- `internal/gateway/provider.go:secureDialContext()` — dial-time DNS rebinding guard
- `internal/gateway/proxy.go:guardUpstreamTargetURL()` — upstream target validation
- `internal/netguard/netguard.go:IsPrivateOrReserved()` — shared SSRF library
- `cli/defenseclaw/registries/ssrf.py:guard_url()` — Python-side registry SSRF guard

**Existing pattern to follow:** `DEFENSECLAW_ALLOW_CGNAT` env var, which carves
out 100.64.0.0/10 from the reserved list. This feature follows the same pattern
but is scoped to operator-specified individual IPs only.

## EARS Requirements

### Functional

- REQ-01: Where `guardrail.allow_private_upstreams` is configured in config.yaml
  with one or more IP addresses, the system shall exempt those specific IPs from
  the SSRF private-address block for LLM upstream forwarding.

- REQ-02: Where `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` env var is set with a
  comma-separated list of IP addresses, the system shall merge those IPs into
  the exemption list alongside any config.yaml entries.

- REQ-03: The system shall validate IP address syntax at config load time and
  reject malformed entries with a clear error message identifying the invalid
  value. CIDR notation (e.g. "10.0.0.0/8") shall be rejected with a message
  directing the operator to specify individual IPs.

- REQ-04: The system shall NEVER exempt loopback (127.0.0.1, ::1), link-local
  (169.254.x.x, fe80::x), or cloud metadata (169.254.169.254, 169.254.170.2)
  from the SSRF guard regardless of the allowlist contents.

- REQ-05: When an upstream request is forwarded to an IP within the allowlist,
  the system shall emit an egress audit event with reason "private-ip-allowed"
  (distinct from the existing "block" / "private-ip" events) for observability.

- REQ-06: The `defenseclaw doctor` command shall surface active private-upstream
  allowlist entries under its "Security Overrides" section with HIGH impact.

- REQ-07: The Python-side SSRF guard (`cli/defenseclaw/registries/ssrf.py`) shall
  honour the same allowlist for registry sync operations so behaviour is
  consistent across Go and Python surfaces.

- REQ-08: The system shall apply the allowlist at BOTH the application-level
  check (`isPrivateHost`/`guardUpstreamTargetURL`) AND the dial-time guard
  (`secureDialContext`) to prevent DNS rebinding from bypassing an allowed
  destination.

### Non-Functional

- REQ-09: The allowlist lookup shall add no more than 1 microsecond per-request
  overhead (map lookup is O(1); expected list size < 10 IPs).

- REQ-10: The feature shall not require a gateway restart when config.yaml is
  hot-reloaded (the existing config watcher picks up changes).

## Acceptance Criteria

- AC-01: A gateway configured with
  `guardrail.allow_private_upstreams: ["10.50.2.100"]` successfully forwards chat
  completion requests to an upstream at 10.50.2.100:8443.

- AC-02: The same gateway blocks requests to 10.50.2.101 (not in the list) and
  to 127.0.0.1 / 169.254.169.254 (hardcoded deny, even if in the list).

- AC-03: Setting `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS=10.50.2.100,172.16.0.5`
  without config.yaml entries produces the same allow behaviour.

- AC-04: An invalid IP (`"not-an-ip"`) in config.yaml causes a startup error
  with a message containing the invalid value.

- AC-05: A CIDR value (`"10.0.0.0/8"`) in config.yaml causes a startup error
  with a message directing the operator to use individual IPs.

- AC-06: `defenseclaw doctor` shows the active allowlist under Security Overrides.

- AC-07: An egress audit event with `reason=private-ip-allowed` appears in
  gateway.jsonl when forwarding to an allowed private IP.

- AC-08: The Python `guard_url()` function respects the allowlist (unit test).

## Traceability

| REQ | Architecture Section | Acceptance Criteria |
|-----|---------------------|---------------------|
| REQ-01 | internal/gateway/proxy.go:guardUpstreamTargetURL | AC-01 |
| REQ-02 | docs/ENV-VARS.md | AC-03 |
| REQ-03 | internal/config/config.go | AC-04, AC-05 |
| REQ-04 | internal/netguard/netguard.go | AC-02 |
| REQ-05 | docs/OBSERVABILITY-CONTRACT.md | AC-07 |
| REQ-06 | CLI doctor surface | AC-06 |
| REQ-07 | cli/defenseclaw/registries/ssrf.py | AC-08 |
| REQ-08 | internal/gateway/provider.go:secureDialContext | AC-01 |
