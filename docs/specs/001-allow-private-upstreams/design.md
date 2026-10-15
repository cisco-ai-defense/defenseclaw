# Design: Allow Private Upstream IPs

## Summary

Adds an operator-configurable allowlist of specific IP addresses that are exempt
from DefenseClaw's SSRF private-address blocking. This enables enterprise
customers to route LLM traffic through on-prem gateways on RFC 1918 addresses
without disabling SSRF protection entirely.

The allowlist is a flat set of IP literals (no CIDR) — intentionally restrictive
to force explicit trust decisions per endpoint.

## Architecture

### Components Modified

| Component | File(s) | Change |
|-----------|---------|--------|
| Config loader | `internal/config/config.go` | Add `AllowPrivateUpstreams []string` field, parse + validate |
| Netguard library | `internal/netguard/netguard.go` | Add `SetAllowedPrivateIPs(ips []net.IP)` + exemption check in `IsPrivateOrReserved` |
| Gateway IP predicate | `internal/gateway/provider.go` | `isUnsafeIP()` checks allowlist before returning true |
| Gateway shape check | `internal/gateway/shape.go` | `isPrivateHost()` passes allowlist context |
| Dial guard | `internal/gateway/provider.go` | `secureDialContext()` checks allowlist |
| Upstream guard | `internal/gateway/proxy.go` | `guardUpstreamTargetURL()` emits "private-ip-allowed" event |
| Env var registry | `internal/envvars/registry.json` | Register `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` |
| Python SSRF | `cli/defenseclaw/registries/ssrf.py` | Read env var, exempt listed IPs |
| Doctor | `cli/defenseclaw/commands/cmd_doctor.py` | Surface allowlist in Security Overrides |

### Data Flow

```
Request arrives at proxy
    │
    ▼
guardUpstreamTargetURL(targetURL)
    │
    ├─ parse hostname
    ├─ resolve DNS → IP(s)
    │
    ▼
isPrivateHost(host)
    │
    ├─ isUnsafeIP(ip)
    │     │
    │     ├─ Is loopback/link-local/metadata? → ALWAYS BLOCK (hardcoded deny)
    │     ├─ Is in allowedPrivateIPs set?     → ALLOW + emit "private-ip-allowed" event
    │     └─ Is private/reserved?             → BLOCK + emit "private-ip" event
    │
    ▼
secureDialContext (dial-time re-check)
    │
    ├─ Re-resolve DNS
    ├─ Check each IP against same predicate
    └─ Dial first safe/allowed IP
```

### Interfaces

**Config.yaml schema addition:**

```yaml
guardrail:
  allow_private_upstreams:
    - "10.50.2.100"
    - "10.50.2.101"
    - "172.16.0.5"
```

**Environment variable:**

```
DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS=10.50.2.100,10.50.2.101,172.16.0.5
```

The env var merges with (does not replace) config.yaml entries. Deduplication
is automatic.

## Data Model

No persistent storage changes. The allowlist is held in memory as a
`map[netip.Addr]struct{}` built at config load time and swapped atomically
on config reload.

```go
// In internal/config/config.go
type GuardrailConfig struct {
    // ... existing fields ...
    AllowPrivateUpstreams []string `yaml:"allow_private_upstreams"`
}
```

```go
// In internal/netguard/netguard.go (or a new internal/netguard/allowlist.go)
var (
    allowedPrivateMu sync.RWMutex
    allowedPrivate   map[netip.Addr]struct{}
)

func SetAllowedPrivateIPs(ips []netip.Addr) { ... }
func isAllowedPrivateIP(ip net.IP) bool { ... }
```

## Integration Points

- **Config hot-reload**: The existing `config.Watcher` calls a reload callback.
  On reload, re-parse `AllowPrivateUpstreams`, validate, and call
  `netguard.SetAllowedPrivateIPs(parsed)`.
- **Sidecar startup**: Parse at boot in `NewGuardrailProxy` → call
  `netguard.SetAllowedPrivateIPs`.
- **Python CLI**: Read `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` at call time in
  `guard_url()` (same lazy-read pattern as `_cgnat_allowed()`).

## Tradeoffs

| Decision | Rationale |
|----------|-----------|
| IP list, not CIDR | Least privilege. A /8 allowance defeats SSRF protection entirely. Operators must name each trusted endpoint explicitly. |
| Hardcoded deny for loopback/link-local/metadata | These are never legitimate LLM gateway addresses. Allowing them enables trivial SSRF even with an explicit opt-in. |
| Global allowlist, not per-provider | Simpler config. The IP either resolves from the provider URL or it doesn't — scoping per-provider adds config complexity with no security benefit (the IP is the trust boundary, not the provider name). |
| Env var merges with config.yaml | Env vars override in container/systemd deployments where config.yaml is baked into the image. Merging (not replacing) means both sources are honoured. |
| `map[netip.Addr]struct{}` over `[]net.IP` | O(1) lookup, no allocation per request. `netip.Addr` is comparable (usable as map key) unlike `net.IP`. |

## Risks

| Risk | Mitigation |
|------|------------|
| Operator allows too many IPs, weakening SSRF posture | `defenseclaw doctor` surfaces the list with HIGH impact. Docs warn against over-allowlisting. |
| DNS rebinding: domain resolves to public IP at check time, private allowed IP at dial time | Both `isPrivateHost` (pre-flight) and `secureDialContext` (dial-time) check the allowlist, so the allowed IP must appear at BOTH resolution points — a rebind to an *un*-allowed IP is still blocked at dial. |
| Config reload race | `sync.RWMutex` protects the allowlist map; readers take RLock, reload takes Lock. Atomic swap means no torn reads. |
