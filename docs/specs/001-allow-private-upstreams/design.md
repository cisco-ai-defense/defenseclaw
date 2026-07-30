# Design: allow private upstream IPs

**Status:** Implemented. See [`requirements.md`](requirements.md) for the
verified contract and evidence.

## Design decisions

- Exemptions are individual IP literals, never CIDR ranges.
- Configuration and the environment are merged and deduplicated into a
  process-wide allowlist.
- The allowlist is stored as normalized `netip.Addr` keys behind an RW mutex.
- Hard-denied address classes stay non-exemptible even if an unvalidated
  environment value names one.
- Provider transport records the concrete connected peer through
  `httptrace.GotConn`; audit does not claim that a DNS preflight answer carried
  the request.
- Configuration reload replaces the allowlist and closes affected provider
  transports so stale connections cannot silently retain removed policy.

## Implementation map

```text
config.yaml + environment
          |
          v
ParseAllowedPrivateUpstreams
          |
          v
SetAllowedPrivateIPs
     |                |
     v                v
preflight guard    dial/peer validation
                         |
                         v
              private-ip-allowed egress record
```

| Area | Source |
| --- | --- |
| Allowlist storage and merge | `internal/netguard/allowlist.go` |
| Non-exemptible address classes | `internal/netguard/netguard.go` |
| Config field and validation | `internal/config/config.go` |
| Startup/reload wiring | `internal/gateway/sidecar.go` |
| Provider preflight, dial safety, and peer audit | `internal/gateway/provider.go` |
| Python registry SSRF parity | `cli/defenseclaw/registries/ssrf.py` |
| Doctor surface | `cli/defenseclaw/commands/cmd_doctor.py` |
| Source schema | `schemas/config/v8/defenseclaw-config.schema.json` |

The public configuration syntax is intentionally not copied here.
