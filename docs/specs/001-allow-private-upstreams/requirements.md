# Requirements: allow private upstream IPs

**Status:** Implemented. This is an engineering contract, not operator setup
guidance. Configuration and environment-variable usage are maintained in the
[configuration reference](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/configuration/)
and
[environment-variable catalog](https://cisco-ai-defense.github.io/defenseclaw/docs/reference/env-vars/).

## Contract

1. `guardrail.allow_private_upstreams` accepts explicit IP literals.
   `DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS` contributes a comma-separated set at
   runtime.
2. CIDR values and malformed configuration entries are rejected.
3. Loopback, link-local, multicast, unspecified, and cloud-metadata addresses
   are never valid configuration exemptions. Runtime checks repeat the
   non-exemptible deny before classifying an observed peer as allowed.
4. An exemption applies only to a listed address. Other private/reserved
   addresses remain blocked.
5. The application-level classification and dial path use the same shared
   allowlist. The actual allowed remote peer is observed after connection
   selection.
6. Each allowlisted private peer actually used by the provider transport emits
   an egress record with decision `allow` and reason `private-ip-allowed`.
7. Gateway startup and accepted configuration reloads replace the process-wide
   allowlist; removing entries clears stale state.
8. `defenseclaw doctor` reports entries from configuration and the environment
   as a high-impact security override.
9. The Python registry SSRF guard honors the environment-variable list and
   retains the same non-exemptible address classes.

## Acceptance evidence

| Contract | Implementation | Focused tests |
| --- | --- | --- |
| Parse, merge, deduplicate, lookup | `internal/netguard/allowlist.go` | `internal/netguard/allowlist_test.go` |
| Configuration validation | `internal/config/config.go` | `internal/config/config_test.go`, `cli/tests/test_observability_v8_config.py` |
| Preflight and dial enforcement | `internal/gateway/provider.go`, `internal/netguard/netguard.go` | provider/netguard tests |
| Actual-peer audit record | `internal/gateway/provider.go` | `internal/gateway/private_upstream_audit_test.go` |
| Startup and reload | `internal/gateway/sidecar.go` | `internal/gateway/sidecar_observability_v8_bootstrap_test.go` |
| Python registry guard | `cli/defenseclaw/registries/ssrf.py` | `cli/tests/test_registry_ssrf.py` |
| Doctor warning | `cli/defenseclaw/commands/cmd_doctor.py` | `cli/tests/test_cmd_doctor.py` |
| Env-var metadata | `internal/envvars/registry.json` | `cli/tests/test_envvars.py`, `cli/tests/test_envvars_codebase_coverage.py` |

The implementation uses a locked `map[netip.Addr]struct{}` for constant-time
membership. No unverified latency number is part of this document.
