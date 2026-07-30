# Tasks: allow private upstream IPs

**Status:** Completed.

| Task | Implemented in | Evidence |
| --- | --- | --- |
| Config field and validation | `internal/config/config.go`, `schemas/config/v8/defenseclaw-config.schema.json`, `cli/defenseclaw/config.py` | config and v8-config tests |
| Environment registry and merge | `internal/envvars/registry.json`, `internal/netguard/allowlist.go` | env-var and allowlist tests |
| Thread-safe normalized lookup | `internal/netguard/allowlist.go` | `internal/netguard/allowlist_test.go` |
| Application and dial enforcement | `internal/gateway/provider.go`, `internal/netguard/netguard.go` | provider and netguard tests |
| Actual-peer audit event | `internal/gateway/provider.go` | `internal/gateway/private_upstream_audit_test.go` |
| Startup/reload lifecycle | `internal/gateway/sidecar.go` | `internal/gateway/sidecar_observability_v8_bootstrap_test.go` |
| Python registry SSRF parity | `cli/defenseclaw/registries/ssrf.py` | `cli/tests/test_registry_ssrf.py` |
| Doctor warning | `cli/defenseclaw/commands/cmd_doctor.py` | `cli/tests/test_cmd_doctor.py` |
| Canonical operator catalog | `docs-site/content/docs/reference/env-vars.mdx` | `scripts/gen_envvars_docs.py --check` |

The former unchecked planning list was replaced because it contradicted the
implemented code. See [`requirements.md`](requirements.md) for the current
engineering contract.
