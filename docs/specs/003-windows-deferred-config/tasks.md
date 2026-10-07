# Tasks: Windows deferred config

| Task | Workstream | State | Evidence |
| --- | --- | --- | --- |
| `--deferred-config` option, validation and forwarding | A | Done | `cmd/defenseclaw-enterprise-setup/main.go`, `internal/cli/windows_enterprise_service.go` |
| Lifecycle support for a late config and manifest drop | A | Not done; refused (REQ-07) | `packaging/windows/install-enterprise.ps1`, `DefenseClawEnterprise.psm1` |
| Gateway bounded wait | B, B2 | Done | `internal/cli/config_v8_wait.go`, `config_v8_wait_test.go` |
| Guardian bounded wait and state file | B3 | Done | `internal/cli/enterprise_hooks.go`, `internal/enterprisehooks/guardianstate` |
| Health `configuration` state and collapse rule | C | Done | `internal/gateway/health.go`, `internal/cli/sidecar.go` |
| Wire mapping for Secure Client | C | Done | `internal/ipc/service.go`, `service_configuration_state_test.go` |
| Serve `waiting_for_config` during the gateway wait | C | Not done | needs a health surface that runs before the config loads |

Remaining work for a supported deferred install:
- a transactional activation boundary for a late `targets.yaml`;
- secure target runtime preparation after the drop;
- removing the REQ-07 refusal.
