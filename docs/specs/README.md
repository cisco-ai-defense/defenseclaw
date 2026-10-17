# Windows managed-enterprise specs

| Spec | Scope | In this repository |
| --- | --- | --- |
| [001](001-windows-deterministic-build/README.md) | Deterministic Windows builds | Yes |
| [002](002-windows-avc-packaging/README.md) | AVC packaging handoff for the signed enterprise Setup | Yes |
| 003 `windows-deferred-config` | Late (deferred) managed configuration and guardian readiness | No |
| 004 `windows-ui-ipc` | Secure Client GUI IPC on Windows | No |
| 005 `windows-per-user-hook-lifecycle` | Per-user hook enumeration and lifecycle | No |
| [006](006-windows-cursor-managed-lifecycle/README.md) | Cursor managed lifecycle on Windows | Yes |

Specs 003, 004 and 005 were written outside this repository. Code comments,
tests and workflows still cite their requirement IDs (`spec 003 REQ-19`,
`Spec 005 D1`, and so on). Those comments describe the implemented behavior
where they appear; the code and its tests are authoritative. This index records
what each missing spec covers so the citations can be followed:

- **003, deferred configuration.** Installing before the managed configuration
  exists (Workstream B), the gateway tolerating a missing configuration and
  waiting for it (B2), the configuration state reported to Secure Client, and
  guardian readiness in `guardianstate` (REQ-19, REQ-20). Also cited: REQ-02,
  REQ-03, REQ-12, REQ-13, REQ-21, REQ-28, AC-06, AC-08, AC-12. Cited from
  `internal/cli/` (`root.go`, `config_v8_wait.go`, `sidecar.go`,
  `enterprise_hooks.go`), `internal/gateway/` (`firstboot.go`, `health.go`),
  `internal/enterprisehooks/guardianstate/state.go`, `internal/ipc/service.go`,
  `cmd/defenseclaw-enterprise-setup/`, and the Secure Client proto.
- **004, Secure Client GUI IPC.** The AF_UNIX gRPC socket the Secure Client GUI
  reads: its ACL (REQ-02, REQ-03), bind-once behavior (REQ-20), and the peer
  authentication posture and how it is reported (REQ-06 to REQ-09, REQ-18,
  REQ-19). Also cited: REQ-05, REQ-11, REQ-12, REQ-13. Cited from
  `internal/ipc/`, `internal/config/managed.go`, the Secure Client proto,
  `internal/sensor/acquire/authorize_windows.go`, and
  `.github/workflows/windows-enterprise-setup.yml`.
- **005, per-user hook lifecycle.** The `DefenseClawHookEnumerator` service, its
  `hook-enumerator` subcommand and uninstall coverage (D1), ProfileList
  discovery and manifest publication (REQ-05, REQ-08, REQ-11), and the cycle
  time target (REQ-19). Also cited: REQ-03, REQ-04, REQ-13, REQ-15, REQ-18.
  Cited from `internal/enterprisehooks/enumerator_windows.go`,
  `internal/cli/enterprise_windows_enumerate_windows.go`,
  `internal/cli/windows_enterprise_service.go`, `internal/gateway/health.go`,
  and `packaging/windows/DefenseClawEnterprise.psm1`.
