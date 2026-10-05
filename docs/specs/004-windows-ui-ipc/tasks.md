# Tasks: Windows UI IPC

| Task | State | Evidence |
| --- | --- | --- |
| Managed socket path under the trusted Program Files root | Done | `internal/ipc/paths_windows.go`, `paths_windows_test.go` |
| Four-ACE protected DACL, directory and socket masks | Done | `internal/ipc/acl_windows.go`, `acl_windows_test.go` |
| Override, reparse and stale-socket handling | Done | `internal/ipc/server_windows.go` |
| Deferred-auth log line and `codesign_peer_auth` label | Done | `internal/ipc/server.go`, `service_configuration_state_test.go` |
| Refuse codesign allowlists on Windows | Done | `internal/config/config.go` |
| `EffectivePeerAuthKind` table | Done | `internal/config/managed_peerauth_test.go` |
| `configuration_state` on the health stream | Done | `internal/ipc/service.go`, `service_configuration_state_test.go` |
| GA release gate and CI check | Done | `internal/ipc/authposture_gagate.go`, `windows-enterprise-setup.yml` |
| Shared bind rules for other local sockets | Done | `internal/ipc/listen.go` |
| Windows peer authentication | Not done | follow-up spec; defines `authpostureGAApproved` |
| Decide the Windows socket path override | Open | design.md, Open questions |
