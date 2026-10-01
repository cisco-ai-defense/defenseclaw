# Design: Windows UI IPC

## Components

| Component | Code | Role |
| --- | --- | --- |
| Path resolution | `internal/ipc/paths.go`, `paths_windows.go`, `internal/winpath` | Socket path (REQ-02) |
| Bind | `internal/ipc/server_windows.go`, `listen.go`, `listen_windows.go` | Override check, reparse check, DACL, listen |
| DACL | `internal/ipc/acl_windows.go` | Four-ACE baseline and gateway-only ACEs |
| Peer auth | `internal/ipc/peerauth_windows.go` | Passthrough; `UnixPeerUnauthenticated` |
| Server | `internal/ipc/server.go` | Startup log lines, gRPC serve, teardown |
| Service | `internal/ipc/service.go` | Health, stats and notification streams |
| Config | `internal/config/managed.go`, `config.go` | `ManagedIPCEnabled`, `EffectivePeerAuthKind`, Windows allowlist refusal |
| Release gate | `internal/ipc/authposture_gagate.go`, `.github/workflows/windows-enterprise-setup.yml` | REQ-18, REQ-19 |

## Bind sequence (Windows)

1. Resolve the path. The order is:
   1. `cfg.Managed.SocketPath`;
   2. the environment value, for unmanaged modes only;
   3. the managed default of REQ-02.
2. `validateWindowsSocketPathOverride` checks the shape and the trusted
   root (REQ-14).
3. `MkdirAll` the `ipc` directory, then `RejectReparseChain` on it
   (REQ-15).
4. Apply the directory DACL (REQ-03, REQ-04, REQ-05).
5. Remove a stale socket file (REQ-20).
6. `net.ListenConfig.Listen("unix", path)`.
7. Apply the socket-file DACL. On failure, close the listener and return.
8. Wrap the listener in the codesign listener, a passthrough on Windows.
9. Log the deferred-auth line, then the "listening on" line (REQ-08,
   REQ-09), and serve.

The DACL is written to the directory before the socket exists. A local user
therefore never sees a window where the directory admits `FILE_ADD_FILE`.

## Interfaces

The service is `DefenseClawSecureClientService`:

- `GetHealth(GetHealthRequest) returns (stream HealthSnapshot)`
- `GetStatsSnapshot(GetStatsSnapshotRequest) returns (stream StatsSnapshot)`
- `WatchNotifications(WatchNotificationsRequest) returns (stream NotificationRecord)`

`HealthSnapshot` fields:

| Field | Number | Meaning |
| --- | --- | --- |
| `schema_version` | 1 | Wire schema |
| `availability` | 2 | `ServiceAvailability` of the runtime |
| `defense_claw_version` | 3 | Build version; omitted when empty |
| `configuration_state` | 4 | `ConfigurationState` (REQ-12, REQ-13) |

`availability` reports whether the runtime is reachable.
`configuration_state` reports whether the managed configuration drop is
complete, using the same values on every managed backend.

- A starting availability with `WAITING_FOR_CONFIG` means the process is up
  and `config.yaml` has not arrived.
- A non-managed deployment never sets the configuration object, so it
  reads `UNSPECIFIED`.
- A state literal this build does not know also reads `UNSPECIFIED`, never
  `READY`.

Log contract:

- `windows: peer-auth is deferred; UDS is DACL-permissive to Authenticated Users`
- `listening on <path> (mode=... codesign_peer_auth=<disabled|enabled|deferred_windows> ...)`

## Tradeoffs

1. **DACL instead of peer authentication.** Windows AF_UNIX has no
   peer-credential API that Go exposes. Pinning the DACL to the Secure
   Client GUI principal, or checking the PID with WinVerifyTrust, is a
   follow-up. Until then any authenticated local user can read the health,
   stats and notification streams. The streams are read-only.
2. **Refuse allowlists instead of ignoring them.** A configured allowlist
   that does nothing would give a false sense of control (REQ-10).
3. **Symbol gate instead of a string check.** Renaming the peer-kind
   literal does not defeat the gate. Deleting the gate file does defeat it,
   so the follow-up spec needs its own release check on the reported peer
   kind.
4. **Program Files root.** Both peers dial a path under the same trusted
   root. The gateway's service SID gets its DACL rights at install.

## Open questions

- **`cfg.Managed.SocketPath` on Windows.** The resolver accepts the value
  as given (`paths_windows_test.go`). Bind then refuses it unless its parent
  is the trusted directory, so in production the key can only restate the
  default. The open choice is whether to drop the key on Windows or to let
  a test rig use a scratch path. No production switch exists today.
- **Peer authentication.** The follow-up spec chooses between a DACL pinned
  to the GUI principal and PID plus signature checks. When it lands it
  defines `authpostureGAApproved`, and the REQ-08 log line goes away.
