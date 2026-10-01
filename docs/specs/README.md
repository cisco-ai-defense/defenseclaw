# Engineering specifications

This directory holds the engineering specifications that are part of the
repository. Each one has a `README.md` and, where written, `requirements.md`,
`design.md` and `tasks.md`.

| Spec | Scope | Status |
| --- | --- | --- |
| [001](001-windows-deterministic-build/README.md) | Windows deterministic-build support for the AVC packaging flow | Implemented |
| [002](002-windows-avc-packaging/README.md) | AVC-driven Windows enterprise packaging: the build kit, the closed eight-file payload, signing order and the outer Setup | Implemented |
| [006](006-windows-cursor-managed-lifecycle/README.md) | Cursor in the Windows managed-enterprise lifecycle through Cursor's machine-wide hook source | Proposal |

## Specs cited in code but not in this directory

Code comments cite specs 003, 004 and 005, with paths such as
`docs/specs/003-windows-deferred-config/`. Those specs were written outside
this repository and were never committed. The code, its tests and the
published documentation are the source of truth for the behavior; the
summaries below say what each cited spec covers so a reader can find the
implementation.

### 003: Windows deferred config

An install path for the Secure Client lifecycle in which the config and
target manifest arrive after the services are installed.

- `--deferred-config` (install only): `--config` and `--manifest` become
  optional; the installer creates the protected drop-point directories with
  their ACLs but writes no file bodies (REQ-02, REQ-03).
  `cmd/defenseclaw-enterprise-setup/main.go`,
  `internal/cli/windows_enterprise_service.go`.
- The gateway waits, bounded, for a missing managed `config.yaml` before it
  exits with a distinguishable error (REQ-08 to REQ-13, REQ-28, AC-06).
  `internal/cli/config_v8_wait.go`, `internal/cli/root.go`.
- The guardian waits for a late target manifest (workstream B3).
  `internal/cli/enterprise_hooks.go`,
  `internal/enterprisehooks/guardianstate`.
- The health snapshot's `configuration` state (`waiting_for_config`,
  `waiting_for_targets`, `ready`) and its `since` time (REQ-19 to REQ-21,
  AC-08, AC-12). `internal/gateway/health.go`, `internal/cli/sidecar.go`.

### 004: Windows UI IPC

The local IPC socket that the Secure Client user interface uses to read
DefenseClaw status.

- The socket path is fixed under the trusted managed IPC directory (REQ-02).
  `internal/ipc/paths_windows.go`.
- A protected four-entry DACL on the socket and its directory (REQ-03,
  REQ-05). `internal/ipc/acl_windows.go`.
- The initial Windows peer-authentication posture: the DACL is the only
  access control and the accept path reports `UnixPeerUnauthenticated`
  (REQ-06 to REQ-09, REQ-11). `internal/ipc/peerauth_windows.go`,
  `internal/config/managed.go`.
- The configuration state on the wire (REQ-12, REQ-13).
  `internal/ipc/service.go`, `proto/defenseclaw/secureclient/v1`.
- A release gate that refuses a `-tags ga` build while that posture remains
  (REQ-18, REQ-19). `internal/ipc/authposture_gagate.go`,
  `.github/workflows/windows-enterprise-setup.yml`.

### 005: Windows per-user hook lifecycle

Automatic enrollment of Windows users by the `DefenseClawHookEnumerator`
service.

- The enumerator service and its place in install, activation, servicing and
  uninstall ordering (workstream D1). `packaging/windows/DefenseClawEnterprise.psm1`,
  `internal/cli/windows_enterprise_service.go`.
- The ProfileList walk and its SID, profile-path and reparse filters (REQ-08,
  REQ-10, REQ-11, REQ-15). `internal/enterprisehooks/enumerator_windows.go`.
- The manifest is rewritten only when its bytes change (REQ-05).
- The first-cycle delay and the per-cycle timeout (REQ-13, REQ-19).
  `internal/cli/enterprise_windows_enumerate_windows.go`.
- Targeted uninstall that excludes a SID (F1).

The resulting behavior is documented in
[`WINDOWS-ENTERPRISE-THREAT-MODEL.md`](../WINDOWS-ENTERPRISE-THREAT-MODEL.md)
(row W-42) and on the docs site's
[Secure Client managed deployment](https://cisco-ai-defense.github.io/defenseclaw/docs/setup/enterprise-deployment/)
page.
