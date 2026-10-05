# Requirements: Windows UI IPC

## Scope

- **REQ-01:** The IPC server starts only when `cfg.ManagedIPCEnabled()` is
  true, which means the Secure Client integration is on. A standalone
  deployment exposes no IPC surface. The gRPC service and its messages are
  the same as on macOS (`proto/defenseclaw/secureclient/v1`).

## Socket path

- **REQ-02:** Under `managed_enterprise` on Windows, the socket path is
  `<TrustedProgramFiles>\Cisco\Cisco Secure Client\DefenseClaw\ipc\defenseclaw_ipc.sock`.
  - `TrustedProgramFiles` comes from the registry through
    `winpath.TrustedProgramFiles`, not from `%ProgramFiles%`. The relative
    directory is `winpath.ManagedIPCRelativeDir`.
  - If the root does not resolve, the server fails to start with
    "ipc: resolve socket path: empty"; it never falls back to a per-user
    path.
  - `DEFENSECLAW_IPC_SOCKET` is ignored in this mode.
  - Earlier builds used the ProgramData root.

## DACL

- **REQ-03:** The socket's parent directory and the socket file each carry
  exactly four ACEs, none inherited:
  - SYSTEM (`S-1-5-18`), full control;
  - Administrators (`S-1-5-32-544`), full control;
  - the gateway service account, full control;
  - Authenticated Users, limited by REQ-04.

  The gateway account is `NT SERVICE\DefenseClawGateway` unless the
  service-account environment value (`managed.WindowsServiceAccountEnv`)
  names another one. That account must resolve to a SID under the
  NT SERVICE authority.
- **REQ-04:** Authenticated Users get:
  - on the directory: `FILE_TRAVERSE | FILE_LIST_DIRECTORY`, without
    `FILE_ADD_FILE`, so they cannot plant a decoy socket while the gateway
    is stopped;
  - on the socket file: `GENERIC_READ | GENERIC_WRITE`, without
    `WRITE_DAC`.
- **REQ-05:** The DACL is set with `PROTECTED_DACL_SECURITY_INFORMATION`, so
  policy on an ancestor cannot widen it.

## Peer authentication posture

- **REQ-06:** On Windows the accept path does no peer authentication. Each
  peer is reported as `UnixPeerUnauthenticated`, and the codesign listener
  passes connections through. The socket DACL is the access boundary.
- **REQ-07:** On macOS and Linux the accept path keeps its peer
  authentication (`UnixPeer`) unchanged.
- **REQ-08:** At startup on Windows, before the "listening on ..." line,
  the server logs this line once:
  "windows: peer-auth is deferred; UDS is DACL-permissive to Authenticated Users".
- **REQ-09:** The `codesign_peer_auth` field of the startup line is:
  - `deferred_windows` on Windows;
  - otherwise `enabled` when any require flag or allowlist is set, and
    `disabled` when none is.

  These literals are a stable log contract.
- **REQ-10:** On Windows, config validation refuses
  `managed.allowed_team_ids`, `managed.allowed_signing_ids` and
  `managed.allowed_bundle_ids`. It names the keys it refuses, because
  allowlists on Windows would be dropped without notice.
- **REQ-11:** `Config.EffectivePeerAuthKind()` returns:

  | Condition | Value |
  | --- | --- |
  | IPC not enabled | `""` |
  | Windows | `UnixPeerUnauthenticated` |
  | other OS | `UnixPeer` |

## Configuration state on the wire

- **REQ-12:** `HealthSnapshot` carries
  `ConfigurationState configuration_state = 4`. The enum values are:
  - `UNSPECIFIED = 0`;
  - `WAITING_FOR_CONFIG = 1`;
  - `WAITING_FOR_TARGETS = 2`;
  - `READY = 3`.
- **REQ-13:** The mapping from the spec 003 health state is:

  | Health state | Wire value |
  | --- | --- |
  | `waiting_for_config` | `WAITING_FOR_CONFIG` |
  | `waiting_for_targets` | `WAITING_FOR_TARGETS` |
  | `ready` | `READY` |
  | absent or unknown | `UNSPECIFIED` |

  A consumer treats `UNSPECIFIED` as "not tracked", not as an error.

## Bind hardening

- **REQ-14:** On Windows a socket path override (`cfg.Managed.SocketPath`)
  must be absolute and named `defenseclaw_ipc.sock`. Its parent directory
  must be named `ipc` and must equal the trusted directory of REQ-02,
  compared case-insensitively. Any other override is refused before a DACL
  is written. Only a package test hook relaxes the trusted-root check.
  No environment variable, registry value or config key can relax it.
- **REQ-15:** The server refuses a reparse point (junction or symlink) at the
  socket directory or any ancestor (`winpath.RejectReparseChain`).
- **REQ-16:** Other local sockets that reuse the bind rules (`ListenSpec`),
  such as the privileged sensor helper, get the gateway-only DACL:
  SYSTEM, Administrators and the gateway account, without Authenticated
  Users.
- **REQ-17:** A bind failure or a DACL failure sets the IPC subsystem health
  to `error` and returns the error. The server never serves on a socket
  whose DACL was not applied.

## Release gate

- **REQ-18:** A build with `-tags ga` fails to compile while the
  unauthenticated Windows posture exists.
  - `authposture_gagate.go` refers to `authpostureGAApproved`.
  - Only the follow-up peer-auth spec defines that symbol.
- **REQ-19:** CI (`windows-enterprise-setup.yml`) runs
  `GOOS=windows go build -tags ga` and fails if that build succeeds. The
  missing symbol in stderr is only a diagnostic hint.

## Lifecycle

- **REQ-20:** The server binds once per run:
  - it removes a stale socket file before it listens;
  - it stops gracefully and removes the socket on shutdown.
