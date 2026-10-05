# Design: Windows deferred config

## Components

| Component | Code | Role |
| --- | --- | --- |
| Setup options | `cmd/defenseclaw-enterprise-setup/main.go`, `platform_windows.go` | Parse `--deferred-config`, validate combinations, forward it for install |
| Service command | `internal/cli/windows_enterprise_service.go` | Same validation; passes `-DeferredConfig` to the lifecycle |
| Lifecycle | `packaging/windows/install-enterprise.ps1`, `DefenseClawEnterprise.psm1` | Rejects `-DeferredConfig` today (REQ-07) |
| Gateway wait | `internal/cli/config_v8_wait.go`, `internal/cli/root.go` | Bounded wait for `config.yaml` (B2) |
| Guardian wait | `internal/cli/enterprise_hooks.go` | Bounded wait for `targets.yaml` (B3) |
| Guardian state | `internal/enterprisehooks/guardianstate` | `.state` file shared by guardian and sidecar |
| Health | `internal/gateway/health.go`, `internal/cli/sidecar.go` | `configuration` state and `since` |
| IPC | `internal/ipc/service.go`, `proto/defenseclaw/secureclient/v1` | `configuration_state` on the wire (spec 004) |

## Data flow

1. **Install.** The setup or service command validates the options:
   `--deferred-config` only with `install`, not with `--mode` or `--connector`.
   The lifecycle then refuses `-DeferredConfig` (REQ-07). A supported install
   today carries an authenticated `config.yaml` and `targets.yaml`.
2. **Gateway start.** `rootPersistentPreRunE` loads the config. On failure it
   calls `enterConfigWaitLoopIfManaged`. That function returns at once unless
   the error is `os.ErrNotExist` and the SCM pin
   `DEFENSECLAW_DEPLOYMENT_MODE` is `managed_enterprise`. Otherwise it runs
   `waitForConfigV8Managed`:
   - it watches the parent directory, and logs and polls only if the watch
     fails;
   - it probes once on entry;
   - it then waits for a create, write or rename event on the config path,
     or for a 30-second poll, until the path is a non-empty regular file;
   - it stops at the 24-hour bound with the timeout error.

   After a successful wait, `root.go` loads the config once more. If that
   load fails, the gateway exits with "failed to load config after wait".
3. **Sidecar start.** Under `managed_enterprise` (any OS), the sidecar:
   - calls `SetDaemonConfigLoaded(true)`;
   - sets a guardian state reader on `guardianstate.PathForPlatform(...)`;
   - starts a 5-second `RefreshConfiguration` ticker.

   Other modes do none of this, so their snapshots have no `configuration`
   object.
4. **Guardian start.** If `targets.yaml` is missing in a managed install, the
   guardian:
   - writes `.state = waiting_for_targets`;
   - waits on fsnotify and a 30-second poll, bounded at 24 hours;
   - runs the startup reconcile again when the manifest appears.

   After a successful startup reconcile it writes `.state = ready`.
5. **Collapse.** `RefreshConfiguration` reads the state file and applies the
   collapse rule:
   - daemon not loaded: `waiting_for_config`;
   - guardian `ready`: `ready`;
   - anything else: `waiting_for_targets`.

   It moves `since` only on a change.
6. **Consumer.** The IPC service maps the state to `ConfigurationState`. A
   nil value or an unknown value maps to `UNSPECIFIED`, so a newer state
   never reads as `READY` on an older consumer.

## Interfaces

- Health JSON (managed only):
  `"configuration": {"state": "waiting_for_targets", "since": "<RFC 3339>"}`.
- Guardian state file: `.state`, one of `waiting_for_targets` or `ready`,
  at most 128 bytes read.
- Errors meant for logs and SCM triage:
  - "configuration wait timeout after <d> at <path> — exiting for SCM restart"
  - "targets.yaml wait timeout after <d> at <path> — exiting for SCM restart"
  - "failed to load config after wait"

## Tradeoffs

1. **Wait in the process, not a restart loop.** An SCM restart loop on a
   missing file floods the event log, and it delays pickup by the restart
   backoff. The in-process wait picks the file up within one poll interval.
2. **Fixed timeouts.** The 24-hour bounds are package variables that tests
   shorten. No environment variable or config key changes them. A setting
   would let an operator extend the wait without limit and hide a broken
   drop pipeline as "still installing".
3. **Existence, not validity.** The wait checks only for a non-empty regular
   file. The one full load after the wait reports a malformed file loudly
   instead of waiting on it.
4. **Safe default for unknown guardian state.** A missing or garbled state
   file reads as `waiting_for_targets`, never `ready`.
5. **Pin, not config.** The gate reads the SCM environment pin, because the
   config is the file that is missing.

## Limits

- The Windows lifecycle refuses `-DeferredConfig` (REQ-07), so the waits run
  today only when a file goes missing after a normal install, for example
  when an administrator removes it.
- `waiting_for_config` is not served by the shipped gateway (REQ-20 note).
