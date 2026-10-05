# Requirements: Windows deferred config

**Status:** Partly implemented (see [README](README.md)).

## Install (workstream A)

- **REQ-01:** `--deferred-config` is a boolean option on both
  `defenseclaw-enterprise-setup` and `defenseclaw enterprise windows
  service`. It defaults to off.
- **REQ-02:** With `--deferred-config`, an install needs neither `--config`
  nor `--manifest`. Without it, an install needs both, or `--mode` and
  `--connector`.
- **REQ-03:** A deferred install creates the protected drop-point directories
  with their ACLs. It writes no config or manifest body. It registers the
  services stopped.
- **REQ-04:** `--deferred-config` is valid only with `install`. Upgrade,
  repair and uninstall reject it before they make any change.
- **REQ-05:** `--deferred-config` cannot be combined with `--mode` or
  `--connector`.
- **REQ-06:** The setup forwards `--deferred-config` to the lifecycle only for
  `install`.
- **REQ-07:** The Windows lifecycle (`install-enterprise.ps1` and
  `DefenseClawEnterprise.psm1`) rejects `-DeferredConfig` before it resolves
  layout paths, takes the lifecycle lock or touches the SCM. The error is:
  "-DeferredConfig is temporarily unavailable: secure target runtime
  preparation requires authenticated targets.yaml during Install". Secure
  target runtime preparation needs an authenticated `targets.yaml` at install
  time. This requirement replaces REQ-03 until a transactional late-drop
  activation exists.

## Gateway wait (workstream B, B2)

- **REQ-08:** When the gateway's first config load fails because
  `config.yaml` does not exist, a managed-enterprise gateway waits for the
  file instead of exiting.
- **REQ-09:** The wait watches the config's parent directory with fsnotify.
  It also polls every 30 seconds, because events can be dropped. If the
  watch cannot be added (for example, the parent directory does not exist
  yet), the wait logs that and polls only.
- **REQ-10:** The wait probes for the file once on entry. This covers a file
  that landed between the failed load and the start of the watch.
- **REQ-11:** The wait ends when the config path is a regular file with a
  size above zero. The gateway then loads the config once more. If that load
  fails, the gateway exits with "failed to load config after wait".
- **REQ-12:** The wait is bounded at 24 hours. At the bound, the gateway
  exits with an error that names the timeout and the path ("configuration
  wait timeout after 24h0m0s at <path> — exiting for SCM restart"). Context
  cancellation returns the cancellation error instead.
- **REQ-13:** Only a missing file (`os.ErrNotExist`) starts the wait. A parse
  error, a file that is too large or a permission error fails at once.
- **REQ-28:** The wait runs only when the SCM environment pin
  `DEFENSECLAW_DEPLOYMENT_MODE` is a valid `managed_enterprise` value. The
  config that would say so has not been read yet. Other deployment modes keep
  the immediate failure.

## Guardian wait (workstream B3)

- **REQ-14:** When `targets.yaml` is missing at startup, a managed-enterprise
  hook guardian waits for it. The wait uses fsnotify on the manifest's parent
  directory and a 30-second poll.
- **REQ-15:** While it waits, the guardian writes the state
  `waiting_for_targets` to its state file.
- **REQ-16:** When the manifest appears, the guardian runs its startup
  reconcile once more. Any error from that retry is fatal. Recovery from it
  belongs to the SCM restart cycle.
- **REQ-17:** After a successful startup reconcile, the guardian writes the
  state `ready`.
- **REQ-18:** The guardian state file is `.state` in the guardian's state
  directory. It holds exactly `waiting_for_targets` or `ready`. Writes use a
  temporary file and a rename, so a reader never sees a partial body.
- **REQ-29:** The guardian wait is bounded at 24 hours. At the bound, the
  guardian exits with "targets.yaml wait timeout after 24h0m0s at <path> —
  exiting for SCM restart". No environment variable or config key changes
  either timeout.

## Health surface (workstream C consumer)

- **REQ-19:** A managed-enterprise health snapshot has a top-level
  `configuration` object with `state` and `since`. The state is
  `waiting_for_config`, `waiting_for_targets` or `ready`.
- **REQ-20:** The state collapses daemon and guardian readiness as follows:
  - daemon config not loaded: `waiting_for_config`;
  - daemon loaded and guardian `ready`: `ready`;
  - daemon loaded and guardian `waiting_for_targets`, unknown or missing:
    `waiting_for_targets`.

  The shipped gateway starts its sidecar and IPC server only after its config
  loads, and it then marks the daemon side loaded. So `waiting_for_config` is
  never served today; the value stays for wire compatibility and for an
  in-process caller.
- **REQ-21:** `since` changes only when the state changes.
- **REQ-22:** A snapshot from any other deployment mode has no
  `configuration` object. Its JSON is unchanged from before this spec.
- **REQ-23:** The sidecar reads the guardian state file at most 128 bytes at
  a time. A missing, unreadable or unknown body reads as unknown.
- **REQ-24:** The sidecar refreshes the configuration state every 5 seconds,
  so a guardian transition shows without a gateway event.
- **REQ-25:** The Secure Client IPC `HealthSnapshot` carries the state as
  `configuration_state` (spec 004 REQ-12, REQ-13).

## Non-functional

- **REQ-26:** The wait loops never treat a parse or permission failure as
  "not yet arrived".
- **REQ-27:** The wait loops add no new privileged surface. They read paths
  from the install-time layout only.

## Acceptance criteria

- **AC-01:** A setup install without `--config`, `--manifest`, `--mode` and
  `--deferred-config` fails with the "install requires both" error.
- **AC-02:** `--deferred-config` with upgrade or repair fails before any
  change.
- **AC-03:** A Windows `-DeferredConfig` install fails with the REQ-07 error
  and leaves no install state behind.
- **AC-04:** A managed gateway started without `config.yaml` resumes once the
  file is written. It does not restart.
- **AC-05:** A non-managed gateway without `config.yaml` exits at once.
- **AC-06:** A managed gateway that waits past the bound exits with the
  distinguishable timeout error. The SCM restart policy then starts it again.
- **AC-07:** A malformed `config.yaml` fails at once, inside or outside the
  wait.
- **AC-08:** Repeated snapshots with no state change carry the same `since`.
- **AC-09:** A guardian started without `targets.yaml` writes
  `waiting_for_targets`. It writes `ready` after the manifest arrives and
  reconciles.
- **AC-10:** A missing or garbled guardian state file never reports `ready`.
- **AC-11:** A non-managed snapshot has no `configuration` key.
- **AC-12:** When the targets arrive while the daemon still waits for config,
  the state goes from `waiting_for_config` to `ready` once the daemon loads
  its config. It does not stop at `waiting_for_targets`. This is checked at
  the health-state level (REQ-20 note).
