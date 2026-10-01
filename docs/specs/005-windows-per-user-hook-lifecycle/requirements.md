# Requirements: Windows per-user hook lifecycle

## Service (D1)

- **REQ-01:** The installer registers a third SCM service next to the
  gateway and the guardian.
  - The default name is `DefenseClawHookEnumerator`. A certification install
    derives a hashed name (`DefenseClawCertEnumerator_<10 hex>`) from the
    guardian name.
  - The ImagePath is
    `"<gateway>" enterprise windows enumerate --manifest "<targets.yaml>" --interval 5m`,
    and the lifecycle checks it the same way as the other two services.
  - The service runs as LocalSystem with an unrestricted service SID and the
    guardian's privileges: SeTcb, SeImpersonate, SeChangeNotify, SeBackup
    and SeRestore. It writes to the guardian's log.
- **REQ-02:** During an install or servicing transaction the lifecycle:
  - sets the service to disabled, then to automatic start after commit;
  - snapshots and restores its start mode with the other services;
  - stops and removes it first on teardown (enumerator, guardian,
    gateway).

## Command

- **REQ-03:** `defenseclaw-gateway enterprise windows enumerate` takes these
  flags:
  - `--manifest` (required, absolute);
  - `--interval` (default 5m; must be positive unless `--once`);
  - `--once`;
  - `--initial-cycle-delay` (default 30s).

  It fails with the Windows enterprise failure exit code. It is Windows only.
- **REQ-04:** If `config.yaml` is missing, the cycle logs
  "config.yaml unavailable; skipping cycle (waiting_for_config)":
  - the interval loop retries on the next tick;
  - `--once` exits non-zero, so an installer can tell "no config yet" from
    "manifest written".
- **REQ-05:** `WriteTargetsManifestAtomic` writes nothing when the new bytes
  equal the file on disk. A steady-state tick does not wake the guardian.
- **REQ-06:** A changed manifest is staged through a protected file and
  published with a replace that keeps the destination's protected DACL. The
  parent and the file must match the installer contract:
  - Administrators owner and group;
  - exactly SYSTEM and Administrators with FullControl;
  - no reparse points and no extra hard links.

  If staging or the trust check fails, the committed manifest stays as it
  was.
- **REQ-07:** A cycle refuses to run unless `deployment_mode` is
  `managed_enterprise`.

## Profile walk

- **REQ-08:** The walk reads
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`. Each
  (SID, connector) row it emits has the shape the guardian's `LoadManifest`
  accepts. The connectors are `claudecode`, `codex` and `cursor`, plus
  `copilot` where machine policy applies.
- **REQ-09:** A profile is kept only if its `ProfileImagePath` is absolute
  and names a real directory with no reparse point anywhere in its ancestor
  chain.
- **REQ-10:** When two profiles share a SID, the one whose
  `ProfileImagePath` has the newer mtime wins.
- **REQ-11:** A profile is kept only if its SID is valid and names a
  specific interactive user: `S-1-5-21-...` with at least five
  sub-authorities.
  - The standalone profile also admits Microsoft Entra ID users
    (`S-1-12-1-...`).
  - Well-known and service SIDs never pass.
- **REQ-12:** A row already in the manifest keeps its `AgentVersion`,
  `Enabled`, `Deferred`, `User`, `UID` and `GID`.

## Cadence

- **REQ-13:** The loop runs the first cycle after the initial delay
  (default 30s), so the gateway and the guardian log their startup lines
  first. It then runs one cycle per interval.
  - New (SID, connector) rows are authorized when the user's profile has a
    supported install of that connector's CLI. The row is published with
    `Enabled: true`, `Deferred: false` and the discovered `AgentVersion`.
  - A row with no discoverable CLI is left out and logged as
    `[hook-enumerator] skipped ...`.
  - This supersedes the original audit-only clause, which only reported
    new profiles. See the residual-risk section of
    `docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md`.
- **REQ-14:** In the standalone profile:
  - a sign-in triggers one extra cycle after a 15-second settle; a burst
    of sign-ins runs one cycle;
  - when `enterprise.enrollment.mode` is `manifest`, the cycle stays idle
    and only refreshes the gateway's inventory read grants.

## Inputs and enrollment

- **REQ-15:** The CLI validates a target SID it is given
  (`validateWindowsEnterpriseTargetSID`) and refuses system identities. This
  is a second check on top of REQ-11.
- **REQ-16:** The standalone profile applies the enrollment filters:
  - `include_users` adds a profile;
  - `exclude_users` drops one;
  - `exempt_users` keeps only machine-policy rows;
  - `include_groups` and `exclude_groups` apply through a cached group
    lookup.

  An unreadable group cache logs a warning, and the cycle starts from the
  signed-in sessions. Agents found but not enrolled are recorded as
  unprotected.
- **REQ-17:** After each published cycle, the enumerator grants the gateway
  service read access to each enrolled user's inventory directories
  (`GrantGatewayInventoryReadForManifest`). A failure on one directory is
  logged and does not fail the cycle.

## Health and limits

- **REQ-18:** Each cycle logs
  `cycle complete users=<n> targets=<n> changed=<bool> elapsed=<d>`. A
  failed cycle logs its error, and the loop keeps running.
- **REQ-19:** One cycle is bounded at 60 seconds. A cycle over 10 seconds logs
  `WARN cycle exceeded 10 s target`. The 10-second figure is the soft target
  for a 100-user host.

## Targeted uninstall (F1)

- **F1:** `EnumerateOptions.ExcludeSIDs` regenerates the manifest without
  the listed SIDs. Leaving `ExistingManifestPath` empty forces a fresh
  generation.

## Health surface (Workstream D)

- **D-1:** `SidecarHealth.SetEnumerator` records enumerator state as
  `starting`, `running` or `error`, with `LastError`. A snapshot shows it as
  `enumerator` only once it is set, which happens only on Windows
  `managed_enterprise`.
- **D-2:** Health details are deep-copied on set and on snapshot, including
  nested maps, `[]string` and `[]int` (T5.4).
