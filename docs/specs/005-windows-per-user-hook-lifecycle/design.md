# Design: Windows per-user hook lifecycle

## Components

| Component | Code | Role |
| --- | --- | --- |
| Command | `internal/cli/enterprise_windows_enumerate_windows.go` | Flags, the cycle, the interval loop |
| Walk and publish | `internal/enterprisehooks/enumerator_windows.go` | ProfileList walk, filters, merge, atomic write |
| Agent discovery | `internal/enterprisehooks/agent_version_windows.go` | Per-user CLI version used to authorize new rows |
| Enrollment | `internal/enterprisehooks/enrollment_groups_windows.go` | Standalone group filters and cache |
| Sign-in events | `internal/winsession` | Extra cycle after a sign-in (standalone) |
| SCM service | `packaging/windows/DefenseClawEnterprise.psm1` | Registration, ImagePath check, transactions, teardown |
| Health | `internal/gateway/health.go` | `SetEnumerator`, deep copy of details |

## Cycle

1. Load the config. If it is missing, log `waiting_for_config` and return
   (REQ-04). Refuse any mode other than `managed_enterprise` (REQ-07).
2. Standalone with `enrollment.mode: manifest`: refresh the inventory read
   grants for the administrator's manifest, publish nothing, and return
   (REQ-14).
3. Walk ProfileList with the filters, in order:
   1. a valid SID;
   2. an interactive-user SID;
   3. an absolute `ProfileImagePath`;
   4. a real directory with no reparse point;
   5. not in `ExcludeSIDs`;
   6. the standalone enrollment filters.

   A dropped profile gets a log line.
4. Deduplicate by SID, newest mtime first (REQ-10).
5. Merge with the existing manifest:
   - a known (SID, connector) row keeps the stored decision (REQ-12);
   - a new row is authorized when a CLI version is found, and left out when
     none is (REQ-13).
6. `WriteTargetsManifestAtomic`: no write when the bytes are identical;
   otherwise stage and do a DACL-preserving replace (REQ-05, REQ-06).
7. Grant the gateway's inventory read access (REQ-17).
8. Log the summary line, and the WARN line above 10 seconds (REQ-18,
   REQ-19).

The whole cycle runs under a 60-second context (REQ-19). The registry walk
checks the context between profiles, so a cancelled cycle stops promptly.

## Interfaces

- SCM ImagePath:
  `"<gateway>" enterprise windows enumerate --manifest "<path>" --interval 5m`.
- Installer: before commit, `--once` publishes the first `targets.yaml`.
  This replaces the old inline PowerShell walk.
- Log prefix: `[hook-enumerator]`. The stable lines are `cycle complete`,
  `cycle failed`, `skipped`, `WARN cycle exceeded 10 s target`,
  `cycle idle` and `session sign-in`.
- Health (in process only): the snapshot field `enumerator`, a
  `SubsystemHealth` that is nil until set.

## Tradeoffs

1. **Auto-authorize instead of audit-only.** The first design emitted new
   rows disabled and waited for an administrator to promote them. That left
   new users without hooks for the length of a support ticket. Managed
   deployments already decide at the policy layer which connectors and
   which users are covered. So a new row is authorized when its CLI is
   present, as on macOS.
   - The residual risk is that any user who signs in on a covered host gets
     hooks. It is recorded in the Windows enterprise threat model.
   - The audit path (`publish=false`) remains for test rigs and diagnostics.
     It reports new, changed and absent targets without writing anything.
2. **A separate service, not a guardian goroutine.** The guardian stays a
   pure reconciler of `targets.yaml`. The enumerator can fail or be stopped
   without stopping enforcement for the users already enrolled.
3. **No-op writes.** Comparing bytes avoids about 288 guardian wakes a day
   on a stable host.
4. **Shared log.** LocalSystem can already write the guardian log. A third
   log file would need its own ACL.

## Limits

- **Health across processes (T5.1).** The enumerator and the sidecar are
  separate processes, so production never calls `SetEnumerator`, and the
  snapshot's `enumerator` stays nil.
  - The planned fix: the enumerator writes an `.enumerator-state` file on
    each cycle, as `guardianstate` does, and the daemon polls it.
  - Today the lifecycle readiness check only proves that the SCM service
    runs. A hung loop is not detected.
- **F1 targeted uninstall.** `ExcludeSIDs` exists in `EnumerateOptions`.
  No uninstall path passes it yet.
- **Stale comments.** Some comments still describe the old audit-only
  behavior:
  - the `EnumerateWindows` doc comment says new rows start with
    `Enabled: false`;
  - the psm1 notes call the enumerator a read-only profile audit.

  The code follows REQ-13.
