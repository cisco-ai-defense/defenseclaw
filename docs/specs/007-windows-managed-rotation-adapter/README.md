# Spec 007 — Windows managed token-rotation adapter

Parent issues: #704, #736. Depends on the Linux/macOS participant and
coordinator in #733–#735. This document records the required Phase 1 product
decision. Phase 2 implementation must not start from a different topology.

## Phase 1 decision (reviewable)

Windows managed-enterprise scoped-token rotation is **unavailable** until a
Windows-native participant exists. The Linux/macOS `enterprise hooks
rotate-prepare|rotate-commit|rotate-rollback` journal protocol must not be
used on Windows.

| Question | Decision |
| --- | --- |
| Topology | Future work uses the already shipped `DefenseClawHookGuardian` LocalSystem service. Closed draft PR #658 is not a product contract and must not be treated as landed support. |
| Coordinator | `defenseclaw setup rotate-token` fail-closes on Windows `managed_enterprise` before stopping service A or changing credentials. Unmanaged Windows rotation is unchanged. |
| POSIX guardian | Forbidden as a Windows participant. Routing Windows through that protocol would claim false parity at a privileged credential boundary. |
| Qualified connectors | Only families that already pass the native Windows managed-hook filter. Today that is the certified Claude/Codex managed set; Cursor machine-wide enterprise remains spec 006 and is not a rotation target. |
| Service identity | Guardian mutations run as LocalSystem. Per-user footprint writes require the exact active non-elevated token for the manifest-pinned SID. Split-token administrators and standard users cannot mint, prepare, commit, or roll back rotation state. |
| Path invariants | Windows-native fixed-volume, no-reparse, single-link, owner, and protected-DACL primitives. Do not emulate POSIX ownership checks. |
| Offline / no session | Preflight fails closed when a required interactive session or impersonation token is missing. |
| Prerequisite failure | Rotation remains unavailable. #704 stays open for Windows until Phase 2 plus certification land. |
| Certification | Native Windows CI plus the approved disposable-host enterprise harness. Cross-compilation or Linux/macOS guardian tests are not Windows coverage. |

## Phase 2 (not started)

After this decision is approved, implement prepare/commit/rollback with the
same generation-bound attestation contract as #733/#735, using Windows handles
and DACLs rather than the POSIX journal. Public state may carry only opaque
operation/generation IDs and non-secret fingerprints. Raw A/B credentials must
never appear in argv, environment snapshots, PowerShell transcripts, SCM
configuration, event logs, audit records, or test diagnostics.
