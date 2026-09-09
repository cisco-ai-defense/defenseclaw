# Spec 007 — Windows managed token-rotation adapter

Parent issues: #704, #736. Depends on the Linux/macOS participant and
coordinator in #733–#735. This document records the required Phase 1 product
decision and the Phase 2 native participant.

## Phase 1 decision (reviewable)

Windows managed-enterprise scoped-token rotation must not use the Linux/macOS
`enterprise hooks rotate-prepare|rotate-commit|rotate-rollback` journal
protocol. Closed draft PR #658 is not a product contract.

| Question | Decision |
| --- | --- |
| Topology | The already shipped `DefenseClawHookGuardian` LocalSystem service is the participant. Closed draft PR #658 is not a product contract and must not be treated as landed support. |
| Coordinator | `defenseclaw setup rotate-token` joins Windows `managed_enterprise` through the native adapter. Unmanaged Windows rotation is unchanged. |
| POSIX guardian | Forbidden as a Windows participant. A POSIX `rotation-transaction.json` on Windows is a fail-closed conflict. |
| Qualified connectors | Only families that already pass the native Windows managed-hook filter. Today that is the certified Claude/Codex managed set; Cursor machine-wide enterprise remains spec 006 and is not a rotation target. |
| Service identity | Guardian mutations run as LocalSystem. Per-user footprint writes require the exact active non-elevated token for the manifest-pinned SID. Split-token administrators and standard users cannot mint, prepare, commit, or roll back rotation state. |
| Path invariants | Windows-native fixed-volume, no-reparse, single-link, owner, and protected-DACL primitives. Do not emulate POSIX ownership checks. |
| Offline / no session | Preflight fails closed when a required interactive session or impersonation token is missing. |
| Prerequisite failure | Rotation remains unavailable. #704 stays open for Windows until disposable-host certification lands. |
| Certification | Native Windows CI plus the approved disposable-host enterprise harness. Cross-compilation or Linux/macOS guardian tests are not Windows coverage. |

## Phase 2 (native participant)

Windows prepare/commit/rollback uses a distinct journal
(`windows-rotation-transaction.json`, schema `windows-guardian-rotation.v1`)
and the same public JSON contract consumed by #735: `ok`, `action`,
`operation_id`, `generation`, `phase`, and target count.

| Phase | Windows behavior |
| --- | --- |
| Preflight | LocalSystem identity, current #733 attestations, exact SID, canonical profile, certified Claude/Codex connector, active interactive session, no-reparse/single-link/fixed-volume handle proof, protected DACL, expected non-secret fingerprint, and rollback capacity. |
| Prepare | Snapshot exact A through a no-follow handle, impersonate the manifest SID, publish B, re-read B through a no-follow handle, then publish generation-bound current attestations. Partial failure restores exact A. |
| Commit | Re-prove every target is on B (fingerprint + owner SID + protected DACL) before retiring rollback material. Idempotent and operation/generation-bound. |
| Rollback | Impersonate each SID and restore exact A bytes or absence, owner, protected DACL, and volume identity. Readiness stays false unless restoration can be proved. |

Public state may carry only opaque operation/generation IDs and non-secret
fingerprints. Raw A/B credentials must never appear in argv, environment
snapshots, PowerShell transcripts, SCM configuration, event logs, audit
records, or test diagnostics.
