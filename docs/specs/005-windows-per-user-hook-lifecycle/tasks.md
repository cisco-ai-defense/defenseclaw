# Tasks: Windows per-user hook lifecycle

| Task | Area | State | Evidence |
| --- | --- | --- | --- |
| Third SCM service, ImagePath check, transactions, teardown order | D1 | Done | `DefenseClawEnterprise.psm1`, `cli/tests/test_windows_enterprise_service_contract.py` |
| `enterprise windows enumerate` command and interval loop | REQ-03, REQ-04, REQ-13, REQ-19 | Done | `internal/cli/enterprise_windows_enumerate_windows.go` and its tests |
| ProfileList walk, SID and path filters, dedup | REQ-08 to REQ-11 | Done | `internal/enterprisehooks/enumerator_windows.go`, `enumerator_windows_test.go` |
| Keep existing rows; authorize new rows with a discovered CLI | REQ-12, REQ-13 | Done | `enumerator_windows_test.go` |
| No-op-no-write and DACL-preserving replace | REQ-05, REQ-06 | Done | `TestWriteTargetsManifestAtomicNoOpNoWrite` |
| Standalone enrollment filters, sign-in cycle, manifest-mode idle | REQ-14, REQ-16 | Done | `enterprise_windows_enumerate_enrollment_windows_test.go` |
| Inventory read grants each cycle | REQ-17 | Done | `GrantGatewayInventoryReadForManifest` |
| `SetEnumerator` and deep-copied details | Workstream D, T5.4 | Done in process | `internal/gateway/health_test.go` |
| Carry enumerator health across processes | Workstream D, T5.1 (Stage 9) | Open | needs an `.enumerator-state` file and a sidecar reader |
| Targeted uninstall that passes `ExcludeSIDs` | F1 | Open | option exists; no caller |
| Update comments that still describe audit-only rows | Docs | Open | `EnumerateWindows` doc comment, psm1 notes |
