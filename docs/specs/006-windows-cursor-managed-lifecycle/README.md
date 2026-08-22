# Spec 006 — Windows cursor managed_enterprise lifecycle (stub)

Extend the Windows `managed_enterprise` per-user hook lifecycle from the
`codex` + `claudecode` pair to also cover `cursor`.

## Why

Cursor exists in the cross-platform connector registry (works on macOS
`managed_enterprise`). On Windows the reconcile, teardown-snapshot,
trusted-state, and native-hook-runtime writers all fail closed on
`cursor` today — reject-with-an-error rather than "not implemented,"
because shipping cursor without teardown-snapshot machinery would strand
any pre-existing `%USERPROFILE%\.cursor\hooks.json` on uninstall (real
data-loss risk).

Existing rejection points (all `!= "codex" && != "claudecode"` checks):

- `internal/cli/hook_trusted_state_windows.go:137` — CLI subcommand
  connector allow-list.
- `internal/cli/windows_managed_hooks_teardown.go:636` — teardown /
  snapshot machinery.
- `internal/gateway/connector/subprocess.go:616` —
  `ReconcileManagedNativeHookRuntime`.
- `internal/gateway/connector/subprocess.go:635` —
  `ValidateManagedNativeHookRuntime`.
- `internal/gateway/connector/subprocess.go:937` — companion accept
  list.

Plus arg-validation early-reject added in this PR at
`cmd/defenseclaw-enterprise-setup/main.go` and
`internal/cli/windows_enterprise_service.go` so the failure surfaces at
the arg boundary instead of deep in the transaction.

## Scope

- Per-user reconcile writer for `%USERPROFILE%\.cursor\hooks.json`
  routed through `managed.WriteServiceRuntimeFile` (managed-runtime
  trust contract; not `atomicWriteFile`'s private-state contract).
- Teardown snapshot + restore for `%USERPROFILE%\.cursor\hooks.json`
  parallel to how spec 004 handles Claude Code's
  `%USERPROFILE%\.claude\settings.json` and spec 002 handles Codex's
  `%ProgramData%\OpenAI\Codex\requirements.toml`.
- Trusted-state validator additions accepting a cursor row shape.
- Manifest schema — no change (cursor already a valid connector).
- Enumerator — likely no change (spec 005 D1 already enumerates all
  supported connectors on the ProfileList walk).
- Tests: cursor reconcile round-trip, snapshot preserves pre-existing
  user hooks, uninstall restores exact bytes.

## Non-goals

- Windows managed_enterprise `amp` support — separate spec if/when
  needed.
- Application control / machine-policy attestation for cursor —
  cursor's hook is per-user with no machine-level component, unlike
  Codex (machine `requirements.toml`) or Claude (machine
  `managed-settings.json`).

## Follow-up

Design + requirements + tasks + plan documents live alongside the other
`docs/specs/00N-windows-*` specs (archived out-of-tree in the
`defenseclaw-debug/windows-parity-windows/` folder per PR #767 body).
Land this spec's documents there when the work starts.
