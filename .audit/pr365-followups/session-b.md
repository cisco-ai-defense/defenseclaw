# PR #365 Follow-up: Session B

Branch: `codex/pr365-go-runtime-capabilities`
Worktree: `../defenseclaw-pr365-go-runtime-capabilities`
Base PR head: `d024fee`

## Changed Files

- `internal/enforce/policy.go`
- `internal/enforce/policy_test.go`
- `.audit/pr365-followups/session-b.md`

## Phase 1

Implemented Go connector-scoped policy resolution as most-specific-wins for connector-aware install actions:

- A connector-scoped install action decides for that connector.
- Global install actions apply only when no connector-scoped install action exists.
- Connector-scoped block wins over a global allow for that connector.
- Connector-scoped allow overrides a global block for that connector.

The same precedence is applied to the `@<connector>/<tool>` tool-policy helper used by Go runtime lanes.

## Phase 2

Not started. No Session C Antigravity contract file was present in this worktree or sibling `.audit/pr365-followups/` scan at the time of this session.

## Tests Run

- `go test ./internal/enforce ./internal/gateway`

Note: The first gateway test attempt failed before package compilation because `internal/gateway/connector/openclaw_extension/` was missing. Ran the repository prerequisite `make sync-openclaw-extension`, which created the gitignored OpenClaw placeholder used by CI, then reran the required test command successfully.

## Unresolved Questions

- Phase 2 remains blocked until Session C writes the Antigravity contract and approved paths/capability semantics are available.

## Risks

- Runtime skill/plugin disable semantics still use the existing runtime-disable field behavior; this session changed install block/allow precedence and the tool helper precedence only.
- Gateway runtime coverage relies on existing consumers of `PolicyEngine` helpers; no unrelated gateway files were edited.
