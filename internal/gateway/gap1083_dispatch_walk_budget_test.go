// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1083TopLevelDispatchesOfOneRequestShareTheWalkWait is
// substrate-1:GAP-1083 for the callers that judge one hook request as several
// top-level dispatches without the Copilot envelope: the members of an
// artifact (agent_hook_artifact.go) and the readings of a sandboxed or Codex
// shell command (sandbox_shell_command.go). Each dispatch made its own wait,
// so with every walk slot held three of them took 3 s. Dispatches under the
// request's context wait once, and each still reads the unknown tier where
// its walk was cut, never an allow where the walk with free slots was not.
func TestGAP1083TopLevelDispatchesOfOneRequestShareTheWalkWait(t *testing.T) {
	root, home := gap0674Tree(t)
	commands := []string{"grep -r KEY t0", "grep -r KEY t1", "grep -r KEY t2", "grep -r KEY t3"}
	judge := func(ctx context.Context, command string) []RuleFinding {
		return dispatchTrustedAction(ctx, trustedActionRequest{
			Input:              actionfacts.Input{Tool: "Bash", Command: command, CWD: root, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
			LegacyText:         command,
			Connector:          "claudecode",
			EnforcementCapable: true,
		})
	}
	free := make([][]RuleFinding, len(commands))
	for i, command := range commands {
		free[i] = judge(withHookWalkBudget(t.Context()), command)
	}
	release, ok := actionfacts.HoldCredentialPathWalkSlotsForTest()
	if !ok {
		t.Fatal("a walk slot stayed taken: another test still walks")
	}
	defer release()

	ctx := withHookWalkBudget(t.Context())
	if hookWalkBudgetFrom(ctx) == nil || withHookWalkBudget(ctx) != ctx {
		t.Fatal("a context with the request's wait must keep it")
	}
	waitsBefore := actionfacts.CredentialWalkSlotWaitsForTest()
	start := time.Now()
	for i, command := range commands {
		held := judge(ctx, command)
		if highestFindingSeverity(held) < highestFindingSeverity(free[i]) {
			t.Errorf("%q: %v while the slots were held, weaker than %v with them free", command, held, free[i])
		}
	}
	// One wait for the dispatches of the request, not one each (RV-0674T F1:
	// the count, not a bound of the time, which a loaded box moves). The
	// hook's 3.5 s stays the absolute ceiling.
	if waits := actionfacts.CredentialWalkSlotWaitsForTest() - waitsBefore; waits != 1 {
		t.Errorf("%d dispatches of one request waited %d times for a walk slot while slow walks held every one, want one wait", len(commands), waits)
	}
	if took := time.Since(start); took > gap1083HookAnswerBudget {
		t.Errorf("%d dispatches of one request took %v while slow walks held every walk slot, past the hook's %v", len(commands), took, gap1083HookAnswerBudget)
	}
}

// highestFindingSeverity is the rank of the most severe of findings, 0 for
// none.
func highestFindingSeverity(findings []RuleFinding) int {
	best := 0
	for _, f := range findings {
		best = max(best, guardrailSeverityRank(f.Severity))
	}
	return best
}
