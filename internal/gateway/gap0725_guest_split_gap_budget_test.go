// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0725GuestSplitGapTwinsSpendTheBudgetOnce: a copy-mode sandbox call
// with a parse gap ($CMD) judges its effect twins as the host places the call
// and again in the guest's folder (withSandboxGuestSplitGapEffects). An
// absolute operand is spelled the same in both, so before the fix each such
// twin was judged twice within the call's one budget: a call of many
// absolute operands spent the budget the laptop still has for a later twin
// (substrate-1 GAP-0725). The extra cost of the actor over the laptop must
// not grow with the number of absolute operands; a relative operand is
// still judged in the guest's folder (its twin names a guest file).
func TestGAP0725GuestSplitGapTwinsSpendTheBudgetOnce(t *testing.T) {
	generation, err := compileRulePackGeneration([]ruleCategory{{Name: "command", Rules: []PatternRule{{
		ID: "GAP0725-RM", Title: "GAP0725-RM", Pattern: regexp.MustCompile("gap0725_marker"),
		Expression: "f.commands.exists(c, c.program == 'rm')", Severity: "HIGH", Confidence: 0.99, ToolCallOnly: true,
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	command := func(n int, tail string) string {
		var b strings.Builder
		b.WriteString("$CMD\n")
		for i := range n {
			fmt.Fprintf(&b, "rm -f /tmp/gap0725/f%02d\n", i)
		}
		return b.String() + tail
	}
	cost := func(command, cwd, guest string) uint64 {
		request := trustedActionRequest{Input: actionfacts.Input{Tool: "shell", Command: command, CWD: cwd},
			LegacyText: command, Connector: "claudecode", EnforcementCapable: true,
			SkipLocalFilesystemResolution: guest != "", SandboxGuestCWD: guest,
			generation: generation, budget: newTrustedActionBudget(false)}
		dispatchTrustedAction(t.Context(), request)
		return request.budget.consumed
	}
	extra := func(n int, tail string) int64 {
		c := command(n, tail)
		laptop, actor := cost(c, "/home/alice", ""), cost(c, "", "/home/alice")
		t.Logf("n=%d tail=%q laptop=%d actor=%d", n, tail, laptop, actor)
		return int64(actor) - int64(laptop)
	}
	for _, tail := range []string{"", "rm -f .bash_history\n"} {
		few, many := extra(2, tail), extra(12, tail)
		if many > few {
			t.Errorf("tail %q: actor spends %d over the laptop with 12 absolute operands, %d with 2: the guest reading judges the absolute twins again", tail, many, few)
		}
	}
}
