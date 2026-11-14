// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The caps of the shell reading budget (shellparse.BudgetExceeded) for the
// property test of the bound rule (TestBoundRuleEveryLaneCap). Each cap is
// found by search on the budget itself, so the table follows the constants.
//
// The chain operators bound (shellparse.MaxChainOperators, 512) is not a
// cap of its own at the hook: a chain of that many stages is over the
// statement budget (128, the "shell-parse statements" lane) at every size
// from 129, so no input is at the chain cap without being past a cap. Its
// exact bound is TestChainBudgetIsExact (internal/shellparse).
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "shell-parse tree nodes", cap: bounded.Nodes, limit: budgetLimit(boundedFlatWords, 40000),
			gen: boundedShellLane(boundedFlatWords, boundedMultiCap(boundedFlatWords)), seen: boundedShellSeenCall},
		boundedLaneCap{lane: "shell-parse tree depth", cap: bounded.Depth, limit: budgetLimit(boundedArithChain, 40000),
			gen: boundedShellLane(boundedArithChain, boundedMultiCap(boundedArithChain)), seen: boundedShellSeenCall},
		// The bytes cap of the reading budget (shellparse.MaxCommandBytes, 1 MiB)
		// is shadowed at the hook by the string limit of the analysis (64 KiB):
		// a text past it is read by the over-limit machinery, not truncated
		// (rel-1-0-10:GAP-0382 is open on that class, see docs/PARSELIMITS.md).
	)
}

// boundedMultiCap is fill(size) behind a list of statements past the
// statement budget: two caps hit at once.
func boundedMultiCap(fill func(int) string) func(int) string {
	return func(size int) string { return gap0568Assignments(2*boundedShellStatements) + "; " + fill(size) }
}

// boundedFlatWords is one double-quoted word of size parameter expansions:
// two nodes each, one statement and one operand.
func boundedFlatWords(size int) string { return "echo \"" + strings.Repeat("$a", size) + "\"" }

// boundedArithChain is an arithmetic expression of size additions: a tree
// size levels deep.
func boundedArithChain(size int) string { return "echo $((1" + strings.Repeat("+1", size) + "))" }

// boundedQuotedWords is one double-quoted string of size words: many tokens,
// few nodes.
func boundedQuotedWords(size int) string { return "echo \"" + strings.Repeat("a ", size) + "\"" }

// boundedOneWord is one word of size bytes.
func boundedOneWord(size int) string { return "echo " + strings.Repeat("a", size) }

// budgetLimit is the largest size up to max for which the call of fill is
// within the reading budget.
func budgetLimit(fill func(int) string, max int) int {
	low, high := 1, max
	for low < high {
		mid := (low + high + 1) / 2
		if shellparse.BudgetExceeded(fill(mid)) == "" {
			low = mid
		} else {
			high = mid - 1
		}
	}
	return low
}
