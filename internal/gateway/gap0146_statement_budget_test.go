// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// withoutStatementBudget drops the statement-budget finding, for a test of
// another reader on a call that is also over the budget.
func withoutStatementBudget(findings []RuleFinding) []RuleFinding {
	return slices.DeleteFunc(slices.Clone(findings), func(f RuleFinding) bool {
		return f.RuleID == "ACTION-COMPOUND-LIMIT"
	})
}

// gap0146Statements is n statements of a benign form joined into one line.
func gap0146Statements(form string, n int) string {
	parts := make([]string, n)
	for i := range parts {
		switch form {
		case "same_file":
			parts[i] = fmt.Sprintf("echo line%d >> notes.txt", i)
		case "distinct_files":
			parts[i] = fmt.Sprintf("echo line%d >> ordinary/n%d.txt", i, i)
		case "echo_only":
			parts[i] = fmt.Sprintf("echo line%d", i)
		case "pipeline":
			parts[i] = "cat"
		case "long_lines":
			// 300-byte statements: past the 64 KiB input bound with few
			// statements.
			parts[i] = "echo " + strings.Repeat("x", 295)
		}
	}
	if form == "pipeline" {
		return "cat notes.txt | " + strings.Join(parts, " | ")
	}
	return strings.Join(parts, "; ")
}

// gap0146Want is the expected answer of one table row: "allow", or "block"
// by rule (any rule when rule is empty) and never by forbidden.
type gap0146Want struct {
	verdict, rule, forbidden string
}

func (w gap0146Want) check(t *testing.T, call *hookCall) {
	t.Helper()
	switch {
	case w.verdict == "allow" && call.verdict != "allow":
		t.Errorf("%s: verdict %s, want allow; body %.240s", call.name, call.verdict, call.body)
	case w.verdict == "block" && (call.verdict != "block" || w.rule != "" && !strings.Contains(call.body, w.rule)):
		t.Errorf("%s: verdict %s, want block by %q; body %.240s", call.name, call.verdict, w.rule, call.body)
	case w.forbidden != "" && strings.Contains(call.body, w.forbidden):
		t.Errorf("%s: named %s; body %.240s", call.name, w.forbidden, call.body)
	}
}

// runGAP0146Table answers every row for both connectors, managed and
// per-user, concurrently, and checks each answer.
func runGAP0146Table(t *testing.T, f b36ManagedHookFixture, commands []string, want func(row int, managed bool) gap0146Want, names []string) {
	t.Helper()
	payloads := make([][]byte, len(commands))
	for i, command := range commands {
		payloads[i] = f.payload(t, command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i := range commands {
		calls = append(calls, everyMode(names[i], payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want(i/4, call.managed).check(t, call)
	}
}

// TestGAP0146OneStatementBudget is rel-1-0-6 GAP-0146 and rel-1-0-2
// GAP-0568: a shell call of more than 128 statements is over the statement
// budget and blocks with ACTION-COMPOUND-LIMIT at every size, per-user and
// managed, for both connectors. Before, the per-command split gave up at
// the analysis node and input bounds (about 460 statements of one form,
// 1000 of another) and the call was allowed, a benign destructive tail
// included, and a managed call whose write targets did not fit the bounded
// map was named an SSH authorized keys mutation. Calls under the budget
// stay allowed; a destructive or protected tail blocks at every size. The
// rows run concurrently. A race build (the CI gateway shards, about 20 times
// slower) runs the sizes at each bound: 128 and 129 statements, the fact
// bound (300), the node bound (600, 1000 for the short form) and the input
// bound (long_lines 250); every form, both tails, connector and mode stays.
func TestGAP0146OneStatementBudget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const limit = "ACTION-COMPOUND-LIMIT"
	const keys = "persistence.ssh_authorized_keys_command"
	sizes := []int{100, 128, 129, 150, 300, 450, 500, 600, 1000, 5000}
	tails := []int{100, 600, 1000, 5000}
	if hookAnswerRaceBuild {
		sizes, tails = []int{128, 129, 300, 600, 1000}, []int{600}
	}
	var commands, names []string
	var wants []gap0146Want
	for _, form := range []string{"same_file", "distinct_files", "echo_only", "pipeline", "long_lines"} {
		forms := sizes
		if form == "long_lines" {
			forms = []int{100, 250}
		} else if hookAnswerRaceBuild && form != "echo_only" {
			forms = slices.DeleteFunc(slices.Clone(sizes), func(n int) bool { return n == 1000 })
		}
		for _, n := range forms {
			commands = append(commands, gap0146Statements(form, n))
			names = append(names, fmt.Sprintf("%s n=%d", form, n))
			// A pipeline of n stages has n+1 statements.
			if n > 128 || form == "pipeline" && n >= 128 {
				wants = append(wants, gap0146Want{"block", limit, keys})
			} else {
				wants = append(wants, gap0146Want{verdict: "allow"})
			}
		}
	}
	for _, n := range tails {
		for _, tail := range []struct{ text, rule string }{
			{"; rm -rf /", ""},
			{"; echo k >> ~/.ssh/authorized_keys", keys},
		} {
			commands = append(commands, gap0146Statements("echo_only", n)+tail.text)
			names = append(names, fmt.Sprintf("echo_only n=%d tail %q", n, tail.text))
			wants = append(wants, gap0146Want{verdict: "block", rule: tail.rule})
		}
	}
	runGAP0146Table(t, f, commands, func(row int, _ bool) gap0146Want { return wants[row] }, names)
}

// TestGAP0146BoundedMapOverflowIsTheBudget keeps the managed known limit of
// rel-1-0-3 GAP-0291 (a call with more write targets than the bounded map
// holds blocks; per-user is not affected) and names it: the block is the
// evaluation budget, not an SSH authorized keys mutation. One statement
// with many write operands is not over the statement budget.
func TestGAP0146BoundedMapOverflowIsTheBudget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	var redirects strings.Builder
	redirects.WriteString("echo hi")
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&redirects, " > ordinary/r%d", i)
	}
	var heredoc strings.Builder
	heredoc.WriteString("cat > notes.sh <<'EOF'\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&heredoc, "echo line %d\n", i)
	}
	heredoc.WriteString("EOF\n")
	allow := gap0146Want{verdict: "allow"}
	runGAP0146Table(t, f,
		[]string{redirects.String(), "touch " + gap0151Operands(600, "none", ""), heredoc.String()},
		func(row int, managed bool) gap0146Want {
			if row == 0 && managed {
				return gap0146Want{"block", "ACTION-COMPOUND-LIMIT", "persistence.ssh_authorized_keys_command"}
			}
			return allow
		},
		[]string{"600 redirects", "600 touch operands", "3000-line heredoc"})
}
