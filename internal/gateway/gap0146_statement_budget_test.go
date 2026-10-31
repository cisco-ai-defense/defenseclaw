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
		}
	}
	if form == "pipeline" {
		return "cat notes.txt | " + strings.Join(parts, " | ")
	}
	return strings.Join(parts, "; ")
}

// TestGAP0146OneStatementBudget is rel-1-0-6 GAP-0146 and rel-1-0-2
// GAP-0568: a shell call of more than 128 statements is over the statement
// budget and blocks with ACTION-COMPOUND-LIMIT at every size, per-user and
// managed, for both connectors. Before, the per-command split gave up at
// the analysis node and input bounds (about 460 statements of one form,
// 1000 of another) and the call was allowed, a benign destructive tail
// included, and a managed call whose write targets did not fit the bounded
// map was named an SSH authorized keys mutation. Calls under the budget
// stay allowed; a destructive or protected tail blocks at every size.
func TestGAP0146OneStatementBudget(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	const limit = "ACTION-COMPOUND-LIMIT"
	const keys = "persistence.ssh_authorized_keys_command"
	for _, form := range []string{"same_file", "distinct_files", "echo_only", "pipeline"} {
		for _, n := range []int{100, 128, 129, 150, 300, 450, 500, 600, 1000, 5000} {
			payload := f.payload(t, gap0146Statements(form, n))
			header := f.clientHeader(t, payload)
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{true, false} {
					verdict, body := f.answerAs(t, connector, payload, header, managed)
					name := fmt.Sprintf("%s n=%d %s managed=%v", form, n, connector, managed)
					// A pipeline of n stages has n+1 statements.
					over := n > 128 || form == "pipeline" && n >= 128
					switch {
					case !over && verdict != "allow":
						t.Errorf("%s: verdict %s, want allow (under the budget)", name, verdict)
					case over && (verdict != "block" || !strings.Contains(body, limit)):
						t.Errorf("%s: verdict %s, want block by %s; body %.240s", name, verdict, limit, body)
					case over && strings.Contains(body, keys):
						t.Errorf("%s: benign call named %s; body %.240s", name, keys, body)
					}
				}
			}
		}
	}
	for _, n := range []int{100, 600, 1000, 5000} {
		for tail, rule := range map[string]string{
			"; rm -rf /":                         "",
			"; echo k >> ~/.ssh/authorized_keys": keys,
		} {
			payload := f.payload(t, gap0146Statements("echo_only", n)+tail)
			header := f.clientHeader(t, payload)
			for _, connector := range []string{"claudecode", "codex"} {
				for _, managed := range []bool{true, false} {
					verdict, body := f.answerAs(t, connector, payload, header, managed)
					if verdict != "block" || rule != "" && !strings.Contains(body, rule) {
						t.Errorf("n=%d tail %q %s managed=%v: verdict %s, want block (%s); body %.240s",
							n, tail, connector, managed, verdict, rule, body)
					}
				}
			}
		}
	}
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
	touches := "touch " + gap0151Operands(600, "none", "")
	var heredoc strings.Builder
	heredoc.WriteString("cat > notes.sh <<'EOF'\n")
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&heredoc, "echo line %d\n", i)
	}
	heredoc.WriteString("EOF\n")
	for _, row := range []struct {
		name, command, managed, perUser string
	}{
		{"600 redirects", redirects.String(), "ACTION-COMPOUND-LIMIT", "allow"},
		{"600 touch operands", touches, "allow", "allow"},
		{"3000-line heredoc", heredoc.String(), "allow", "allow"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			for managed, want := range map[bool]string{true: row.managed, false: row.perUser} {
				verdict, body := f.answerAs(t, connector, payload, header, managed)
				switch {
				case want == "allow" && verdict != "allow":
					t.Errorf("%s %s managed=%v: verdict %s, want allow; body %.240s", row.name, connector, managed, verdict, body)
				case want != "allow" && (verdict != "block" || !strings.Contains(body, want) ||
					strings.Contains(body, "persistence.ssh_authorized_keys_command")):
					t.Errorf("%s %s managed=%v: verdict %s, want block by %s only; body %.240s", row.name, connector, managed, verdict, want, body)
				}
			}
		}
	}
}
