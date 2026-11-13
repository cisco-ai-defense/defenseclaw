// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// The reading budget of shellparse (GAP-0254, GAP-0255, review GAP-0281 to
// GAP-0285) at the hook. Every input is generated from a shape of
// budget_gen_test.go and a size; none is stored. A call past the budget is
// opaque to the readers: it takes the evaluation-limit path, alerts outside
// the strict tier with the reason parse_budget_exceeded, blocks in strict
// (managed included), and keeps the proof the readers gave before.

// overBudget is one shape at a size past one bound of the budget.
type overBudget struct {
	shape string
	n     int
}

// overBudgetRows covers every dimension of the budget: chains of every
// operator (the two P1 probes first), chains of compound stages, a chain
// that does not parse, deep arithmetic, and flat words and statements.
var overBudgetRows = []overBudget{
	{"pipe", 33577}, {"or", 166443}, {"and", 100000}, {"mixed", 60000},
	{"pipe", shellparse.MaxChainOperators + 1}, {"or", 4096},
	{"subst-pipe", 3000}, {"group-pipe", 3000}, {"block-pipe", 3000}, {"redirect-pipe", 3000}, {"assign-pipe", 3000},
	{"unparsed-pipe", 2000}, {"arith", 3000}, {"flat-words", 20000}, {"flat-stmts", 12000},
	// Nesting past shellparse.MaxNestingDepth (GAP-2537, GAP-0312).
	{"nest", shellparse.MaxNestingDepth + 1}, {"nest", 2000},
}

func (row overBudget) command() string { return budgetShapeNamed(row.shape).command(row.n) }

func (row overBudget) String() string { return fmt.Sprintf("%s x%d", row.shape, row.n) }

func TestParseBudgetCallsTakeTheEvaluationLimitPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	var rows []readingBoundRow
	for _, row := range overBudgetRows {
		if reason := shellparse.BudgetExceeded(row.command()); reason == "" {
			t.Fatalf("%s is within the budget", row)
		}
		rows = append(rows, readingBoundRow{row.String(), "Bash", row.command(), guardrailActionAlert})
	}
	readingBoundCells(t, rows, 0)
}

// TestShellCallPastTheAnalysisLimitIsTruncated pins GAP-0382: one word past
// the string limit of the analysis (64 KiB) leaves no command to judge, and
// is no padding the bounded twin can shorten: it is truncated, an alert
// outside the strict pack and a block in strict, with the state check of the
// raw text. A write the hook blocks stays a block whatever comment follows
// it, whether or not the comment holds shell operators (GAP-0381).
func TestShellCallPastTheAnalysisLimitIsTruncated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	var rows []readingBoundRow
	for _, n := range budgetShapeNamed("bigword").sizes {
		rows = append(rows, readingBoundRow{fmt.Sprintf("one word of %d bytes", n), "Bash", budgetShapeNamed("bigword").command(n), guardrailActionAlert})
	}
	readingBoundCells(t, rows, 0)
	var keys []readingBoundRow
	for _, name := range []string{"keys-comment", "keys-comment-ops"} {
		for _, n := range budgetShapeNamed(name).sizes {
			keys = append(keys, readingBoundRow{fmt.Sprintf("%s %d", name, n), "Bash", budgetShapeNamed(name).command(n), guardrailActionBlock})
		}
	}
	readingBoundCells(t, keys, 0)
}

// TestParseBudgetReasonIsExplicit pins the reason and the profile mapping of
// the finding: the bound rule's reason with the cap, then parse_budget_exceeded;
// an alert in the default tier and in a managed install whose pack is not
// strict (rel-1-0-6:GAP-0675), a block in strict (managed strict included).
func TestParseBudgetReasonIsExplicit(t *testing.T) {
	reason := shellparse.BudgetNodes
	for _, tc := range []struct {
		name    string
		request trustedActionRequest
		want    string
	}{
		{"default", trustedActionRequest{EnforcementCapable: true}, guardrailActionAlert},
		{"managed", trustedActionRequest{EnforcementCapable: true, ManagedInstall: true}, guardrailActionAlert},
		{"strict", trustedActionRequest{EnforcementCapable: true, StrictPolicy: true}, guardrailActionBlock},
		{"managed strict", trustedActionRequest{EnforcementCapable: true, StrictPolicy: true, ManagedInstall: true}, guardrailActionBlock},
	} {
		findings := withBudgetTruncation(tc.request, reason)
		if len(findings) != 1 || findings[0].RuleID != "ACTION-COMPOUND-LIMIT" ||
			findings[0].Evidence != "bounded_truncated cap=nodes; parse_budget_exceeded" {
			t.Fatalf("%s: findings = %+v", tc.name, findings)
		}
		strict := tc.request.StrictPolicy
		got := guardrailActionForProfile(findings, false, func() bool { return strict }, func(string) string { return guardrailActionBlock })
		if got != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestParseBudgetKeepsTheStateWriteProof pins GAP-0281: a write to the
// active DefenseClaw state after any padding blocks in every mode, as it
// did when the readers read the whole call (rel-1-0-2:GAP-0568), whether
// the padding is inside the budget (the readers prove it) or past it (the
// raw-text check, on every shape and for both connectors, per user and
// managed). An over-budget call that names no state is never allowed in
// action mode.
func TestParseBudgetKeepsTheStateWriteProof(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can search a mode 0 directory")
	}
	homes := filepath.Join(t.TempDir(), "homes")
	home := filepath.Join(homes, "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	state := gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	rows := append([]overBudget{
		{"pipe", 100}, {"and", 100}, {"pipe", shellparse.MaxChainOperators}, {"nest", shellparse.MaxNestingDepth},
		// One word past the string limit of the analysis (GAP-0382).
		{"bigword", 70000},
	}, overBudgetRows...)
	for _, connector := range []string{"claudecode", "codex"} {
		for _, mode := range []string{"observe", "action"} {
			api := instructionProtectionTestAPIWithPack(t, connector, mode, "HIGH", "strict")
			for _, cell := range []struct{ client, managed bool }{{false, false}, {true, false}, {true, true}} {
				for _, row := range rows {
					separator := "; "
					if row.shape == "arith" || row.shape == "flat-words" {
						separator = "\n"
					}
					// The write after the padding (GAP-0281) and before it
					// (GAP-0312: the statements read before the cap are judged).
					for _, form := range []struct{ name, command string }{
						{"after", row.command() + separator + "printf changed >> " + state},
						{"before", "printf changed >> " + state + separator + row.command()},
					} {
						if got := gap0568HookAction(t, api, connector, home, cwd, form.command, cell.client, cell.managed); got != guardrailActionBlock {
							t.Errorf("%s/%s client=%t managed=%t state write %s %s: action %q, want block", connector, mode, cell.client, cell.managed, form.name, row, got)
						}
					}
					if mode == "action" && shellparse.BudgetExceeded(row.command()) != "" {
						if got := gap0568HookAction(t, api, connector, home, cwd, row.command(), cell.client, cell.managed); got == guardrailActionAllow {
							t.Errorf("%s/%s client=%t managed=%t %s: allowed", connector, mode, cell.client, cell.managed, row)
						}
					}
				}
			}
		}
	}
}

// TestParseBudgetProbesStayBounded asserts the memory and the time of the
// hook on every over-budget row (refused before any reader, so a few MiB)
// and at the cap of each chain shape (read in full). The bounds are loose:
// they hold under -race on a loaded box, and the cost curve of the caps is
// PARSE_BUDGET_CURVE=1 (TestParseBudgetCostCurve).
func TestParseBudgetProbesStayBounded(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes")
	}
	home := filepath.Join(t.TempDir(), "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	api := readingBoundTierTestAPI(t, "claudecode", config.HookPolicyTierDefault)
	for _, row := range append(append([]overBudget(nil), overBudgetRows...),
		overBudget{"pipe", shellparse.MaxChainOperators}, overBudget{"subst-pipe", shellparse.MaxChainOperators},
		overBudget{"flat-words", 4000}, overBudget{"heredoc-lines", 4000}) {
		command := row.command()
		over := shellparse.BudgetExceeded(command) != ""
		memory, window := uint64(256<<20), 10*time.Second
		if over {
			memory, window = 96<<20, 5*time.Second
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		action := gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > memory || took > window {
			t.Errorf("%s (%d bytes, over=%t): %d MiB allocated in %s", row, len(command), over, alloc>>20, took)
		}
		if over && action != guardrailActionAlert {
			t.Errorf("%s: action=%s, want alert", row, action)
		}
	}
}
