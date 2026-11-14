// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

// TestTrailingCommentKeepsTheBlock pins GAP-0381: a write the hook blocks on
// its own stays a block whatever comment follows it, whether or not the
// comment holds shell operators and brackets (a comment is not an operand: the
// budget counts nothing in it as nesting, chain or token).
func TestTrailingCommentKeepsTheBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	var keys []readingBoundRow
	for _, name := range []string{"keys-comment", "keys-comment-ops"} {
		for _, n := range budgetShapeNamed(name).sizes {
			keys = append(keys, readingBoundRow{fmt.Sprintf("%s %d", name, n), "Bash", budgetShapeNamed(name).command(n), guardrailActionBlock})
		}
	}
	readingBoundCells(t, keys, 0)
}

// TestGAP0381Fixture087AtEverySize pins the repro of GAP-0381 (corpus case
// gap/p0-round_GAP-1024/087, a sed append to the authorized keys file) with
// a trailing comment of every size from nothing to 70 KB, in both connectors
// and tiers, per user and managed: the comment is not shell, so the call
// stays the block it is without it, and carries no evaluation-limit finding
// of its own (the nested-body weight of the call is 0).
func TestGAP0381Fixture087AtEverySize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	const command = "sed -i '$ a ssh-ed25519 AAAAuccmarker ucc@test' ~/.ssh/authorized_keys"
	var rows []readingBoundRow
	for _, filler := range []struct{ name, unit string }{{"word", "x"}, {"blanks", "x "}, {"hashes", "#"}} {
		for _, size := range []int{0, 2000, 4000, 4096, 4097, 8192, 40000, 70000} {
			text := command
			if size > 0 {
				text += "\n# " + strings.Repeat(filler.unit, size/len(filler.unit))
			}
			if weight := shellparse.NestedBodyWeight(text); weight != 0 {
				t.Fatalf("%s %d: nested-body weight %d, want 0", filler.name, size, weight)
			}
			rows = append(rows, readingBoundRow{fmt.Sprintf("087 %s %d", filler.name, size), "Bash", text, guardrailActionBlock})
		}
	}
	readingBoundCells(t, rows, 0)
}

// TestBudgetSegmentThatIsPastTheBudgetDoesNotAskForItself pins the owner
// trace replay: a statement that names a protected target and is itself past
// the budget (one deeply nested statement of 1.3 KB, the whole call) was its
// own statement twin, and the hook recursed to a stack overflow.
func TestBudgetSegmentThatIsPastTheBudgetDoesNotAskForItself(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	var rows []readingBoundRow
	for _, n := range []int{shellparse.MaxNestingDepth + 1, 1300, 3000} {
		command := "echo ~/.ssh/authorized_keys " + strings.Repeat("(", n) + "a" + strings.Repeat(")", n)
		if shellparse.BudgetExceeded(command) == "" {
			t.Fatalf("nest %d is within the budget", n)
		}
		rows = append(rows, readingBoundRow{fmt.Sprintf("names a key file in %d levels", n), "Bash", command, guardrailActionAlert})
	}
	readingBoundCells(t, rows, 0)
}

// TestCallsTheReadersDidNotReadKeepTheProvenBlock pins GAP-0435 and
// GAP-0381: a write the hook blocks on its own (a keys-file edit) stays a
// block in every cell when the call is past a reading bound, whether the
// padding comes before it or after it, and whether the call is past the
// reading budget (nesting, chains, nodes) or past the nested-body bound (a
// 4 KiB trailing comment carries the weight of the one body that follows
// the command).
func TestCallsTheReadersDidNotReadKeepTheProvenBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX homes and a mode 0 homes folder")
	}
	const keys = "sed -i 's/a/b/' ~/.ssh/authorized_keys"
	var rows []readingBoundRow
	for _, pad := range []overBudget{
		{"nest", shellparse.MaxNestingDepth + 1}, {"pipe", shellparse.MaxChainOperators + 1}, {"flat-words", 20000},
	} {
		padding := pad.command()
		if shellparse.BudgetExceeded(padding) == "" {
			t.Fatalf("%s is within the budget", pad)
		}
		rows = append(rows,
			readingBoundRow{"keys write before " + pad.String(), "Bash", keys + "\n" + padding, guardrailActionBlock},
			readingBoundRow{"keys write after " + pad.String(), "Bash", padding + "\n" + keys, guardrailActionBlock})
	}
	// The write, a body that makes the call weigh as nested bodies, and a
	// comment that puts the call past the nested-body minimum.
	comment := "\n# " + strings.Repeat("x", 4200)
	rows = append(rows, readingBoundRow{"keys write with a 4 KiB comment", "Bash",
		"sed -i '$ a x y z' ~/.ssh/authorized_keys" + comment, guardrailActionBlock})
	readingBoundCells(t, rows, 0)
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
	}, overBudgetRows...)
	pairs := []struct{ connector, mode string }{
		{"claudecode", "observe"}, {"claudecode", "action"}, {"codex", "observe"}, {"codex", "action"},
	}
	if hookAnswerRaceBuild {
		// A race build runs a call 10 to 20 times slower (this test took 707
		// s in a CI-style shard, past its 11 minutes). The state check is
		// the same for every shape of padding and for every call of a
		// connector, so it keeps both connectors and both modes, one pair
		// each, and the shapes that differ in how the budget is reached;
		// TestParseBudgetCallsTakeTheEvaluationLimitPath and
		// TestParseBudgetProbesStayBounded run every row.
		pairs = pairs[:0]
		pairs = append(pairs, struct{ connector, mode string }{"claudecode", "observe"}, struct{ connector, mode string }{"codex", "action"})
		var kept []overBudget
		for _, row := range rows {
			switch row.shape {
			case "or", "mixed", "group-pipe", "block-pipe", "redirect-pipe", "assign-pipe":
				continue
			case "and":
				if row.n > 100 {
					continue
				}
			}
			kept = append(kept, row)
		}
		rows = kept
	}
	for _, pair := range pairs {
		connector, mode := pair.connector, pair.mode
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

// TestParseBudgetProbesStayBounded asserts the memory of the hook on every
// over-budget row (refused before any reader, so a few MiB) and at the cap of
// each chain shape (read in full). The allocation is a count and holds on
// every host; the time is logged, not asserted (it moves with the load of
// the host), and the cost curve of the caps is PARSE_BUDGET_CURVE=1
// (TestParseBudgetCostCurve).
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
	hook := func(command string) string {
		return gap0568ToolHookAction(t, api, "claudecode", "Bash", home, cwd, command, true, false)
	}
	for _, row := range append(append([]overBudget(nil), overBudgetRows...),
		overBudget{"pipe", shellparse.MaxChainOperators}, overBudget{"subst-pipe", shellparse.MaxChainOperators},
		overBudget{"flat-words", 4000}, overBudget{"heredoc-lines", 4000}) {
		command := row.command()
		over := shellparse.BudgetExceeded(command) != ""
		memory := uint64(256 << 20)
		if over {
			memory = 96 << 20
		}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		start := time.Now()
		action := hook(command)
		took := time.Since(start)
		runtime.ReadMemStats(&after)
		// The time is logged, never asserted: it moves with the load of the
		// host (34 s for 8 KB under -race beside a 12-shard run), and the cost
		// curve of the caps (TestParseBudgetCostCurve, PARSELIMITS.md) is the
		// record of it. The allocation is a count and holds on every host.
		t.Logf("%s (%d bytes, over=%t): %d MiB in %s", row, len(command), over, (after.TotalAlloc-before.TotalAlloc)>>20, took)
		if alloc := after.TotalAlloc - before.TotalAlloc; alloc > memory {
			t.Errorf("%s (%d bytes, over=%t): %d MiB allocated, bound %d MiB", row, len(command), over, alloc>>20, memory>>20)
		}
		if over && action != guardrailActionAlert {
			t.Errorf("%s: action=%s, want alert", row, action)
		}
	}
}
