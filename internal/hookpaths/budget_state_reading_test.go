// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// budgetPadding builds the padding of a call past one dimension of the
// reading budget (shellparse.BudgetExceeded) from a shape and a size.
var budgetPadding = map[string]func(n int) string{
	"pipe":  func(n int) string { return strings.Repeat("a|", n) + "a" },
	"or":    func(n int) string { return strings.Repeat("a||", n) + "a" },
	"nest":  func(n int) string { return strings.Repeat("(", n) + "true" + strings.Repeat(")", n) },
	"arith": func(n int) string { return "echo $((1" + strings.Repeat("+1", n) + "))" },
	"words": func(n int) string { return "echo " + strings.Repeat("a ", n) },
	"stmts": func(n int) string { return strings.Repeat("echo x > ordinary/f.txt;", n) + "true" },
}

// TestClientHeaderOfAnOverBudgetCallListsTheStateAndTheMarker pins the bound
// rule at the hook client: a call past the reading budget, with a write to
// the DefenseClaw state before the padding or after it, gets a map that
// lists the state and carries the truncated marker; one that names no state
// gets the marker alone. No reader can take an empty map for a call that
// touched nothing.
func TestClientHeaderOfAnOverBudgetCallListsTheStateAndTheMarker(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	write := "printf changed >> '" + state + "'"
	header := func(command string) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "budget", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(body))
		if !ok {
			t.Fatalf("%.40q: header does not decode", command)
		}
		return targets
	}
	for _, row := range []struct {
		shape string
		n     int
	}{
		{"pipe", 700}, {"pipe", 33577}, {"or", 5000}, {"nest", shellparse.MaxNestingDepth + 1}, {"nest", 2000},
		{"arith", 3000}, {"words", 20000}, {"stmts", 12000},
	} {
		padding := budgetPadding[row.shape](row.n)
		if shellparse.BudgetExceeded(padding) == "" {
			t.Fatalf("%s x%d is within the budget", row.shape, row.n)
		}
		separator := "; "
		if row.shape == "arith" || row.shape == "words" {
			separator = "\n"
		}
		for form, command := range map[string]string{"after": padding + separator + write, "before": write + separator + padding} {
			got := header(command)
			if got[TruncatedKey] != "1" {
				t.Errorf("%s x%d state write %s: header %v has no truncated marker", row.shape, row.n, form, got)
			}
			if _, listed := got[state]; !listed {
				t.Errorf("%s x%d state write %s: header %v does not list %s", row.shape, row.n, form, got, state)
			}
		}
		got := header(padding)
		if got[TruncatedKey] != "1" || len(got) != 2 {
			t.Errorf("%s x%d naming no state: header %v, want only the truncated marker and cwd", row.shape, row.n, got)
		}
	}
}
