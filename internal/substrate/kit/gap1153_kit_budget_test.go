// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1153Fit repeats unit ({k} counts up) between prefix and suffix up to
// 8190 bytes: the BISECT-1153 S1..S8 scripts.
func gap1153Fit(prefix, unit, suffix string) string {
	var out strings.Builder
	out.WriteString(prefix)
	for k := 0; ; k++ {
		piece := strings.ReplaceAll(unit, "{k}", fmt.Sprint(k))
		if out.Len()+len(piece)+len(suffix) > 8190 {
			break
		}
		out.WriteString(piece)
	}
	return out.String() + suffix
}

func gap1153Bash(t *testing.T, command, cwd string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
		"tool_name": "Bash", "tool_input": map[string]any{"command": command}, "tool_use_id": "t"})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestGAP1153KitOverBudgetDecisionOnlyForClaimableWords: a shell command
// over the statement budget gets no protected-target decision when none of
// its words gives the gateway a claim to read (substrate-1 GAP-1153): a
// write to an ordinary file padded past the budget in an open folder has
// no proof. A word a link moves (ak-link), a private place of the home (a
// word in a private working folder), or a word that names a protected file
// (a direct write to the SSH folder's key list, substrate-1 GAP-1156 item
// 4) keeps the decision, so those facts are rel's; and the write alone
// gets the decision as before.
func TestGAP1153KitOverBudgetDecisionOnlyForClaimableWords(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	app := filepath.Join(home, "app")
	open := filepath.Join(t.TempDir(), "work")
	for _, dir := range []string{filepath.Join(home, ".ssh"), app, open} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(app, "ak-link")); err != nil {
		t.Fatal(err)
	}
	padding := gap1153Fit("", "true;", "true")
	facts := func(command, cwd string, rel bool) *Facts {
		t.Helper()
		if !actionfacts.ShellStatementsOverBudget(command) && len(command) > 4096 {
			t.Fatalf("%.40q is not over the statement budget", command)
		}
		restore := SetOverBudgetShellProofsForTest(rel)
		defer restore()
		return CollectFacts("claudecode", "PreToolUse", gap1153Bash(t, command, cwd), 1<<20)
	}
	proofs := func(f *Facts) []string {
		if f == nil {
			return nil
		}
		return f.Proofs
	}
	direct := "echo k >> ~/.ssh/authorized_keys; " + padding
	ordinary := "echo k >> out.txt; " + padding
	if head, rel := facts(ordinary, open, false), facts(ordinary, open, true); len(proofs(head)) != 0 || !reflect.DeepEqual(head, rel) {
		t.Errorf("ordinary write past the budget in an open folder: head facts %+v, rel %+v: want no proof (no claimable word)", head, rel)
	}
	if got := proofs(facts(direct, open, true)); !slices.Contains(got, ProofProtectedWrite) {
		t.Errorf("direct write past the budget with rel's decision: proofs %v, want %s", got, ProofProtectedWrite)
	}
	for _, row := range []struct{ name, command, cwd string }{
		{"write alone", "echo k >> ak-link", app},
		{"link word past the budget", "echo k >> ak-link; " + padding, app},
		{"private working folder past the budget", direct, app},
		{"protected word past the budget in an open folder", direct, open},
	} {
		head, rel := facts(row.command, row.cwd, false), facts(row.command, row.cwd, true)
		if !slices.Contains(proofs(head), ProofProtectedWrite) || !reflect.DeepEqual(head, rel) {
			t.Errorf("%s: head facts %+v, rel %+v: want rel's facts with the decision", row.name, head, rel)
		}
	}
}
