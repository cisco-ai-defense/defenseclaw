// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package kit

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP1153KitOverBudgetDecisionOnlyForClaimableWords: a shell command
// over the statement budget gets no protected-target decision when none of
// its words gives the gateway a claim to read (substrate-1 GAP-1153): a
// direct write to ~/.ssh/authorized_keys padded past the budget has the
// key-read proof's facts and the word facts as before, less the decision's
// proof, which rel made. A word a link moves (ak-link), or a private place
// of the home (a word in a private working folder), keeps the decision, so
// those facts are rel's; and the write alone gets the decision as before.
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
	if got := proofs(facts(direct, open, false)); len(got) != 0 {
		t.Errorf("direct write past the budget in an open folder: proofs %v, want none (no claimable word)", got)
	}
	if got := proofs(facts(direct, open, true)); !slices.Contains(got, ProofProtectedWrite) {
		t.Errorf("direct write past the budget with rel's decision: proofs %v, want %s", got, ProofProtectedWrite)
	}
	for _, row := range []struct{ name, command, cwd string }{
		{"write alone", "echo k >> ak-link", app},
		{"link word past the budget", "echo k >> ak-link; " + padding, app},
		{"private working folder past the budget", direct, app},
	} {
		head, rel := facts(row.command, row.cwd, false), facts(row.command, row.cwd, true)
		if !slices.Contains(proofs(head), ProofProtectedWrite) || !reflect.DeepEqual(head, rel) {
			t.Errorf("%s: head facts %+v, rel %+v: want rel's facts with the decision", row.name, head, rel)
		}
	}
}
