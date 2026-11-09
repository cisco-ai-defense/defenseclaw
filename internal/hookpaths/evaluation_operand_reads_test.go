// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The scans of one evaluation read each operand of a long command again and
// again (the entry reading of the state scan, the stat of its target, the
// write-target walk), and on Windows each read first walks the folders of
// the name for a link into a network share, about 125 us, so 5000 ordinary
// operands passed the hook answer budget. The evaluation now reads a name
// once for all of its scans (TargetMemo); every read is still a walked
// pathLstat or pathStat, so a path that reaches a share is still asked
// (rel-1-0-9:GAP-0943).
type operandReadsFixture struct {
	home, project, command string
	reads                  *int
}

// newOperandReadsFixture is a project of operands ordinary names and the last
// name that name(home, project) gives, in a home with a keys file, a state
// file and a link to each in the project (entry, keylink).
func newOperandReadsFixture(t *testing.T, operands int, name func(home, project string) string) operandReadsFixture {
	t.Helper()
	resetPlainFolders(t)
	restore := OverrideNetworkSharesForTest(func(string) string { return "" }, func(string) {})
	t.Cleanup(restore)
	home := t.TempDir()
	project := filepath.Join(home, "work", "team", "project")
	for _, dir := range []string{project, filepath.Join(home, ".defenseclaw"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	for target, link := range map[string]string{state: "entry", keys: "keylink"} {
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Skip(err)
		}
	}
	words := make([]string, 0, operands+1)
	for i := range operands {
		words = append(words, fmt.Sprintf("f%d", i+1))
	}
	if name != nil {
		words = append(words, name(home, project))
	}
	return operandReadsFixture{home: home, project: project, command: "touch " + strings.Join(words, " "), reads: countWalkReads(t)}
}

// scans runs what the gateway runs on one evaluation: the action decision and
// the state scan twice (a second pass), on one memo. A Windows home takes the
// state scan through the Windows grammar, which these names do not exercise;
// there only the action decision runs.
func (fx operandReadsFixture) scans(t *testing.T) (decision string, state bool) {
	t.Helper()
	memo := NewTargetMemo()
	decision = memo.ActionCommandDecisionInShell(fx.command, fx.project, fx.home, nil, true)
	if runtime.GOOS == "windows" {
		return decision, false
	}
	state = memo.ActionStateTargetMention(fx.command, fx.project, fx.home)
	if again := memo.ActionStateTargetMention(fx.command, fx.project, fx.home); again != state {
		t.Fatalf("the second state pass answered %v, the first %v", again, state)
	}
	return decision, state
}

func TestEvaluationReadsAnOrdinaryOperandOnce(t *testing.T) {
	const operands = 2000
	fx := newOperandReadsFixture(t, operands, nil)
	end := HookCall()
	decision, state := fx.scans(t)
	end()
	if decision != "" || state {
		t.Fatalf("ordinary operands: decision %q, state %v, want allowed", decision, state)
	}
	// One walk read an operand (the folder of the name); the other readers of
	// the evaluation are answered. Before: 7 an operand.
	if want := 2*operands + 200; *fx.reads > want {
		t.Fatalf("%d ordinary operands made %d walk reads in one evaluation, want at most %d", operands, *fx.reads, want)
	}
}

// The protected twins: the same long command naming the keys file, the state
// file or a link to either last is still judged as before, and an ordinary
// name last stays allowed.
func TestEvaluationStillJudgesProtectedOperandNamedLast(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		last                 func(home, project string) string
		wantBlock, wantState bool
	}{
		{"keys file", func(home, _ string) string { return filepath.Join(home, ".ssh", "authorized_keys") }, true, false},
		{"state file", func(home, _ string) string { return filepath.Join(home, ".defenseclaw", "config.yaml") }, false, true},
		{"link to the state file", func(_, project string) string { return filepath.Join(project, "entry") }, false, true},
		{"link to the keys file", func(_, project string) string { return filepath.Join(project, "keylink") }, true, false},
		{"ordinary name", func(_, project string) string { return filepath.Join(project, "plain") }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newOperandReadsFixture(t, 500, tc.last)
			end := HookCall()
			decision, state := fx.scans(t)
			end()
			if blocked := decision != ""; blocked != tc.wantBlock {
				t.Errorf("decision %q, want block=%v", decision, tc.wantBlock)
			}
			if state != tc.wantState && runtime.GOOS != "windows" {
				t.Errorf("state scan %v, want %v", state, tc.wantState)
			}
		})
	}
}
