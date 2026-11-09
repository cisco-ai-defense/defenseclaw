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
// once for all the readers of a scan (TargetMemo); every read is still a
// walked pathLstat or pathStat, so a path that reaches a share is still asked
// (rel-1-0-9:GAP-0943).
type operandReadsFixture struct {
	home, project, command string
	reads                  *int
	// scanReads are the walk reads each scan of scans made.
	scanReads []int
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
func (fx *operandReadsFixture) scans(t *testing.T) (decision string, state bool) {
	t.Helper()
	memo := NewTargetMemo()
	scan := func(run func()) {
		before := *fx.reads
		run()
		fx.scanReads = append(fx.scanReads, *fx.reads-before)
	}
	scan(func() { decision = memo.ActionCommandDecisionInShell(fx.command, fx.project, fx.home, nil, true) })
	if runtime.GOOS == "windows" {
		return decision, false
	}
	scan(func() { state = memo.ActionStateTargetMention(fx.command, fx.project, fx.home) })
	scan(func() {
		if again := memo.ActionStateTargetMention(fx.command, fx.project, fx.home); again != state {
			t.Fatalf("the second state pass answered %v, the first %v", again, state)
		}
	})
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
	// Each scan reads the name again, so a file that changed between scans is
	// judged as it is; inside a scan the readers of one name share one walk
	// read (before: 17 an operand for the three scans together).
	t.Logf("walk reads for each scan: %v", fx.scanReads)
	for i, reads := range fx.scanReads {
		if want := operands + 100; reads > want {
			t.Errorf("scan %d of %d ordinary operands made %d walk reads, want at most %d", i+1, operands, reads, want)
		}
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

// The scans of one evaluation share a memo, and a second process can change
// a name between two of them. The identity of a file (the hard link that
// names a protected file) is read again by each scan, so the decision judges
// the file as it is when it is made, and answers as without a memo.
func TestHardLinkChangedBetweenScansIsJudgedAsItIsNow(t *testing.T) {
	setup := func(t *testing.T) (home, project, keys, alias string) {
		t.Helper()
		var err error
		if home, err = filepath.EvalSymlinks(t.TempDir()); err != nil {
			t.Fatal(err)
		}
		project = filepath.Join(home, "work", "project")
		keys = filepath.Join(home, ".ssh", "authorized_keys")
		for _, dir := range []string{project, filepath.Dir(keys)} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(keys, []byte("key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return home, project, keys, filepath.Join(project, "alias")
	}
	// scanThenChange runs the state scan, then change, then the decision, on
	// one memo; the memo answers the same as a fresh one after the change.
	scanThenChange := func(t *testing.T, home, project string, change func()) string {
		t.Helper()
		memo := NewTargetMemo()
		end := HookCall()
		defer end()
		if memo.ActionStateTargetMention("touch alias", project, home) {
			t.Fatal("the alias was taken for active state")
		}
		change()
		shared := memo.ActionCommandDecisionInShell("touch alias", project, home, nil, true)
		if fresh := NewTargetMemo().ActionCommandDecisionInShell("touch alias", project, home, nil, true); (fresh != "") != (shared != "") {
			t.Fatalf("decision %q on the shared memo, %q on a fresh one", shared, fresh)
		}
		return shared
	}
	t.Run("an ordinary file that became a hard link to the keys file is blocked", func(t *testing.T) {
		home, project, keys, alias := setup(t)
		if err := os.WriteFile(alias, []byte("ordinary"), 0o600); err != nil {
			t.Fatal(err)
		}
		decision := scanThenChange(t, home, project, func() {
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(keys, alias); err != nil {
				t.Skipf("hard link: %v", err)
			}
		})
		if decision == "" {
			t.Fatal("a hard link to the keys file was allowed")
		}
	})
	t.Run("a hard link that became an ordinary file is allowed", func(t *testing.T) {
		home, project, keys, alias := setup(t)
		if err := os.Link(keys, alias); err != nil {
			t.Skipf("hard link: %v", err)
		}
		decision := scanThenChange(t, home, project, func() {
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(alias, []byte("ordinary"), 0o600); err != nil {
				t.Fatal(err)
			}
		})
		if decision != "" {
			t.Fatalf("an ordinary file was blocked: %q", decision)
		}
	})
	t.Run("a missing name that became a hard link to the keys file is blocked", func(t *testing.T) {
		home, project, keys, alias := setup(t)
		decision := scanThenChange(t, home, project, func() {
			if err := os.Link(keys, alias); err != nil {
				t.Skipf("hard link: %v", err)
			}
		})
		if decision == "" {
			t.Fatal("a hard link to the keys file was allowed")
		}
	})
}
