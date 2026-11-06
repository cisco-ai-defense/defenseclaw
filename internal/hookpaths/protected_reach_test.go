// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestProtectedReachGradesNamedAndOrdinaryPaths(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "project")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	policy := filepath.Join(home, ".defenseclaw", "policies", "rule.yaml")
	for _, dir := range []string{filepath.Dir(keys), filepath.Dir(policy), project} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{keys, state, policy} {
		if err := os.WriteFile(file, []byte("fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ordinary := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	if err := os.WriteFile(knownHosts, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	direct := filepath.Join(project, "direct")
	relative := filepath.Join(project, "relative")
	parent := filepath.Join(project, "linked-dir")
	hard := filepath.Join(project, "hard")
	if err := os.Symlink(keys, direct); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	rel, err := filepath.Rel(project, keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(rel, relative); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(keys), parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, hard); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	chain := filepath.Join(project, "step0")
	for i := 0; i < 20; i++ {
		next := keys
		if i < 19 {
			next = filepath.Join(project, "step"+strconv.Itoa(i+1))
		}
		if err := os.Symlink(next, filepath.Join(project, "step"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, path string
		want       Grade
	}{
		{"direct", keys, GradeNamed},
		{"direct-link", direct, GradeNamed},
		{"relative-link", relative, GradeNamed},
		{"parent-link", filepath.Join(parent, "authorized_keys"), GradeNamed},
		{"parent-link-missing", filepath.Join(parent, "authorized_keys2"), GradeNamed},
		{"hard-link", hard, GradeNamed},
		{"long-chain", chain, GradeNamed},
		{"state-file", state, GradeNamed},
		{"state-tree", policy, GradeNamed},
		{"ordinary-file", ordinary, GradeNone},
		{"ordinary-missing", filepath.Join(project, "new.txt"), GradeNone},
		{"ordinary-ssh-file", knownHosts, GradeNone},
		{"ordinary-ssh-sibling", filepath.Join(home, ".ssh", "notes.txt"), GradeNone},
		{"ordinary-state-sibling", filepath.Join(home, ".defenseclaw", "notes.txt"), GradeNone},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := ProtectedReach(row.path, home, NewTargetMemo()); got != row.want {
				t.Fatalf("ProtectedReach(%s) = %s, want %s", row.name, got, row.want)
			}
		})
	}
}

func TestGradeMaximumKeepsNamedThroughPossibleSegments(t *testing.T) {
	for _, row := range []struct {
		parts []Grade
		want  Grade
	}{
		{[]Grade{GradePossible, GradeNamed}, GradeNamed},
		{[]Grade{GradeNamed, GradePossible}, GradeNamed},
		{[]Grade{GradeNone, GradePossible}, GradePossible},
		{[]Grade{GradeNone, GradeNone}, GradeNone},
	} {
		got := GradeNone
		for _, part := range row.parts {
			got = got.Max(part)
		}
		if got != row.want {
			t.Fatalf("maximum %v = %s, want %s", row.parts, got, row.want)
		}
	}
}
