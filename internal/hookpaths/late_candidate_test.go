// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGAP0518LateCandidateText(t *testing.T) {
	home := t.TempDir()
	for _, row := range []struct {
		text string
		want bool
	}{
		{"echo hello", false},
		{"cat README.md", false},
		{"cat ~/.ssh/authorized_keys", true},
		{"cat ~/.ss*/auth*", true},
		{"p=$HOME/.ssh/authorized_keys; cat $p", true},
		{"cat /home/test/.defenseclaw/config.yaml", true},
		{"cat project/authorized_keys_notes.txt", false},
		{"cat project/notes.ssh.txt", false},
		{"echo $PWD", false},
		{"printf '%s' \"$USER\"", false},
		{"cat $unknown", true},
		{"cat $PWD/.ssh/config", true},
		{"cat project/authorized_keys", false},
	} {
		command := strings.ReplaceAll(row.text, "/home/test", home)
		calls, known := LateKnownCalls(command, home, home)
		got := !known
		memo := NewTargetMemo()
		for _, words := range calls {
			for i, word := range words {
				if i == 0 || word == "" {
					continue
				}
				path := word
				if !filepath.IsAbs(path) {
					path = filepath.Join(home, path)
				}
				got = got || ProtectedReach(path, home, memo) != GradeNone
			}
		}
		if got != row.want {
			t.Errorf("candidate %q = %t, want %t", row.text, got, row.want)
		}
	}
}

// GAP-0641 review 7: assignments are read as known values, so a harmless
// prefix keeps an ordinary call ordinary while an assigned protected path
// (whole or as a colon-list element) stays a candidate, and an assignment
// that changes how later words expand stays unknown. A process-relative
// link cannot clear a protected file it reaches.
func TestGAP0641LateAssignmentsAndProcessLinks(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "project")
	state := filepath.Join(home, ".defenseclaw", "cache")
	for _, dir := range []string{cwd, state, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	protected := filepath.Join(state, "entry")
	if err := os.WriteFile(protected, []byte("state"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, filepath.Join(cwd, "alias")); err != nil {
		t.Fatal(err)
	}
	if grade := ProtectedReach(filepath.Join(cwd, "alias"), home, NewTargetMemo()); grade != GradeNamed {
		t.Fatalf("direct protected alias grade=%s, want Named", grade)
	}
	t.Chdir(cwd)
	for _, row := range []struct {
		command string
		want    Grade
	}{
		{"echo ready", GradeNone},
		{"FOO=bar echo ready", GradeNone},
		{"FOO=bar; echo ready", GradeNone},
		{"FOO=bar BAR= echo ready", GradeNone},
		{"LIST=a:b:~/notes echo ready", GradeNone},
		{"FOO=bar cat ~/.ssh/authorized_keys", GradeNamed},
		{"KEY=~/.ssh/authorized_keys echo ready", GradeNamed},
		{"KEY=~/.ssh/authorized_keys; echo ready", GradeNamed},
		{"LIST=a:~/.ssh/authorized_keys echo ready", GradeNamed},
		{"HOME=/tmp echo ready", GradePossible},
		{"PWD=/tmp echo ready", GradePossible},
		{"IFS=/; echo ready", GradePossible},
		{"KEY=$(id) echo ready", GradePossible},
		{"cat /proc/self/cwd/alias", GradePossible},
		{"cat /proc/thread-self/cwd/alias", GradePossible},
		{"cat /proc/1/task/1/cwd/alias", GradePossible},
	} {
		if got := LateCallGrade(row.command, cwd, home); got != row.want {
			t.Errorf("LateCallGrade(%q) = %s, want %s", row.command, got, row.want)
		}
	}
	for _, path := range []string{"/proc/self/cwd/alias", "/proc/thread-self/cwd/alias", "/dev/fd/3", "/dev/stdin"} {
		if grade := ProtectedReach(path, home, NewTargetMemo()); grade == GradeNone {
			t.Errorf("ProtectedReach(%q) = None, want a closed grade", path)
		}
	}
	for _, path := range []string{"/proc/cpuinfo", "/proc/self/status"} {
		if processRelativeLink(path) {
			t.Errorf("processRelativeLink(%q) = true for a plain proc file", path)
		}
	}
}
