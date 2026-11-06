// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

func TestG288ProtectedDirectoryAliasClosure(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	ssh := filepath.Join(home, ".ssh")
	policies := filepath.Join(home, ".defenseclaw", "policies")
	for _, dir := range []string{ssh, policies, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, destination string
		grade             Grade
	}{
		{"ssh", ssh, GradeNamed},
		{"policies", policies, GradeNamed},
	} {
		alias := filepath.Join(project, row.name)
		if err := os.Symlink(row.destination, alias); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		for _, target := range []struct {
			name string
			path string
			want Grade
		}{
			{"directory", alias, row.grade},
			{"listed child", filepath.Join(alias, "authorized_keys"), GradeNamed},
		} {
			if row.name == "policies" && target.name == "listed child" {
				target.path = filepath.Join(alias, "rule.yaml")
			}
			t.Run(row.name+"/"+target.name, func(t *testing.T) {
				if got := ProtectedReach(target.path, home, NewTargetMemo()); got != target.want {
					t.Fatalf("reach %s = %s, want %s", target.path, got, target.want)
				}
			})
		}
	}
	// The SSH directory itself is protected, while an unlisted sibling
	// reached through it is an ordinary file.
	if got := ProtectedSSHReach(filepath.Join(project, "ssh", "notes.txt"), home, NewTargetMemo()); got != GradeNone {
		t.Fatalf("unlisted SSH sibling = %s, want none", got)
	}
	if got := ProtectedSSHReach(filepath.Join(project, "policies", "rule.yaml"), home, NewTargetMemo()); got != GradeNone {
		t.Fatalf("state tree under SSH rule = %s, want none", got)
	}
}

func TestG288ProtectedReachAnsweredShareDelay(t *testing.T) {
	for _, delayMS := range []int{0, 40, 80, 120, 300, 700, 760, 780} {
		for _, kind := range []string{"hard", "link", "ordinary"} {
			t.Run(strconv.Itoa(delayMS)+"ms/"+kind, func(t *testing.T) {
				root := t.TempDir()
				home := filepath.Join(root, "home")
				project := filepath.Join(root, "project")
				if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(project, 0o700); err != nil {
					t.Fatal(err)
				}
				keys := filepath.Join(home, ".ssh", "authorized_keys")
				if err := os.WriteFile(keys, []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(project, kind)
				switch kind {
				case "hard":
					if err := os.Link(keys, target); err != nil {
						t.Skipf("hard link unavailable: %v", err)
					}
				case "link":
					if err := os.Symlink(keys, target); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				default:
					if err := os.WriteFile(target, []byte("ordinary"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				fakeNetworkShare(t, root, networkShareAnswerWait, 5*time.Second, func(string) {
					time.Sleep(2 * time.Second)
				})
				oldRead := readPath
				t.Cleanup(func() { readPath = oldRead })
				readPath = func(name string, kind pathReadKind) pathReadResult {
					if name == root || strings.HasPrefix(name, root+string(filepath.Separator)) {
						time.Sleep(time.Duration(delayMS) * time.Millisecond)
					}
					return oldRead(name, kind)
				}
				want := GradeNamed
				if kind == "ordinary" {
					want = GradePossible
				}
				if got := ProtectedReach(target, home, NewTargetMemo()); got != want {
					t.Fatalf("delay %dms reach %s = %s, want %s", delayMS, kind, got, want)
				}
			})
		}
	}
}

func TestG288LinkSourceUsesPlacedDirectory(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		name, source string
		want         bool
	}{
		{"protected", ".ssh/authorized_keys", true},
		{"ordinary", "notes.txt", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			links := CommandLinksWithFacts("Bash", "env -C ~ ln -s "+row.source+" project/link", project, home, nil)
			if got := links.LinkNamesProtectedSource(home, NewTargetMemo()); got != row.want {
				t.Fatalf("link source = %t, want %t", got, row.want)
			}
		})
	}
}
