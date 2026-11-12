// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A dot-dot step after a link has two readings on Windows: Win32 removes the
// step from the text, Git Bash and the hook follow the link first. The name is
// ordinary only when both readings are. Elsewhere only the second reading
// exists. The test runs the rule on every host through dotDotReadsLexically.
func TestDotDotAfterALinkIsOrdinaryOnlyWhenEveryReadingIs(t *testing.T) {
	for _, windows := range []bool{false, true} {
		for _, row := range []struct {
			name                                string
			lexicalProtected, physicalProtected bool
		}{
			{"both_ordinary", false, false},
			{"cleaned_spelling_protected", true, false},
			{"followed_link_protected", false, true},
			{"both_protected", true, true},
		} {
			name := row.name
			if windows {
				name += "_windows"
			}
			t.Run(name, func(t *testing.T) {
				previous := dotDotReadsLexically
				dotDotReadsLexically = windows
				t.Cleanup(func() { dotDotReadsLexically = previous })
				root := t.TempDir()
				home := filepath.Join(root, "home")
				project := filepath.Join(root, "project")
				other := filepath.Join(root, "other")
				protected := filepath.Join(home, ".defenseclaw", "cache", "entry")
				for _, dir := range []string{filepath.Dir(protected), project, filepath.Join(other, "child")} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(protected, []byte("protected"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(other, "child"), filepath.Join(project, "jump")); err != nil {
					t.Fatal(err)
				}
				entry := func(path string, protectedEntry bool) {
					t.Helper()
					var err error
					if protectedEntry {
						err = os.Symlink(protected, path)
					} else {
						err = os.WriteFile(path, []byte("ordinary"), 0o600)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				entry(filepath.Join(project, "status"), row.lexicalProtected)
				entry(filepath.Join(other, "status"), row.physicalProtected)
				want := GradeNone
				if row.physicalProtected || windows && row.lexicalProtected {
					want = GradeNamed
				}
				target := project + "/jump/../status"
				if got := ProtectedReach(target, home, NewTargetMemo()); got != want {
					t.Errorf("ProtectedReach(%q)=%s want %s", target, got, want)
				}
				if got := LateCallGrade("cat jump/../status", project, home); got != want {
					t.Errorf("late call grade=%s want %s", got, want)
				}
			})
		}
	}
}

// readParentThroughLink reads name in the parent of the folder the link at
// dir reaches: the reading that follows the link first, which POSIX opens for
// dir/../name and which Git Bash and the hook walk on Windows. The Go
// os.ReadFile of a dot-dot path is not an oracle for it on Windows, where
// Win32 removes the step from the text first.
func readParentThroughLink(t *testing.T, dir, name string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(resolved), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// readParentOfText reads name in the parent of dir as written, the reading in
// which Win32 removes the dot-dot step from the text.
func readParentOfText(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(filepath.Dir(dir), name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
