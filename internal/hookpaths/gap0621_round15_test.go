// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// REVIEW-14: only a skill folder, or a link to one, can be selected by the
// identity of its manifest. A link to a plain file in the refused root is no
// skill folder, so an ordinary skill whose manifest is the same file as the
// link target is not claimed through it. A real folder whose manifest is the
// same file stays bound.
func TestGAP0621R15StrayFileDoesNotClaimOrdinarySkill(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	ordinary := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, ordinary, "sample")
	linked := filepath.Join(t.TempDir(), "linked.md")
	round14Link(t, os.Link, filepath.Join(ordinary, "SKILL.md"), linked)
	round14Link(t, os.Symlink, linked, filepath.Join(target, "readme.md"))
	sources := []string{ordinary, filepath.Join(ordinary, "SKILL.md")}
	for _, source := range sources {
		if got := round6Selected(round9Facts(root, home, project, source)); len(got) != 0 {
			t.Errorf("ordinary skill source %s claimed root file %v", source, got)
		}
	}
	// Benign twin turned protected: a real folder in the root holding the
	// same manifest file is that skill under another spelling.
	round14Link(t, os.Link, linked, filepath.Join(target, "real", "SKILL.md"))
	for _, source := range sources {
		want := []string{filepath.Join(root, "real")}
		if got := round6Selected(round9Facts(root, home, project, source)); !slices.Equal(got, want) {
			t.Errorf("source %s selected %v; want %v", source, got, want)
		}
	}
}

// REVIEW-14: a refused project manifest that is also a hard link inside
// another, private skill is the protected file wherever it is named: by the
// link, by a symbolic link to it or by a relative path. A distinct private
// copy and the private skill own manifest stay allowed; a project link to
// the private manifest claims nothing.
func TestGAP0621R15ProtectedFileInsidePrivateSkill(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	protected := filepath.Join(target, "sample")
	round6Skill(t, protected, "sample")
	private := filepath.Join(home, ".claude", "skills", "ordinary")
	round6Skill(t, private, "ordinary")
	alias := filepath.Join(private, "refs", "linked.md")
	round14Link(t, os.Link, filepath.Join(protected, "SKILL.md"), alias)
	symlink := filepath.Join(private, "refs", "symlink.md")
	round14Link(t, os.Symlink, alias, symlink)
	relative, err := filepath.Rel(project, alias)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(private, "refs", "copy.md")
	data, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	round14Write(t, copied, string(data))
	for _, tc := range []struct {
		label, source string
		bound         bool
	}{
		{"hard link", alias, true},
		{"symbolic link to the hard link", symlink, true},
		{"relative hard link", relative, true},
		{"distinct private copy", copied, false},
		{"private skill folder", private, false},
		{"private skill manifest", filepath.Join(private, "SKILL.md"), false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, tc.source))
			var want []string
			if tc.bound {
				want = []string{filepath.Join(root, "sample")}
			}
			if !slices.Equal(got, want) {
				t.Errorf("source %s selected %v; want %v", tc.source, got, want)
			}
		})
	}
}

// The private skill own manifest, hard linked into the refused folder, is a
// file the refused root holds: naming it selects the folder. Naming the
// private skill folder is the user own selection, and the same private
// manifest reached by a project symbolic link claims nothing.
func TestGAP0621R15PrivateManifestHardLinkedIntoRefusedFolder(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	private := filepath.Join(home, ".claude", "skills", "ordinary")
	round6Skill(t, private, "ordinary")
	round14Link(t, os.Link, filepath.Join(private, "SKILL.md"), filepath.Join(target, "hard", "SKILL.md"))
	round14Link(t, os.Symlink, filepath.Join(private, "SKILL.md"), filepath.Join(target, "soft", "SKILL.md"))
	for source, want := range map[string][]string{
		filepath.Join(private, "SKILL.md"): {filepath.Join(root, "hard")},
		private:                            nil,
	} {
		if got := round6Selected(round9Facts(root, home, project, source)); !slices.Equal(got, want) {
			t.Errorf("source %s selected %v; want %v", source, got, want)
		}
	}
}

// REVIEW-15: a refused project whose manifest is a link to a file outside the
// profile is that file wherever it is named, a hard link of it inside an
// ordinary private skill included: by the link, by a symbolic link to it or
// by a relative path. A distinct private copy, the private skill folder and
// its manifest stay allowed.
func TestGAP0621R15LinkedProjectManifestAliasInsidePrivateSkill(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	linked := filepath.Join(t.TempDir(), "linked.md")
	round14Write(t, linked, round14Manifest)
	round14Link(t, os.Symlink, linked, filepath.Join(target, "sample", "SKILL.md"))
	private := filepath.Join(home, ".claude", "skills", "ordinary")
	round6Skill(t, private, "ordinary")
	alias := filepath.Join(private, "refs", "linked.md")
	round14Link(t, os.Link, linked, alias)
	symlink := filepath.Join(private, "refs", "symbolic.md")
	round14Link(t, os.Symlink, alias, symlink)
	relative, err := filepath.Rel(project, alias)
	if err != nil {
		t.Fatal(err)
	}
	copied := filepath.Join(private, "refs", "copy.md")
	round14Write(t, copied, round14Manifest)
	for _, tc := range []struct {
		label, source string
		bound         bool
	}{
		{"hard link", alias, true},
		{"symbolic link to the hard link", symlink, true},
		{"relative hard link", relative, true},
		{"distinct private copy", copied, false},
		{"private skill folder", private, false},
		{"private skill manifest", filepath.Join(private, "SKILL.md"), false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, tc.source))
			var want []string
			if tc.bound {
				want = []string{filepath.Join(root, "sample")}
			}
			if !slices.Equal(got, want) {
				t.Errorf("source %s selected %v; want %v", tc.source, got, want)
			}
		})
	}
}
