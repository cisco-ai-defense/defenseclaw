// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const round14Manifest = "---\nname: sample\n---\nprotected\n"

func round14Write(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func round14Link(t *testing.T, link func(string, string) error, from, to string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := link(from, to); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
}

// REVIEW-13: a second skill folder whose SKILL.md is the same file as the
// manifest the refused project folder links to is another spelling of that
// skill, whether the manifest there is a hard link or a symbolic link and
// whether the call names the folder, its manifest, an alias, a relative path
// or a file inside it. A distinct copy with the same bytes is a different
// file and stays allowed.
func TestGAP0621R14CrossFolderManifestIdentity(t *testing.T) {
	home := t.TempDir()
	project, root, _ := round6Root(t, home)
	projectSkill := filepath.Join(root, "sample")
	base := t.TempDir()
	linked := filepath.Join(base, "source", "linked.md")
	round14Write(t, linked, round14Manifest)
	round14Link(t, os.Symlink, linked, filepath.Join(projectSkill, "SKILL.md"))
	hardDir, symDir, copyDir := filepath.Join(base, "hard"), filepath.Join(base, "symbolic"), filepath.Join(base, "copy")
	round14Link(t, os.Link, linked, filepath.Join(hardDir, "SKILL.md"))
	round14Link(t, os.Symlink, linked, filepath.Join(symDir, "SKILL.md"))
	round14Write(t, filepath.Join(copyDir, "SKILL.md"), round14Manifest)
	round14Write(t, filepath.Join(hardDir, "refs", "note.md"), "note\n")
	alias := filepath.Join(base, "alias")
	round14Link(t, os.Symlink, hardDir, alias)
	relative, err := filepath.Rel(project, hardDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		label, source string
		bound         bool
	}{
		{"hard-linked folder", hardDir, true},
		{"hard-linked manifest", filepath.Join(hardDir, "SKILL.md"), true},
		{"hard-linked alias folder", alias, true},
		{"hard-linked alias manifest", filepath.Join(alias, "SKILL.md"), true},
		{"hard-linked relative folder", relative, true},
		{"hard-linked relative manifest", filepath.Join(relative, "SKILL.md"), true},
		{"file in hard-linked folder", filepath.Join(hardDir, "refs", "note.md"), true},
		{"symbolic folder", symDir, true},
		{"symbolic manifest", filepath.Join(symDir, "SKILL.md"), true},
		{"linked target", linked, true},
		{"distinct copy folder", copyDir, false},
		{"distinct copy manifest", filepath.Join(copyDir, "SKILL.md"), false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, tc.source))
			var want []string
			if tc.bound {
				want = []string{projectSkill}
			}
			if !slices.Equal(got, want) {
				t.Errorf("source %s selected %v; want %v", tc.source, got, want)
			}
		})
	}
}

// The mirror case: the refused folder holds a regular manifest of its own and
// another folder outside the root hard-links to that same file.
func TestGAP0621R14HardLinkToRegularManifest(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	projectSkill := filepath.Join(root, "sample")
	manifest := filepath.Join(target, "sample", "SKILL.md")
	round14Write(t, manifest, round14Manifest)
	base := t.TempDir()
	hardDir, copyDir := filepath.Join(base, "hard"), filepath.Join(base, "copy")
	round14Link(t, os.Link, manifest, filepath.Join(hardDir, "SKILL.md"))
	round14Write(t, filepath.Join(copyDir, "SKILL.md"), round14Manifest)
	for _, tc := range []struct {
		label, source string
		bound         bool
	}{
		{"hard-linked folder", hardDir, true},
		{"hard-linked manifest", filepath.Join(hardDir, "SKILL.md"), true},
		{"distinct copy folder", copyDir, false},
		{"distinct copy manifest", filepath.Join(copyDir, "SKILL.md"), false},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, tc.source))
			var want []string
			if tc.bound {
				want = []string{projectSkill}
			}
			if !slices.Equal(got, want) {
				t.Errorf("source %s selected %v; want %v", tc.source, got, want)
			}
		})
	}
}

// A project link to the caller own private skill, by a link or a hard link in
// the profile, is that user selection and claims nothing.
func TestGAP0621R14PrivateSkillIdentityClaimsNothing(t *testing.T) {
	home := t.TempDir()
	project, root, _ := round6Root(t, home)
	private := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, private, "sample")
	round14Link(t, os.Symlink, filepath.Join(private, "SKILL.md"), filepath.Join(root, "sample", "SKILL.md"))
	for label, source := range map[string]string{
		"private folder":   private,
		"private manifest": filepath.Join(private, "SKILL.md"),
	} {
		t.Run(label, func(t *testing.T) {
			if got := round6Selected(round9Facts(root, home, project, source)); len(got) != 0 {
				t.Errorf("private skill %s selected %v", source, got)
			}
		})
	}
}
