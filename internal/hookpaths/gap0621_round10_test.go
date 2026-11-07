// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// g621R10Fixture builds a private user skill whose manifest is the given
// link target, and a project skills root that links to the skill folder or
// to the user skills folder.
func g621R10Fixture(t *testing.T, manifestTarget func(home string) string, rootToUserRoot bool) (home, project, root, private string) {
	t.Helper()
	home = t.TempDir()
	userRoot := filepath.Join(home, ".claude", "skills")
	private = filepath.Join(userRoot, "sample")
	if err := os.MkdirAll(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(manifestTarget(home), filepath.Join(private, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	project = filepath.Join(home, "project")
	root = filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	target := private
	if rootToUserRoot {
		target = userRoot
	}
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	return home, project, root, private
}

// REVIEW-9: a private Skill folder whose manifest is a link to a file
// outside the profile is not the caller private skill. The explicit folder
// and manifest spellings bind under both linked-root shapes; a manifest
// link to another private file in the profile stays the caller own skill.
func TestGAP0621R10ManifestLinkTargetOwnership(t *testing.T) {
	outside := func(string) string {
		dir := filepath.Join(t.TempDir(), "sample")
		round6Skill(t, dir, "sample")
		return filepath.Join(dir, "SKILL.md")
	}
	inProfile := func(home string) string {
		dir := filepath.Join(home, "notes", "sample")
		round6Skill(t, dir, "sample")
		return filepath.Join(dir, "SKILL.md")
	}
	for _, shape := range []struct {
		label    string
		toUserRt bool
	}{{"root-to-skill", false}, {"root-to-user-skills", true}} {
		for _, tc := range []struct {
			label  string
			target func(string) string
			bound  bool
		}{{"manifest outside profile", outside, true}, {"manifest in profile", inProfile, false}} {
			t.Run(shape.label+"/"+tc.label, func(t *testing.T) {
				home, project, root, private := g621R10Fixture(t, tc.target, shape.toUserRt)
				for _, source := range []string{private, filepath.Join(private, "SKILL.md")} {
					got := round6Selected(round9Facts(root, home, project, source))
					if tc.bound && len(got) == 0 {
						t.Errorf("source %s reaching an outside manifest produced no selected fact", source)
					}
					if !tc.bound && len(got) != 0 {
						t.Errorf("private source %s claimed as project skill: %v", source, got)
					}
				}
			})
		}
	}
}

// A plain project skill folder whose manifest links to a file outside the
// profile is selected by a source naming that file; a plain folder with its
// own manifest is not claimed by an unrelated source.
func TestGAP0621R10PlainFolderManifestLinkBinds(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	folder := filepath.Join(root, "sample")
	round6Skill(t, filepath.Join(root, "plain"), "plain")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	outsideDir := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, outsideDir, "sample")
	if err := os.Symlink(filepath.Join(outsideDir, "SKILL.md"), filepath.Join(folder, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	got := round6Selected(round9Facts(root, home, project, filepath.Join(outsideDir, "SKILL.md")))
	if len(got) != 1 || got[0] != folder {
		t.Errorf("manifest link target did not bind the project folder: %v", got)
	}
	unrelated := filepath.Join(t.TempDir(), "other")
	round6Skill(t, unrelated, "other")
	if got := round6Selected(round9Facts(root, home, project, unrelated)); len(got) != 0 {
		t.Errorf("unrelated source claimed: %v", got)
	}
}
