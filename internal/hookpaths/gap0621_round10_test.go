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

// REVIEW-10: a plain project skill folder whose manifest links to a file
// outside the profile is selected by any explicit spelling of the folder
// holding that file (direct, alias, relative) as well as of the file. The
// same shape with a manifest link to another private skill in the profile
// stays the caller own skill, and an unrelated source is not claimed.
func TestGAP0621R10PlainFolderManifestLinkFolderSource(t *testing.T) {
	for _, tc := range []struct {
		label string
		bound bool
	}{{"manifest outside profile", true}, {"manifest in private profile skill", false}} {
		t.Run(tc.label, func(t *testing.T) {
			home := t.TempDir()
			project := filepath.Join(home, "project")
			root := filepath.Join(project, ".claude", "skills")
			projectSkill := filepath.Join(root, "sample")
			if err := os.MkdirAll(projectSkill, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "sample")
			if !tc.bound {
				target = filepath.Join(home, "notes", "sample")
			}
			round6Skill(t, target, "sample")
			if err := os.Symlink(filepath.Join(target, "SKILL.md"), filepath.Join(projectSkill, "SKILL.md")); err != nil {
				t.Skipf("manifest link unavailable: %v", err)
			}
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(target, alias); err != nil {
				t.Skipf("alias unavailable: %v", err)
			}
			relative, err := filepath.Rel(project, target)
			if err != nil {
				t.Fatal(err)
			}
			for _, source := range []string{
				target, filepath.Join(target, "SKILL.md"),
				alias, filepath.Join(alias, "SKILL.md"),
				relative, filepath.Join(relative, "SKILL.md"),
			} {
				got := round6Selected(round9Facts(root, home, project, source))
				if tc.bound && (len(got) != 1 || got[0] != projectSkill) {
					t.Errorf("source %s did not bind the project folder: %v", source, got)
				}
				if !tc.bound && len(got) != 0 {
					t.Errorf("private source %s claimed as project skill: %v", source, got)
				}
			}
			unrelated := filepath.Join(t.TempDir(), "other")
			round6Skill(t, unrelated, "other")
			if got := round6Selected(round9Facts(root, home, project, unrelated)); len(got) != 0 {
				t.Errorf("unrelated source claimed: %v", got)
			}
		})
	}
}

// REVIEW-11: a linked project manifest and a distinct Skill beside the link
// target keep separate identities. The target folder selects its own
// SKILL.md; only the linked file and the project link select the project
// skill.
func TestGAP0621R10SiblingManifestSelection(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	if got := inspectProjectSkillRoot(home, root); got != ProjectSkillRootOutsideProfile {
		t.Fatalf("root classification: %q", got)
	}
	projectSkill := filepath.Join(root, "sample")
	if err := os.MkdirAll(projectSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, outside, "sample")
	linked := filepath.Join(outside, "linked.md")
	if err := os.WriteFile(linked, []byte("---\nname: sample\n---\nlinked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linked, filepath.Join(projectSkill, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	relative, err := filepath.Rel(project, outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		label, source string
		bound         bool
	}{
		{"own folder", outside, false},
		{"own manifest", filepath.Join(outside, "SKILL.md"), false},
		{"own alias folder", alias, false},
		{"own relative folder", relative, false},
		{"linked target", linked, true},
		{"project link", filepath.Join(projectSkill, "SKILL.md"), true},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, tc.source))
			if tc.bound && (len(got) != 1 || got[0] != projectSkill) {
				t.Errorf("source %s did not bind the project folder: %v", tc.source, got)
			}
			if !tc.bound && len(got) != 0 {
				t.Errorf("source %s claimed the project folder: %v", tc.source, got)
			}
		})
	}
}

// REVIEW-12: a Skill folder whose own SKILL.md is a hard link to the linked
// manifest is the same file under another spelling, so every spelling that
// names that folder or its manifest binds the project skill. A distinct
// sibling manifest stays allowed (TestGAP0621R10SiblingManifestSelection).
func TestGAP0621R10HardLinkedManifestSelection(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	projectSkill := filepath.Join(root, "sample")
	if err := os.MkdirAll(projectSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "sample")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(outside, "linked.md")
	if err := os.WriteFile(linked, []byte("---\nname: sample\n---\nlinked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linked, filepath.Join(outside, "SKILL.md")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	if err := os.Symlink(linked, filepath.Join(projectSkill, "SKILL.md")); err != nil {
		t.Skipf("manifest link unavailable: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(outside, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	relative, err := filepath.Rel(project, outside)
	if err != nil {
		t.Fatal(err)
	}
	for label, source := range map[string]string{
		"hard-linked folder":   outside,
		"hard-linked manifest": filepath.Join(outside, "SKILL.md"),
		"alias folder":         alias,
		"alias manifest":       filepath.Join(alias, "SKILL.md"),
		"relative folder":      relative,
		"relative manifest":    filepath.Join(relative, "SKILL.md"),
		"linked target":        linked,
		"project link":         filepath.Join(projectSkill, "SKILL.md"),
	} {
		t.Run(label, func(t *testing.T) {
			got := round6Selected(round9Facts(root, home, project, source))
			if len(got) != 1 || got[0] != projectSkill {
				t.Errorf("source %s did not bind the project folder: %v", source, got)
			}
		})
	}
}
