// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func round9Facts(root, home, project, source string) map[string]string {
	args, _ := json.Marshal(map[string]any{"skill": "sample", "skill_path": source})
	facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootSharedWritable}
	addProjectSkillSelectedFacts(facts, nil, args, home, project)
	return facts
}

// REVIEW-8: the project skills root itself is a link to the caller private
// skill (or to the private user skills folder). A call that names that skill
// by its own folder, manifest, relative path or another link is the user own
// selection, however the project root is judged.
func TestGAP0621R9PrivateSkillAsLinkedRoot(t *testing.T) {
	for _, tc := range []struct {
		label  string
		toRoot bool // link to ~/.claude/skills rather than the skill folder
	}{{"skill folder", false}, {"user skills folder", true}} {
		t.Run(tc.label, func(t *testing.T) {
			home := t.TempDir()
			userRoot := filepath.Join(home, ".claude", "skills")
			private := filepath.Join(userRoot, "sample")
			round6Skill(t, private, "sample")
			project := filepath.Join(home, "project")
			root := filepath.Join(project, ".claude", "skills")
			if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
				t.Fatal(err)
			}
			target := private
			if tc.toRoot {
				target = userRoot
			}
			if err := os.Symlink(target, root); err != nil {
				t.Skipf("root link unavailable: %v", err)
			}
			alias := filepath.Join(t.TempDir(), "sample")
			if err := os.Symlink(private, alias); err != nil {
				t.Skipf("alias unavailable: %v", err)
			}
			relative := mustRelG621R9(t, project, private)
			for _, source := range []string{private, filepath.Join(private, "SKILL.md"), relative, filepath.Join(relative, "SKILL.md"), alias, filepath.Join(alias, "SKILL.md")} {
				if got := round6Selected(round9Facts(root, home, project, source)); len(got) != 0 {
					t.Errorf("private source %s claimed as project skill: %v", source, got)
				}
			}
		})
	}
}

// Twins: a root link to a skill folder outside the profile still binds the
// folder and its manifest, and a call that names the project link itself
// stays claimed even when the link reaches a private skill.
func TestGAP0621R9LinkedRootStillBinds(t *testing.T) {
	home := t.TempDir()
	private := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, private, "sample")
	outside := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, outside, "sample")
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	for _, source := range []string{outside, filepath.Join(outside, "SKILL.md"), root, filepath.Join(root, "SKILL.md")} {
		if got := round6Selected(round9Facts(root, home, project, source)); len(got) == 0 {
			t.Errorf("outside skill source %s lost its selected fact", source)
		}
	}
	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	for _, source := range []string{root, filepath.Join(root, "SKILL.md")} {
		if got := round6Selected(round9Facts(root, home, project, source)); len(got) == 0 {
			t.Errorf("call naming the project link %s lost its selected fact", source)
		}
	}
}

func mustRelG621R9(t *testing.T, base, target string) string {
	t.Helper()
	rel, err := filepath.Rel(base, target)
	if err != nil {
		t.Fatal(err)
	}
	return rel
}
