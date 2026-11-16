// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A private user skill stays a user selection when another project happens
// to link to the same folder. Folder and manifest spellings should agree.
func TestGAP0621R8DirectLinkToPrivateUserSkill(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, ordinary, "sample")
	child := filepath.Join(target, "zz-private-skill")
	if err := os.Symlink(ordinary, child); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "sample")
	if err := os.Symlink(ordinary, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	relative, err := filepath.Rel(project, ordinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{ordinary, filepath.Join(ordinary, "SKILL.md"), relative, filepath.Join(relative, "SKILL.md"), alias, filepath.Join(alias, "SKILL.md")} {
		args, _ := json.Marshal(map[string]any{"skill": "sample", "skill_path": source})
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		for key := range facts {
			if strings.HasPrefix(key, ProjectSkillSelectedPrefix) {
				t.Errorf("ordinary private skill %s claimed as %s", source, key)
			}
		}
	}
}

// A source spelled in the user skill root may resolve to an outside skill
// that the refused project root also reaches. The selected fact must survive.
func TestGAP0621R8UserRootAliasToProtectedSkill(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	protected := filepath.Join(target, "sample")
	round6Skill(t, protected, "sample")
	alias := filepath.Join(home, ".claude", "skills", "outside-alias")
	if err := os.MkdirAll(filepath.Dir(alias), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(protected, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	for _, source := range []string{alias, filepath.Join(alias, "SKILL.md")} {
		args, _ := json.Marshal(map[string]any{"skill": "sample", "skill_path": source})
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		if facts[ProjectSkillSelectedPrefix+filepath.Join(root, "sample")] != "sample" {
			t.Errorf("protected alias %s lost selected fact", source)
		}
	}
}

// Twin of TestGAP0621R8DirectLinkToPrivateUserSkill: a project child linked
// straight to a skill folder outside the profile is still claimed, for the
// folder, its manifest and an alternate link, whichever way it is spelled.
func TestGAP0621R8DirectLinkToOutsideSkillStillBinds(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	outside := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, outside, "sample")
	if err := os.Symlink(outside, filepath.Join(target, "zz-outside-skill")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "sample")
	if err := os.Symlink(outside, alias); err != nil {
		t.Skipf("alias unavailable: %v", err)
	}
	relative, err := filepath.Rel(project, outside)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{outside, filepath.Join(outside, "SKILL.md"), relative, filepath.Join(relative, "SKILL.md"), alias, filepath.Join(alias, "SKILL.md")} {
		args, _ := json.Marshal(map[string]any{"skill": "sample", "skill_path": source})
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		if facts[ProjectSkillSelectedPrefix+filepath.Join(root, "zz-outside-skill")] != "sample" {
			t.Errorf("outside skill %s lost its selected fact: %v", source, round6Selected(facts))
		}
	}
}
