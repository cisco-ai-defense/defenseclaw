// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// REVIEW-6 item 1: a name the gateway parser accepts but that is not a
// folder name (a qualified plugin name) still carries the explicit source
// that names the refused root's folder, and the fact survives Decode. The
// same name with an ordinary source, or with no source, selects nothing.
func TestGAP0621QualifiedNameExplicitSourceBinds(t *testing.T) {
	home, project, root, target, _, other := projectSkillLinkedRoot(t)
	protected := filepath.Join(target, "sample")
	selected := ProjectSkillSelectedPrefix + filepath.Join(root, "sample")
	for _, tc := range []struct {
		label string
		args  map[string]any
		want  bool
	}{
		{"skill_name and skill_path", map[string]any{"skill_name": "plugin:sample", "skill_path": protected}, true},
		{"skill_name and manifest", map[string]any{"skill_name": "plugin:sample", "skill_path": filepath.Join(protected, "SKILL.md")}, true},
		{"nested name and path", map[string]any{"skill": map[string]any{"name": "plugin:sample", "path": protected}}, true},
		{"ordinary source", map[string]any{"skill_name": "plugin:sample", "skill_path": other}, false},
		{"name only", map[string]any{"skill_name": "plugin:sample"}, false},
	} {
		args, err := json.Marshal(tc.args)
		if err != nil {
			t.Fatal(err)
		}
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		if !tc.want {
			if dirs := round6Selected(facts); len(dirs) != 0 {
				t.Errorf("%s: selected %v, want none", tc.label, dirs)
			}
			continue
		}
		if facts[selected] != "plugin:sample" {
			t.Errorf("%s: selected=%q, want plugin:sample (all: %v)", tc.label, facts[selected], round6Selected(facts))
			continue
		}
		encoded, err := json.Marshal(facts)
		if err != nil {
			t.Fatal(err)
		}
		decoded, ok := Decode(base64.RawURLEncoding.EncodeToString(encoded))
		if !ok || decoded[selected] != "plugin:sample" {
			t.Errorf("%s: Decode dropped the selected fact: ok=%v", tc.label, ok)
		}
	}
}

// A selected-folder fact value is a name the shared parser returns.
func TestGAP0621SelectedFactNameBound(t *testing.T) {
	for name, want := range map[string]bool{
		"sample": true, "plugin:sample": true, "": false, "a/b": false,
		"@sample": false, " sample": false, string(make([]byte, MaxWriteTargetPathBytes+1)): false,
	} {
		if got := projectSkillFactName(name); got != want {
			t.Errorf("projectSkillFactName(%q) = %v, want %v", name, got, want)
		}
	}
}

// REVIEW-6 item 2: a link under a refused root that is not a skill, sorted
// after 4,096 plain folders and reaching an ancestor of the caller's own
// skill, does not claim that skill. A link reaching an outside folder that
// holds the selected skill below it, and a link to the skill itself, still
// bind the explicit source.
func TestGAP0621NonskillChildLinkLeavesOrdinarySource(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, ordinary, "sample")
	for i := 0; i < 4096; i++ {
		if err := os.Mkdir(filepath.Join(target, fmt.Sprintf("a%04d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	outside := t.TempDir()
	nested := filepath.Join(outside, "pack", "sample")
	round6Skill(t, nested, "sample")
	linked := filepath.Join(t.TempDir(), "sample")
	round6Skill(t, linked, "sample")
	for name, dest := range map[string]string{
		"zz-home": home, "zz-skills": filepath.Dir(ordinary), "zz-outside": outside, "zz-skill": linked,
	} {
		if err := os.Symlink(dest, filepath.Join(target, name)); err != nil {
			t.Skipf("child link unavailable: %v", err)
		}
	}
	for _, tc := range []struct {
		label, source, want string
	}{
		{"ordinary folder", ordinary, ""},
		{"ordinary manifest", filepath.Join(ordinary, "SKILL.md"), ""},
		{"nested outside folder", nested, filepath.Join(root, "zz-outside")},
		{"nested outside manifest", filepath.Join(nested, "SKILL.md"), filepath.Join(root, "zz-outside")},
		{"linked skill", linked, filepath.Join(root, "zz-skill")},
		{"linked manifest", filepath.Join(linked, "SKILL.md"), filepath.Join(root, "zz-skill")},
	} {
		args, err := json.Marshal(map[string]any{"skill": "sample", "skill_path": tc.source})
		if err != nil {
			t.Fatal(err)
		}
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		dirs := round6Selected(facts)
		if tc.want == "" && len(dirs) != 0 {
			t.Errorf("%s: ordinary source claimed project folders %v", tc.label, dirs)
		}
		if tc.want != "" && (len(dirs) != 1 || dirs[0] != tc.want || facts[ProjectSkillSelectedPrefix+tc.want] != "sample") {
			t.Errorf("%s: selected %v, want %s", tc.label, dirs, tc.want)
		}
	}
}

// The resolved-root branch keeps the same ownership: a refused root whose
// target is an ancestor of the caller's profile does not claim the caller's
// own skill through the profile folder, while a skill in an outside folder
// under that target still binds.
func TestGAP0621ResolvedRootAncestorLeavesOrdinarySource(t *testing.T) {
	home := t.TempDir()
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, ordinary, "sample")
	outside := t.TempDir()
	parent := filepath.Dir(home)
	if filepath.Dir(outside) != parent {
		t.Skip("temporary folders do not share a parent")
	}
	nested := filepath.Join(outside, "sample")
	round6Skill(t, nested, "sample")
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(parent, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	for _, tc := range []struct {
		label, source, want string
	}{
		{"ordinary folder", ordinary, ""},
		{"ordinary manifest", filepath.Join(ordinary, "SKILL.md"), ""},
		{"outside skill", nested, filepath.Join(root, filepath.Base(outside))},
		{"outside manifest", filepath.Join(nested, "SKILL.md"), filepath.Join(root, filepath.Base(outside))},
	} {
		args, err := json.Marshal(map[string]any{"skill": "sample", "skill_path": tc.source})
		if err != nil {
			t.Fatal(err)
		}
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, args, home, project)
		dirs := round6Selected(facts)
		if tc.want == "" && len(dirs) != 0 {
			t.Errorf("%s: ordinary source claimed project folders %v", tc.label, dirs)
		}
		if tc.want != "" && (len(dirs) != 1 || dirs[0] != tc.want) {
			t.Errorf("%s: selected %v, want %s", tc.label, dirs, tc.want)
		}
	}
}
