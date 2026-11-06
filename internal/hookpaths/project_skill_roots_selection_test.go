// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// projectSkillLinkedRoot builds a project skill root linked to a folder
// outside home, an alias link to the selected skill and an ordinary user
// skill of the same name.
func projectSkillLinkedRoot(t *testing.T) (home, project, root, target, alias, other string) {
	t.Helper()
	home = t.TempDir()
	project = filepath.Join(home, "project")
	root = filepath.Join(project, ".claude", "skills")
	target = t.TempDir()
	realSelected := filepath.Join(target, "sample")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realSelected, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realSelected, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	alias = filepath.Join(project, "alternate-skill")
	if err := os.Symlink(realSelected, alias); err != nil {
		t.Skipf("skill alias unavailable: %v", err)
	}
	other = filepath.Join(home, ".claude", "skills", "sample")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, project, root, target, alias, other
}

func TestGAP0621CallerBindsSelectedProjectSkillToExplicitPath(t *testing.T) {
	home, project, root, target, alias, other := projectSkillLinkedRoot(t)
	selected := filepath.Join(root, "sample")
	realSelected := filepath.Join(target, "sample")
	manifest := filepath.Join(realSelected, "SKILL.md")
	for _, tc := range []struct {
		path string
		want bool
	}{
		{realSelected, true},
		{target, true},
		{manifest, true},
		{alias, true},
		{root, true},
		{filepath.Join(".claude", "skills", "sample", "SKILL.md"), true},
		{other, false},
		{filepath.Join(other, "SKILL.md"), false},
	} {
		got := slices.Contains(projectSkillSourceFolders(root, "sample", tc.path, home, project), selected)
		if got != tc.want {
			t.Errorf("path %q selected=%v, want %v", tc.path, got, tc.want)
		}
	}
}

// Every Skill selection form the gateway accepts binds the folder it names
// under the refused root, whatever name the path spells; an ordinary skill
// of the same name elsewhere stays unselected.
func TestGAP0621CallerSelectionFormsBindRefusedRoot(t *testing.T) {
	home, project, root, target, alias, other := projectSkillLinkedRoot(t)
	selected := filepath.Join(root, "sample")
	realSelected := filepath.Join(target, "sample")
	forms := map[string]func(path string) map[string]any{
		"skill_path":    func(p string) map[string]any { return map[string]any{"skill_path": p} },
		"sourcePath":    func(p string) map[string]any { return map[string]any{"sourcePath": p} },
		"path-in-skill": func(p string) map[string]any { return map[string]any{"skill": p} },
		"nested-path":   func(p string) map[string]any { return map[string]any{"skill": map[string]any{"path": p}} },
		"name-and-path": func(p string) map[string]any { return map[string]any{"skill": "sample", "skill_path": p} },
		"nested-name-and-path": func(p string) map[string]any {
			return map[string]any{"skill": map[string]any{"name": "sample", "path": p}}
		},
		"skill_name-and-path": func(p string) map[string]any { return map[string]any{"skill_name": "sample", "skill_path": p} },
	}
	for form, build := range forms {
		for _, tc := range []struct {
			label string
			path  string
			want  bool
		}{
			{"resolved-folder", realSelected, true},
			{"resolved-manifest", filepath.Join(realSelected, "SKILL.md"), true},
			{"alias", alias, true},
			{"project-folder", selected, true},
			{"ordinary-user-skill", other, false},
			{"ordinary-user-manifest", filepath.Join(other, "SKILL.md"), false},
		} {
			args, err := json.Marshal(build(tc.path))
			if err != nil {
				t.Fatal(err)
			}
			facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
			addProjectSkillSelectedFacts(facts, nil, args, home, project)
			_, got := facts[ProjectSkillSelectedPrefix+selected]
			if got != tc.want {
				t.Errorf("%s %s: selected fact=%v, want %v (facts %v)", form, tc.label, got, tc.want, facts)
			}
		}
	}
	// A name-only call keeps the named folder.
	facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
	addProjectSkillSelectedFacts(facts, nil, json.RawMessage(`{"skill":"sample"}`), home, project)
	if facts[ProjectSkillSelectedPrefix+selected] != "sample" {
		t.Errorf("name-only selection facts = %v", facts)
	}
	// A top-level event source wins over the tool input, as at the gateway.
	facts = map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
	payload, _ := json.Marshal(map[string]any{"skill_path": other})
	addProjectSkillSelectedFacts(facts, payload, json.RawMessage(`{"skill":"sample"}`), home, project)
	if _, ok := facts[ProjectSkillSelectedPrefix+selected]; ok {
		t.Errorf("top-level ordinary source selected the refused folder: %v", facts)
	}
}

func TestGAP0621SkillCallPathForms(t *testing.T) {
	for _, tc := range []struct {
		input string
		name  string
		want  string
	}{
		{`{"skill":"sample","skill_path":"/tmp/sample"}`, "sample", "/tmp/sample"},
		{`{"skill":"sample","sourcePath":"/tmp/sample/SKILL.md"}`, "sample", "/tmp/sample/SKILL.md"},
		{`{"skill":{"name":"sample","path":"/tmp/sample"}}`, "sample", "/tmp/sample"},
		{`{"skill":"/tmp/sample/SKILL.md"}`, "sample", "/tmp/sample/SKILL.md"},
		{`{"skill":"sample"}`, "sample", ""},
	} {
		name, sources := projectSkillCallSelection(nil, json.RawMessage(tc.input))
		got := ""
		if len(sources) == 1 {
			got = sources[0]
		}
		if name != tc.name || got != tc.want || len(sources) > 1 {
			t.Errorf("selection for %s = %q, %q, want %q, %q", tc.input, name, got, tc.name, tc.want)
		}
	}
}

// REVIEW-4: the caller reads the path-only forms the gateway accepts.
func TestReviewG621R4CallerRecognizesGatewayPathOnlySkill(t *testing.T) {
	for _, raw := range []string{
		`{"skill_path":"/tmp/root/sample"}`,
		`{"skill":"/tmp/root/sample"}`,
		`{"skill":{"path":"/tmp/root/sample"}}`,
	} {
		if got, _ := projectSkillCallSelection(nil, json.RawMessage(raw)); got != "sample" {
			t.Errorf("caller selected name for %s = %q, want sample", raw, got)
		}
	}
}
