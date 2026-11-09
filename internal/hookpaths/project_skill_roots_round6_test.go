// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// round6Skill writes a skill folder whose manifest declares name.
func round6Skill(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// round6Root links home/project/.claude/skills to a folder outside home
// and returns the project, the root link and its target.
func round6Root(t *testing.T, home string) (project, root, target string) {
	t.Helper()
	project = filepath.Join(home, "project")
	root = filepath.Join(project, ".claude", "skills")
	target = t.TempDir()
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("root link unavailable: %v", err)
	}
	return project, root, target
}

func round6Selected(facts map[string]string) []string {
	var dirs []string
	for key := range facts {
		if len(key) > len(ProjectSkillSelectedPrefix) && key[:len(ProjectSkillSelectedPrefix)] == ProjectSkillSelectedPrefix {
			dirs = append(dirs, key[len(ProjectSkillSelectedPrefix):])
		}
	}
	slices.Sort(dirs)
	return dirs
}

// REVIEW-5 item 1: a child link of a refused root that sorts after more
// than 4,096 other entries, plain folders or other links, still binds an
// explicit source naming its target or manifest. An ordinary same-name
// user skill stays unselected.
func TestGAP0621LinkedChildAfterManyEntriesBinds(t *testing.T) {
	for _, filler := range []string{"folders", "skills", "links"} {
		t.Run(filler, func(t *testing.T) {
			// Each filler fills its own 4,097 entries: on Windows creating
			// them took 65 s in a row, so the three run side by side (GAP-0963).
			t.Parallel()
			home := t.TempDir()
			project, root, target := round6Root(t, home)
			protected := filepath.Join(t.TempDir(), "protected")
			ordinary := filepath.Join(home, ".claude", "skills", "protected")
			round6Skill(t, protected, "protected")
			round6Skill(t, ordinary, "protected")
			elsewhere := t.TempDir()
			for i := 0; i <= 4096; i++ {
				entry := filepath.Join(target, fmt.Sprintf("a%04d", i))
				var err error
				switch filler {
				case "folders":
					err = os.Mkdir(entry, 0o700)
				case "skills":
					round6Skill(t, entry, fmt.Sprintf("a%04d", i))
				case "links":
					err = os.Symlink(elsewhere, entry)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			linked := filepath.Join(root, "zz-linked-skill")
			if err := os.Symlink(protected, filepath.Join(target, "zz-linked-skill")); err != nil {
				t.Skipf("child link unavailable: %v", err)
			}
			for _, tc := range []struct {
				label, source string
				want          []string
			}{
				{"protected target", protected, []string{linked}},
				{"protected manifest", filepath.Join(protected, "SKILL.md"), []string{linked}},
				{"ordinary twin", ordinary, nil},
				{"ordinary twin manifest", filepath.Join(ordinary, "SKILL.md"), nil},
			} {
				args, _ := json.Marshal(map[string]any{"skill_path": tc.source})
				facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
				addProjectSkillSelectedFacts(facts, nil, args, home, project)
				if got := round6Selected(facts); !slices.Equal(got, tc.want) {
					t.Errorf("%s: selected %v, want %v", tc.label, got, tc.want)
				}
			}
		})
	}
}

// REVIEW-5 item 2: a name-only call does not claim a project copy that does
// not exist, however many other skill folders the refused root holds, and
// still binds a late folder that declares the name or the named folder.
func TestGAP0621LargeRootNameOnlySelectionIsExact(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	round6Skill(t, filepath.Join(home, ".claude", "skills", "sample"), "sample")
	for i := 0; i <= 4096; i++ {
		if i%2 == 0 {
			round6Skill(t, filepath.Join(target, fmt.Sprintf("a%04d", i)), fmt.Sprintf("a%04d", i))
		} else if err := os.Mkdir(filepath.Join(target, fmt.Sprintf("a%04d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	selected := func() []string {
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, nil, json.RawMessage(`{"skill":"sample"}`), home, project)
		return round6Selected(facts)
	}
	if got := selected(); got != nil {
		t.Fatalf("ordinary name-only skill selected project folders %v", got)
	}
	round6Skill(t, filepath.Join(target, "zz-declares"), "sample")
	if got, want := selected(), []string{filepath.Join(root, "zz-declares")}; !slices.Equal(got, want) {
		t.Fatalf("late declared-name folder: selected %v, want %v", got, want)
	}
	round6Skill(t, filepath.Join(target, "sample"), "sample")
	if got, want := selected(), []string{filepath.Join(root, "sample")}; !slices.Equal(got, want) {
		t.Fatalf("named folder: selected %v, want %v", got, want)
	}
}

// A root the caller cannot list: an absent named folder is not claimed, and
// a named folder that cannot be ruled out still is.
func TestGAP0621UnlistableRootNameOnlySelection(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	run := func() []string {
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootUnreadable}
		addProjectSkillSelectedFacts(facts, nil, json.RawMessage(`{"skill":"sample"}`), home, project)
		return round6Selected(facts)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o700) })
	if err := os.Chmod(target, 0o300); err != nil {
		t.Skipf("permission simulation unavailable: %v", err)
	}
	if _, err := os.ReadDir(root); err == nil {
		t.Skip("listing is not restricted for this user")
	}
	if got := run(); got != nil {
		t.Errorf("listing denied, folder absent: selected %v", got)
	}
	if err := os.Chmod(target, 0); err != nil {
		t.Fatal(err)
	}
	if got, want := run(), []string{filepath.Join(root, "sample")}; !slices.Equal(got, want) {
		t.Errorf("traversal denied: selected %v, want %v", got, want)
	}
}

// REVIEW-5 item 3: a top-level name with an explicit tool-input path is
// bound by that path. An ordinary path selects nothing under the refused
// root; a path into the root, its target or another child is bound.
func TestGAP0621TopLevelNameUsesEveryExplicitSource(t *testing.T) {
	home := t.TempDir()
	project, root, target := round6Root(t, home)
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	round6Skill(t, ordinary, "sample")
	round6Skill(t, filepath.Join(target, "sample"), "sample")
	round6Skill(t, filepath.Join(target, "other"), "other")
	top := json.RawMessage(`{"skill":"sample"}`)
	for _, tc := range []struct {
		label   string
		payload json.RawMessage
		input   map[string]any
		want    []string
	}{
		{"ordinary input path", top, map[string]any{"skill": "sample", "skill_path": ordinary}, nil},
		{"ordinary input manifest", top, map[string]any{"skill": "sample", "skill_path": filepath.Join(ordinary, "SKILL.md")}, nil},
		{"ordinary nested input path", top, map[string]any{"skill": map[string]any{"name": "sample", "path": ordinary}}, nil},
		{"project input path", top, map[string]any{"skill": "sample", "skill_path": filepath.Join(root, "sample")}, []string{filepath.Join(root, "sample")}},
		{"resolved input path", top, map[string]any{"skill_path": filepath.Join(target, "sample", "SKILL.md")}, []string{filepath.Join(root, "sample")}},
		{"other child input path", top, map[string]any{"skill_path": filepath.Join(root, "other")}, []string{filepath.Join(root, "other")}},
		{"ordinary top path, project input path", json.RawMessage(fmt.Sprintf(`{"skill_path":%q}`, ordinary)),
			map[string]any{"skill_path": filepath.Join(root, "sample")}, []string{filepath.Join(root, "sample")}},
		{"name only both", top, map[string]any{"skill": "sample"}, []string{filepath.Join(root, "sample")}},
	} {
		args, _ := json.Marshal(tc.input)
		facts := map[string]string{ProjectSkillRootUnverifiedPrefix + root: ProjectSkillRootOutsideProfile}
		addProjectSkillSelectedFacts(facts, tc.payload, args, home, project)
		if got := round6Selected(facts); !slices.Equal(got, tc.want) {
			t.Errorf("%s: selected %v, want %v", tc.label, got, tc.want)
		}
		for _, dir := range tc.want {
			if facts[ProjectSkillSelectedPrefix+dir] != "sample" {
				t.Errorf("%s: fact for %s names %q, want the gateway name sample", tc.label, dir, facts[ProjectSkillSelectedPrefix+dir])
			}
		}
	}
}
