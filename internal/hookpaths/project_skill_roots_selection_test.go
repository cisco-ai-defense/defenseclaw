// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0621CallerBindsSelectedProjectSkillToExplicitPath(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	root := filepath.Join(project, ".claude", "skills")
	target := t.TempDir()
	selected := filepath.Join(root, "sample")
	realSelected := filepath.Join(target, "sample")
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realSelected, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(realSelected, "SKILL.md")
	if err := os.WriteFile(manifest, []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, root); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	alias := filepath.Join(project, "alternate-skill")
	if err := os.Symlink(realSelected, alias); err != nil {
		t.Skipf("skill alias unavailable: %v", err)
	}
	other := filepath.Join(home, ".claude", "skills", "sample")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
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
		if got := projectSkillSelectionMatchesPath(root, selected, tc.path, project); got != tc.want {
			t.Errorf("path %q selected=%v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestGAP0621SkillCallPathForms(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{`{"skill":"sample","skill_path":"/tmp/sample"}`, "/tmp/sample"},
		{`{"skill":"sample","sourcePath":"/tmp/sample/SKILL.md"}`, "/tmp/sample/SKILL.md"},
		{`{"skill":{"name":"sample","path":"/tmp/sample"}}`, "/tmp/sample"},
		{`{"skill":"/tmp/sample/SKILL.md"}`, "/tmp/sample/SKILL.md"},
		{`{"skill":"sample"}`, ""},
	} {
		if got := projectSkillCallPath(json.RawMessage(tc.input)); got != tc.want {
			t.Errorf("path for %s = %q, want %q", tc.input, got, tc.want)
		}
	}
}
