// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0621SelectedSkillEvidenceIsNarrow(t *testing.T) {
	root := t.TempDir()
	for folder, declared := range map[string]string{"direct": "direct", "folder": "declared"} {
		dir := filepath.Join(root, folder)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+declared+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{"direct": "direct", "declared": "folder", "unrelated": ""} {
		folders := projectSkillSelectedFolders(root, name)
		if want == "" && len(folders) != 0 || want != "" && (len(folders) != 1 || folders[0] != filepath.Join(root, want)) {
			t.Fatalf("selected %q = %v, want %q", name, folders, want)
		}
	}
	for _, input := range []map[string]any{
		{"skill": "direct"}, {"skill_name": "direct"},
		{"skill_info": map[string]string{"name": "direct"}},
	} {
		raw, _ := json.Marshal(input)
		if got, _ := projectSkillCallSelection(nil, raw); got != "direct" {
			t.Fatalf("input %s selected %q", raw, got)
		}
	}
	if ProjectSkillHookCall("claudecode", []byte(`{"tool_name":"Bash"}`)) ||
		!ProjectSkillHookCall("claudecode", []byte(`{"tool_name":"Skill"}`)) ||
		ProjectSkillHookCall("codex", []byte(`{"tool_name":"Skill"}`)) {
		t.Fatal("Skill call event selection changed")
	}
}

func TestGAP0621CodexPromptSelectionUsesFirstToken(t *testing.T) {
	for prompt, want := range map[string]string{
		"$sample Continue.": "sample",
		"Use $sample":       "",
		"$sample, Continue": "",
		"$../sample":        "",
	} {
		if got := CodexSelectedSkillName(prompt); got != want {
			t.Errorf("prompt %q selected %q, want %q", prompt, got, want)
		}
	}
}

func TestGAP0621ProjectSkillRootClassification(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	outside := filepath.Join(base, "shared", ".claude", "skills")
	ordinary := filepath.Join(home, "plain", ".claude", "skills")
	for _, dir := range []string{outside, ordinary} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	linked := filepath.Join(home, "linked", ".claude")
	if err := os.MkdirAll(filepath.Dir(linked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(outside), linked); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if got := inspectProjectSkillRoot(home, filepath.Join(linked, "skills")); got != ProjectSkillRootOutsideProfile {
		t.Fatalf("linked root = %q, want outside profile", got)
	}
	if got := inspectProjectSkillRoot(home, ordinary); got != "" {
		t.Fatalf("ordinary root = %q, want no finding", got)
	}
	if got := inspectProjectSkillRoot(home, filepath.Join(home, "absent", ".claude", "skills")); got != "" {
		t.Fatalf("absent root = %q, want no finding", got)
	}
}
