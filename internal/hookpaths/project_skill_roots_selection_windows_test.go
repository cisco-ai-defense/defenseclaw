// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGAP0621WindowsExplicitSkillSelectionBinding(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	project := filepath.Join(home, "project")
	outside := t.TempDir()
	target := filepath.Join(outside, ".claude")
	selected := filepath.Join(project, ".claude", "skills", "sample")
	resolved := filepath.Join(target, "skills", "sample")
	ordinary := filepath.Join(home, ".claude", "skills", "sample")
	for _, dir := range []string{project, resolved, ordinary} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{resolved, ordinary} {
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(project, ".claude"), target).CombinedOutput(); err != nil {
		t.Fatalf("create project junction: %v: %s", err, out)
	}
	selectedKey := ProjectSkillSelectedPrefix + selected
	rootKey := ProjectSkillRootUnverifiedPrefix + filepath.Dir(selected)
	for _, tc := range []struct {
		name     string
		path     string
		want     bool
		inTopMap bool
		input    map[string]any
	}{
		{name: "resolved-folder", path: resolved, want: true},
		{name: "resolved-root", path: filepath.Dir(resolved), want: true},
		{name: "resolved-manifest", path: filepath.Join(resolved, "SKILL.md"), want: true},
		{name: "project-root", path: filepath.Dir(selected), want: true},
		{name: "ordinary-user-skill", path: ordinary, want: false},
		{name: "ordinary-top-level-source", path: ordinary, want: false, inTopMap: true},
		{name: "path-only-resolved-folder", want: true, input: map[string]any{"skill_path": resolved}},
		{name: "path-in-skill-resolved-folder", want: true, input: map[string]any{"skill": resolved}},
		{name: "nested-path-only-resolved-folder", want: true, input: map[string]any{"skill": map[string]any{"path": resolved}}},
		{name: "path-only-resolved-manifest", want: true, input: map[string]any{"skill_path": filepath.Join(resolved, "SKILL.md")}},
		{name: "path-only-ordinary-user-skill", want: false, input: map[string]any{"skill_path": ordinary}},
		{name: "path-in-skill-ordinary-user-skill", want: false, input: map[string]any{"skill": ordinary}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := map[string]any{
				"hook_event_name": "PreToolUse", "cwd": project,
				"tool_name": "Skill", "tool_input": map[string]string{"skill": "sample", "skill_path": tc.path},
			}
			if tc.input != nil {
				event["tool_input"] = tc.input
			}
			if tc.inTopMap {
				event["tool_input"] = map[string]string{"skill": "sample"}
				event["skill_path"] = tc.path
			}
			body, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			facts, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", body))
			if !ok || facts[rootKey] != ProjectSkillRootOutsideProfile {
				t.Fatalf("project root finding = %q, decoded=%v", facts[rootKey], ok)
			}
			if got := facts[selectedKey] == "sample"; got != tc.want {
				t.Fatalf("selected folder fact = %v, want %v", got, tc.want)
			}
		})
	}
}
