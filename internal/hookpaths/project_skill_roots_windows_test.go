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

func TestGAP0621WindowsSkillHookReportsLinkedAndSharedProjectRoots(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	outside := t.TempDir()
	target := filepath.Join(outside, ".claude")
	if err := os.MkdirAll(filepath.Join(target, "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "skills", "sample", "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(project string) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "cwd": project,
			"tool_name": "Skill", "tool_input": map[string]string{"skill": "sample"},
		})
		if err != nil {
			t.Fatal(err)
		}
		encoded := ResolveConnector("claudecode", "", "PreToolUse", body)
		if encoded == "" {
			return nil
		}
		facts, ok := Decode(encoded)
		if !ok {
			t.Fatal("Skill hook facts were not decoded")
		}
		return facts
	}
	makeProject := func(name string) string {
		t.Helper()
		project := filepath.Join(home, name)
		if err := os.MkdirAll(project, 0o700); err != nil {
			t.Fatal(err)
		}
		return project
	}
	junction := makeProject("junction")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(junction, ".claude"), target).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, out)
	}
	key := ProjectSkillRootUnverifiedPrefix + filepath.Join(junction, ".claude", "skills")
	if got := check(junction)[key]; got != ProjectSkillRootOutsideProfile {
		t.Fatalf("junction finding = %q", got)
	}
	start, err := json.Marshal(map[string]string{"hook_event_name": "SessionStart", "cwd": junction})
	if err != nil {
		t.Fatal(err)
	}
	startFacts, ok := Decode(ResolveConnector("claudecode", "", "SessionStart", start))
	if !ok || startFacts[key] != ProjectSkillRootOutsideProfile {
		t.Fatalf("session start finding = %q, decoded=%v", startFacts[key], ok)
	}
	if got := check(junction)[ProjectSkillSelectedPrefix+filepath.Join(junction, ".claude", "skills", "sample")]; got != "sample" {
		t.Fatalf("selected skill finding = %q", got)
	}

	t.Run("symlink", func(t *testing.T) {
		project := makeProject("symlink")
		if err := os.Symlink(target, filepath.Join(project, ".claude")); err != nil {
			t.Skipf("directory symlink unavailable: %v", err)
		}
		key := ProjectSkillRootUnverifiedPrefix + filepath.Join(project, ".claude", "skills")
		if got := check(project)[key]; got != ProjectSkillRootOutsideProfile {
			t.Fatalf("symlink finding = %q", got)
		}
	})

	shared := makeProject("shared")
	sharedRoot := filepath.Join(shared, ".claude", "skills")
	if err := os.MkdirAll(sharedRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("icacls.exe", sharedRoot, "/grant", "*S-1-1-0:(OI)(CI)M").CombinedOutput(); err != nil {
		t.Fatalf("grant test folder write: %v: %s", err, out)
	}
	key = ProjectSkillRootUnverifiedPrefix + sharedRoot
	if got := check(shared)[key]; got != ProjectSkillRootSharedWritable {
		t.Fatalf("shared folder finding = %q", got)
	}

	plain := makeProject("plain")
	plainRoot := filepath.Join(plain, ".claude", "skills")
	if err := os.MkdirAll(plainRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := check(plain)[ProjectSkillRootUnverifiedPrefix+plainRoot]; got != "" {
		t.Fatalf("ordinary project finding = %q", got)
	}
	if got := check(plain)[ProjectSkillRootVerifiedPrefix+plainRoot]; got != "1" {
		t.Fatalf("ordinary project inspection = %q", got)
	}

	codex := makeProject("codex")
	codexTarget := filepath.Join(outside, ".agents")
	if err := os.MkdirAll(filepath.Join(codexTarget, "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexTarget, "skills", "sample", "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(codex, ".agents"), codexTarget).CombinedOutput(); err != nil {
		t.Fatalf("create Codex junction: %v: %s", err, out)
	}
	prompt, err := json.Marshal(map[string]string{"hook_event_name": "UserPromptSubmit", "cwd": codex, "prompt": "$sample Continue."})
	if err != nil {
		t.Fatal(err)
	}
	if !ProjectSkillHookCall("codex", prompt) {
		t.Fatal("Codex skill selection did not request caller inspection")
	}
	codexFacts, ok := Decode(ResolveConnector("codex", "", "UserPromptSubmit", prompt))
	if !ok || codexFacts[ProjectSkillRootUnverifiedPrefix+filepath.Join(codex, ".agents", "skills")] != ProjectSkillRootOutsideProfile ||
		codexFacts[ProjectSkillSelectedPrefix+filepath.Join(codex, ".agents", "skills", "sample")] != "sample" {
		t.Fatalf("Codex selected project skill facts = %v, decoded=%v", codexFacts, ok)
	}
}
