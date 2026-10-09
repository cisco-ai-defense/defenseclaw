// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1063: a session in a project registers the project's skill folder for
// the install watcher, and a skill there is refused until install admission
// has recorded it, then judged as usual.
func TestProjectSkillIsHeldUntilItsFirstAdmission(t *testing.T) {
	store, logger := newNativeSkillRuntimeTestStore(t)
	home := t.TempDir()
	project := filepath.Join(home, "proj", "ucc-app")
	skills := filepath.Join(project, ".claude", "skills")
	skill := filepath.Join(skills, "ucc-flagged-skill2")
	for _, dir := range []string{skill, filepath.Join(project, ".git")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte("---\nname: ucc-flagged-skill2\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	roots := &projectSkillRoots{}
	roots.start(true)
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg, projectSkills: roots}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1004, Home: home})
	call := func() (config.AssetPolicyDecision, bool) {
		return api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "ucc-flagged-skill2"},
		})
	}
	if decision, matched := call(); !matched || decision.Action != "block" {
		t.Fatalf("unadmitted project skill = %+v, matched=%v; want refused", decision, matched)
	}
	if !roots.registered(skills) {
		t.Fatalf("project skill folder %s was not registered for the watcher", skills)
	}
	if err := store.SetTargetSnapshot("skill", skill, "h", "{}", "{}", "[]", "scan-1", "fp"); err != nil {
		t.Fatal(err)
	}
	if decision, matched := call(); matched {
		t.Fatalf("admitted project skill = %+v, want it judged as usual", decision)
	}
}
