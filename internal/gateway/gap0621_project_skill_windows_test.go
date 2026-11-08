// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGAP0621ManagedWindowsProfileExcludedSkillHook(t *testing.T) {
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
	linked := filepath.Join(home, "linked")
	if err := os.MkdirAll(linked, 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(linked, ".claude"), target).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, out)
	}
	plain := filepath.Join(home, "plain")
	if err := os.MkdirAll(filepath.Join(plain, ".claude", "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plain, ".claude", "skills", "sample", "SKILL.md"), []byte("---\nname: sample\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(home, ".claude", "skills", "other")
	if err := os.MkdirAll(global, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(global, "SKILL.md"), []byte("---\nname: other\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := gatewaySkillPathCheck
	gatewaySkillPathCheck = func(path string) error {
		if insideHome(home, path) {
			return errors.New("profile root excluded")
		}
		return nil
	}
	t.Cleanup(func() { gatewaySkillPathCheck = restore })
	store, logger := newNativeSkillRuntimeTestStore(t)
	policy := config.DefaultAssetPolicy()
	policy.Mode = config.AssetPolicyModeAction
	cfg := &config.Config{AssetPolicy: policy, DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	api := &APIServer{scannerCfg: cfg, store: store, logger: logger, projectSkills: &projectSkillRoots{}, health: NewSidecarHealth()}
	api.projectSkills.start(true)
	call := func(project, name string) (config.AssetPolicyDecision, bool) {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "cwd": project,
			"tool_name": "Skill", "tool_input": map[string]string{"skill": name},
		})
		if err != nil {
			t.Fatal(err)
		}
		var facts map[string]string
		if encoded := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", body); encoded != "" {
			var ok bool
			facts, ok = hookpaths.Decode(encoded)
			if !ok {
				t.Fatal("hook facts were not decoded")
			}
		}
		ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
		return api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": name},
		})
	}
	if decision, matched := call(linked, "sample"); !matched || decision.Action != "block" || decision.Source != "project-skill-unverified" {
		t.Fatalf("linked project decision = %+v, matched=%v", decision, matched)
	}
	if count := api.health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail]; count != 1 {
		t.Fatalf("health unverified count = %v", count)
	}
	if api.projectSkills.registered(filepath.Join(linked, ".claude", "skills")) {
		t.Fatal("linked profile root entered the watcher")
	}
	if decision, matched := call(plain, "sample"); matched && decision.Action == "block" {
		t.Fatalf("ordinary profile project was blocked: %+v", decision)
	}
	if decision, matched := call(linked, "other"); matched && decision.Action == "block" {
		t.Fatalf("unrelated selected skill was blocked: %+v", decision)
	}
	cfg.AssetPolicy.Mode = config.AssetPolicyModeObserve
	if decision, matched := call(linked, "sample"); !matched || decision.Action != "block" {
		t.Fatalf("observe decision = %+v, matched=%v", decision, matched)
	}
	if err := os.Remove(filepath.Join(linked, ".claude")); err != nil {
		t.Fatalf("remove repaired junction: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(linked, ".claude", "skills", "sample"), 0o700); err != nil {
		t.Fatal(err)
	}
	if decision, matched := call(linked, "sample"); matched && decision.Action == "block" {
		t.Fatalf("repaired project decision = %+v", decision)
	}
	if count := api.health.Snapshot().Watcher.Details[projectSkillRootsUnverifiedDetail]; count != nil {
		t.Fatalf("repaired project health count = %v, want none (a cleared count is removed)", count)
	}
}
