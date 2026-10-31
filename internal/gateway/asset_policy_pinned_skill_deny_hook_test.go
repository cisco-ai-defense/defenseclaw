// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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

// A skill.denied rule pinned with source_path_contains to the user-level copy
// refuses a Claude Code Skill call that loads that copy, although the call
// itself carries no path: the gateway judges each folder that provides the
// name at its own path (docs: policies/admission, "Path pins"). A pin to a
// copy the caller does not have matches nothing.
func TestPinnedSkillDenyRefusesClaudeCodeSkillCallOnThePinnedCopy(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	userCopy := filepath.Join(home, ".claude", "skills", "shared-tool")
	projectCopy := filepath.Join(project, ".claude", "skills", "shared-tool")
	for _, dir := range []string{userCopy, projectCopy} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: shared-tool\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{
		Name: "shared-tool", SourcePathContains: []string{userCopy},
	}}
	store, logger := newNativeSkillRuntimeTestStore(t)
	api := &APIServer{store: store, logger: logger, scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: home})
	call := func() (config.AssetPolicyDecision, bool) {
		return api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Skill", CWD: project,
			ToolInput: map[string]interface{}{"skill": "shared-tool"},
		})
	}
	if decision, matched := call(); !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("both copies present: matched=%v decision=%+v, want an admin-deny block from the pinned user copy", matched, decision)
	}
	if err := os.RemoveAll(userCopy); err != nil {
		t.Fatal(err)
	}
	if decision, matched := call(); matched && decision.Source == "admin-deny" {
		t.Fatalf("user copy gone: decision=%+v, a pin to a copy the caller does not have must match nothing", decision)
	}
}
