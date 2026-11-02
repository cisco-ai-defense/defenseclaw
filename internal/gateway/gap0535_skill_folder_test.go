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

func TestGAP0535DeclaredSkillFolderSpellings(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	root := filepath.Join(home, ".claude", "skills")
	for folder, declared := range map[string]string{"folder": "listed-name", "ordinary": "unlisted-name"} {
		dir := filepath.Join(root, folder)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+declared+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	for name, command := range map[string]string{
		"absolute": "cat " + filepath.Join(root, "folder", "SKILL.md"),
		"home":     "cat ~/.claude/skills/folder/SKILL.md",
		"variable": "cat $HOME/.claude/skills/folder/SKILL.md",
		"parent":   "cat " + filepath.Join(root, "ordinary", "..", "folder", "SKILL.md"),
		"slashes":  "cat " + home + "//.claude//skills//folder//SKILL.md",
		"cd":       "cd " + filepath.Join(home, ".claude") + " && cat skills/folder/SKILL.md",
		"account":  "cat ~fixture/.claude/skills/folder/SKILL.md",
	} {
		t.Run(name, func(t *testing.T) {
			decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
				t.Fatalf("skill folder decision = %+v, matched=%v", decision, matched)
			}
		})
	}
	for _, command := range []string{
		"cd " + filepath.Join(home, ".claude") + " && cat skills/ordinary/SKILL.md",
		"cat ~fixture/.claude/skills/ordinary/SKILL.md",
	} {
		if decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		}); matched {
			t.Fatalf("ordinary skill folder matched: %+v", decision)
		}
	}
}
