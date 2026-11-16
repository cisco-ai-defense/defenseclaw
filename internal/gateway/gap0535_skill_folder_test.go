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
	"runtime"
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

func TestGAP0535ChangedDirectoryUsesReachedSkillTree(t *testing.T) {
	home, cwd, other := t.TempDir(), t.TempDir(), t.TempDir()
	for _, row := range []struct{ dir, name string }{
		{filepath.Join(home, ".claude", "skills", "folder"), "listed-name"},
		{filepath.Join(other, "skills", "folder"), "ordinary-name"},
	} {
		if err := os.MkdirAll(row.dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(row.dir, "SKILL.md"), []byte("---\nname: "+row.name+"\n---\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{scannerCfg: cfg}
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Name: "fixture", Home: home})
	for _, command := range []string{
		"cd " + other + " && cat skills/folder/SKILL.md",
		"cd " + other + " && cat skills/missing/SKILL.md",
	} {
		decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		})
		if matched {
			t.Fatalf("ordinary skill read matched: %+v", decision)
		}
	}
	decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
		HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
		ToolInput: map[string]interface{}{"command": "cd " + filepath.Join(home, ".claude") + " && cat skills/folder/SKILL.md"},
	})
	if !matched || decision.Action != "block" || decision.Source != "admin-deny" {
		t.Fatalf("listed skill read = %+v, matched=%v", decision, matched)
	}
}

func TestGAP0535SequentialDirectoryUsesReachedSkillTree(t *testing.T) {
	home, cwd, other := t.TempDir(), t.TempDir(), t.TempDir()
	homeSkill := filepath.Join(home, ".claude", "skills", "folder")
	otherSkill := filepath.Join(other, ".claude", "skills", "folder")
	for _, dir := range []string{homeSkill, otherSkill} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{scannerCfg: cfg}
	// This fixture represents an entered directory: its mode and owner must
	// agree with the peer credentials used by the resolver.
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: os.Geteuid(), GID: os.Getegid(), Name: "fixture", Home: home})
	for _, separator := range []string{"; ", "\n"} {
		for _, deniedAtReached := range []bool{false, true} {
			homeName, otherName := "listed-name", "ordinary-name"
			if deniedAtReached {
				homeName, otherName = otherName, homeName
			}
			for dir, name := range map[string]string{homeSkill: homeName, otherSkill: otherName} {
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			command := "cd " + filepath.Join(other, ".claude") + separator + "cat skills/folder/SKILL.md"
			decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
				ToolInput: map[string]interface{}{"command": command},
			})
			if matched != deniedAtReached || matched && (decision.Action != "block" || decision.Source != "admin-deny") {
				t.Errorf("separator %q, denied at reached %t: decision=%+v matched=%t", separator, deniedAtReached, decision, matched)
			}
		}
	}
}

func TestGAP0535UnprovenSequentialDirectoryChecksBothTrees(t *testing.T) {
	home, cwd, other := t.TempDir(), t.TempDir(), t.TempDir()
	first := filepath.Join(cwd, "skills", "folder")
	second := filepath.Join(other, "skills", "folder")
	for _, dir := range []string{first, second} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "listed-name"}}
	api := &APIServer{scannerCfg: cfg}
	for _, tc := range []struct {
		name string
		path string
		uid  int
		gid  int
	}{
		{"regular-file", filepath.Join(t.TempDir(), "file"), os.Geteuid(), os.Getegid()},
		{"missing", filepath.Join(t.TempDir(), "missing"), os.Geteuid(), os.Getegid()},
		// A directory owned by this test process at 0700 is not enterable
		// by the synthetic managed peer; existence alone proves nothing.
		{"foreign-0700", other, os.Geteuid() + 1001, os.Getegid() + 1001},
	} {
		if tc.name == "regular-file" {
			if err := os.WriteFile(tc.path, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, separator := range []string{"; ", "\n"} {
			for _, placement := range []string{"ordinary", "cwd-denied", "candidate-denied"} {
				if placement == "candidate-denied" && tc.name != "foreign-0700" {
					continue
				}
				for _, dir := range []string{first, second} {
					name := "ordinary-name"
					if placement == "cwd-denied" && dir == first || placement == "candidate-denied" && dir == second {
						name = "listed-name"
					}
					if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+name+"\n---\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ctx := withManagedHookPeer(context.Background(), managedHookPeer{UID: tc.uid, GID: tc.gid, Name: "fixture", Home: home})
				decision, matched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
					ToolInput: map[string]interface{}{"command": "cd " + tc.path + separator + "cat skills/folder/SKILL.md"},
				})
				want := placement != "ordinary"
				// Mode 0700 and a synthetic UID do not restrict a Windows
				// directory. The cd reaches other there, so a denied skill
				// only in cwd cannot be read by the following cat.
				if runtime.GOOS == "windows" && tc.name == "foreign-0700" && placement == "cwd-denied" {
					want = false
				}
				if matched != want || matched && (decision.Action != "block" || decision.Source != "admin-deny") {
					t.Errorf("%s separator=%q placement=%s: decision=%+v matched=%t", tc.name, separator, placement, decision, matched)
				}
			}
		}
	}
}
