// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// r107MSYSDrive spells an absolute Windows path as a Git Bash drive mount.
func r107MSYSDrive(path string) string {
	path = filepath.ToSlash(path)
	return "/" + strings.ToLower(path[:1]) + path[2:]
}

// TestR107DeniedSkillFolderInEveryDriveSpelling: a skill on the admin deny
// list, matched by the name its SKILL.md declares, is refused when a call
// reads its folder spelled C:/..., ~/..., /c/... (Git Bash), //c/... or
// /cygdrive/c/..., for Claude Code and Codex, per user and managed; a skill
// that is not denied stays allowed in every spelling (rel-1-0-6:GAP-0299).
func TestR107DeniedSkillFolderInEveryDriveSpelling(t *testing.T) {
	home := t.TempDir()
	for folder, declared := range map[string]string{"renamed17": "vs8-denied-x", "plain1": "vs8-plain"} {
		dir := filepath.Join(home, ".claude", "skills", folder)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: "+declared+"\n---\nbody\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	cfg := &config.Config{AssetPolicy: config.DefaultAssetPolicy()}
	cfg.Guardrail.Mode = "action"
	cfg.AssetPolicy.Skill.Denied = []config.AssetPolicyRule{{Name: "vs8-denied-x"}}
	api := &APIServer{scannerCfg: cfg}
	spellings := func(folder string) []string {
		manifest := filepath.Join(home, ".claude", "skills", folder, "SKILL.md")
		msys := r107MSYSDrive(manifest)
		return []string{filepath.ToSlash(manifest), "~/.claude/skills/" + folder + "/SKILL.md", msys, "/" + msys, "/cygdrive" + msys}
	}
	for _, row := range []struct {
		folder string
		block  bool
	}{{"renamed17", true}, {"plain1", false}} {
		for _, path := range spellings(row.folder) {
			command := "cat " + path
			for _, managed := range []bool{false, true} {
				ctx := context.Background()
				if managed {
					ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
				}
				claude, claudeMatched := api.claudeCodeSkillAssetDecision(ctx, claudeCodeHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash", CWD: home,
					ToolInput: map[string]interface{}{"command": command},
				})
				codex, codexMatched := api.codexSkillAssetDecision(ctx, codexHookRequest{
					HookEventName: "PreToolUse", ToolName: "Bash", CWD: home,
					ToolInput: map[string]interface{}{"command": command},
				})
				for connector, got := range map[string]bool{
					"claudecode": claudeMatched && claude.Action == "block",
					"codex":      codexMatched && codex.Action == "block",
				} {
					if got != row.block {
						t.Errorf("%s managed=%v %q: block=%v, want %v (claude %+v, codex %+v)", connector, managed, command, got, row.block, claude, codex)
					}
				}
			}
		}
	}
}
