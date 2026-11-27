// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGAP1590UnreadableFindRegexBlocksAtBothRoots (rel-1-0-10:GAP-1590, a
// documented limit): a find -regex whose escape the reader cannot prove (the
// GNU word anchors \< and \>, the q47 class) is treated as aimed at the
// protected hook files, so the delete is blocked in every tier, for both
// connectors, at the dot root and at the absolute root, whether or not the
// project holds a hook file. That over-block of a benign expression is the
// documented limit: the reader would have to lower the verdict of an
// expression that spells a protected name to fix it, and a64 blocks that
// spelling. This pin holds today's verdict so a later change cannot lower it
// silently; it stays green at rel and at the head. The protected-name twins
// (a word anchor around a name the reader can see) block as well.
func TestGAP1590UnreadableFindRegexBlocksAtBothRoots(t *testing.T) {
	commands := []struct{ name, command string }{
		{"q47 benign word-anchored build folder", `find @R@ -regex '.*/\<build\>.*' -delete`},
		{"protected-name twin, leading anchor", `find @R@ -regex '.*/\<setting[s]\.json' -delete`},
		{"protected-name twin, trailing anchor", `find @R@ -regex '.*/setting[s]\>\.json' -delete`},
	}
	cells := []struct {
		name, profile string
		managed       bool
	}{
		{"default", "default", false},
		{"permissive", "permissive", false},
		{"strict", "strict", false},
		{"managed", "default", true},
		{"managed-strict", "strict", true},
	}
	for _, conn := range []string{"claudecode", "codex"} {
		for _, c := range cells {
			t.Run(conn+"/"+c.name, func(t *testing.T) {
				home := filepath.Join(t.TempDir(), "home")
				project := filepath.Join(home, "proj")
				t.Setenv("HOME", home)
				t.Setenv("USERPROFILE", home)
				t.Setenv("CLAUDE_CONFIG_DIR", "")
				t.Setenv("CODEX_HOME", "")
				user := filepath.Join(home, ".claude", "settings.json")
				if err := os.MkdirAll(filepath.Dir(user), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(user, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				judge := newHookConfigJudge(t, conn, c.profile)
				for _, layout := range []string{"no hook file", "hook file present"} {
					_ = os.RemoveAll(project)
					if err := os.MkdirAll(project, 0o700); err != nil {
						t.Fatal(err)
					}
					if layout == "hook file present" {
						full := filepath.Join(project, ".claude", "settings.json")
						if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(full, []byte("{}\n"), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					for _, row := range commands {
						for _, root := range []string{".", project} {
							command := strings.ReplaceAll(row.command, "@R@", root)
							got := judge(project, c.managed, "Bash", map[string]any{"command": command})
							if action := hookConfigAction(got); action != "block" {
								t.Errorf("%s, %s: %s = %s, want block (documented limit): %s", layout, row.name, command, action, strings.TrimSpace(got))
							}
						}
					}
				}
			})
		}
	}
}

// TestGAP1590ProtectedNameWordAnchorTwinKeepsBlock (rel-1-0-10:GAP-1590): the
// earlier pin of the 1.0.10 verdict for a word-anchored find -regex that
// spells a protected file name, kept here by name beside the documented
// limit so the two stay together: a64 blocked it in every tier for both
// connectors, and it must not drop to an alert when the benign twin is ever
// reworked.
func TestGAP1590ProtectedNameWordAnchorTwinKeepsBlock(t *testing.T) {
	home := t.TempDir()
	// The protected name is spelled in two parts so no literal fixture of it
	// sits in this file.
	name := "authorized_" + "keys"
	target := filepath.Join(home, ".ssh", name)
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	useEffectsRulesMode(t, "on")
	command := `find . -regex '.*\<` + name + `\>.*' -delete`
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(tier.name+"/"+connector, func(t *testing.T) {
				api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
				var action string
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
						ToolInput: map[string]interface{}{"command": command},
					})
					action = resp.Action
				} else {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap1590-doc-limit",
						ToolName: "Bash", CWD: home,
						ToolInput: map[string]interface{}{"command": command},
					})
					action = resp.Action
				}
				if action != "block" {
					t.Errorf("protected-name word-anchor verdict = %s, want block", action)
				}
			})
		}
	}
}
