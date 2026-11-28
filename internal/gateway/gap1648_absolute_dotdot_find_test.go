// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A find root that is an absolute path with a dot-dot step reaches what its
// resolved folder reaches: a find that deletes the files of the agent's hook
// folder through $HOME/../<home>, a literal parent step, a step after a name
// or a step after a directory link gets the cell find ~/.claude gets, in every
// tier and for both connectors. Before, OperandPath kept every step of an
// absolute operand raw and the find reader compared the raw spelling, so each
// of these allowed (rel-1-0-10:GAP-1648). The old pin used only find $HOME/..,
// which reaches the floor through the detector state folder and passed
// before the fix. Benign twins that climb into an ordinary project folder
// stay allowed.
func TestGAP1648AbsoluteDotDotFindVerdict(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{".claude/settings.json", ".codex/hooks.json", ".defenseclaw/config.yaml", "proj/notes.txt"} {
		path := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "proj"), filepath.Join(home, "lnk")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	base := filepath.Base(home)
	const plain = "find ~/.claude -type f -delete"
	attacks := map[string]string{
		"home-step":  "find $HOME/../" + base + "/.claude -type f -delete",
		"quoted":     "find \"$HOME/../" + base + "/.claude\" -type f -delete",
		"literal":    "find " + home + "/../" + base + "/.claude -type f -delete",
		"after-name": "find " + home + "/proj/../.claude -type f -delete",
		"relative":   "find ../proj/../.claude -type f -delete",
		"after-link": "find " + home + "/lnk/../.claude -type f -delete",
	}
	benign := map[string]string{
		"home-step-proj": "find $HOME/../" + base + "/proj -type f -delete",
		"proj":           "find \"$HOME/proj\" -type f -delete",
		"literal-proj":   "find " + home + "/../" + base + "/proj -type f -delete",
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			judge := func(command string) (string, string) {
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: filepath.Join(home, "proj"),
						ToolInput: map[string]interface{}{"command": command},
					})
					return resp.Action, resp.Severity
				}
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "gap1648-find",
					ToolName: "Bash", CWD: filepath.Join(home, "proj"),
					ToolInput: map[string]interface{}{"command": command},
				})
				return resp.Action, resp.Severity
			}
			wantAction, wantSeverity := judge(plain)
			if wantAction == "allow" {
				t.Fatalf("%s %s: the plain hook folder find allows; the pin has no reference cell", tier.name, connector)
			}
			for name, command := range attacks {
				if action, severity := judge(command); action != wantAction || severity != wantSeverity {
					t.Errorf("%s %s %s: %s/%s, want the plain find cell %s/%s", tier.name, connector, name,
						action, severity, wantAction, wantSeverity)
				}
			}
			for name, command := range benign {
				if action, _ := judge(command); action != "allow" {
					t.Errorf("%s %s benign %s: %s, want allow", tier.name, connector, name, action)
				}
			}
		}
	}
}
