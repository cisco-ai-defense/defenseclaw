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

func TestGAP1037LastpipeCredentialReadVerdict(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{".ssh/id_rsa", "proj/notes.txt"} {
		path := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	const plain = "cat ~/.ssh/id_rsa"
	const attack = "shopt -s lastpipe; echo x | cd ~/.ssh; cat id_rsa"
	const benign = "shopt -s lastpipe; echo x | cd ~/proj; cat notes.txt"
	rank := func(action string) int {
		switch action {
		case "allow":
			return 0
		case "alert":
			return 1
		case "block":
			return 2
		default:
			return -1
		}
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			judge := func(command string) (string, string, []string) {
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: filepath.Join(home, "proj"),
						ToolInput: map[string]interface{}{"command": command},
					})
					return resp.Action, resp.Severity, resp.RuleIDs
				}
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "gap1037-lastpipe",
					ToolName: "Bash", CWD: filepath.Join(home, "proj"),
					ToolInput: map[string]interface{}{"command": command},
				})
				return resp.Action, resp.Severity, resp.RuleIDs
			}
			plainAction, plainSeverity, plainRules := judge(plain)
			attackAction, attackSeverity, attackRules := judge(attack)
			benignAction, benignSeverity, benignRules := judge(benign)
			t.Logf("%s %s: plain=%s/%s %v attack=%s/%s %v benign=%s/%s %v",
				tier.name, connector, plainAction, plainSeverity, plainRules,
				attackAction, attackSeverity, attackRules, benignAction, benignSeverity, benignRules)
			if rank(plainAction) < 1 {
				t.Errorf("%s %s: plain credential read was not detected", tier.name, connector)
			}
			if rank(attackAction) < rank(plainAction) {
				t.Errorf("%s %s: lastpipe credential read weaker than plain", tier.name, connector)
			}
			if benignAction != "allow" {
				t.Errorf("%s %s: benign lastpipe read changed to %s", tier.name, connector, benignAction)
			}
		}
	}
}
