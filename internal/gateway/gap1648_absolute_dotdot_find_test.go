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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func TestGAP1648AbsoluteDotDotFindVerdict(t *testing.T) {
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

	const attack = "find $HOME/.. -type f -delete"
	const benign = "find \"$HOME/proj\" -type f -delete"
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
					HookEventName: "PreToolUse", SessionID: "gap1648-find",
					ToolName: "Bash", CWD: filepath.Join(home, "proj"),
					ToolInput: map[string]interface{}{"command": command},
				})
				return resp.Action, resp.Severity, resp.RuleIDs
			}
			attackAction, attackSeverity, attackRules := judge(attack)
			benignAction, benignSeverity, benignRules := judge(benign)
			t.Logf("%s %s attack=%s/%s %v benign=%s/%s %v", tier.name, connector,
				attackAction, attackSeverity, attackRules, benignAction, benignSeverity, benignRules)
			got, want := boundedParse(attackAction), bounded.Unknown(tier.tier)
			if bounded.Stricter(got, want) != got {
				t.Errorf("%s %s: absolute dot-dot find below unknown tier", tier.name, connector)
			}
			if benignAction != "allow" {
				t.Errorf("%s %s: benign project-local find changed to %s", tier.name, connector, benignAction)
			}
		}
	}
}
