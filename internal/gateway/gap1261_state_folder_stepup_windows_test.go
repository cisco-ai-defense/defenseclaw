// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP1261StateFolderStepUpWindowsFiveTiers(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "alice")
	project := filepath.Join(home, "proj")
	for _, name := range []string{".defenseclaw/config.yaml", "proj/backup/.defenseclaw/config.yaml", "proj/notes.txt"} {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("marker"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	gap0589WindowsHost(t)
	previous := liveGeneration.Load()
	cfg := &config.Config{}
	cfg.Guardrail.EffectsRulesTier = string(tierRestricted)
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	for _, tier := range boundedTestTiers {
		want := "alert"
		if strings.Contains(tier.name, "strict") {
			want = "block"
		}
		api := gap0589TierAPI(t, "claudecode", tier.posture, tier.managed, tier.tier)
		for _, row := range []struct{ id, command, cwd, want string }{
			{"destination-dotdot", `cp -r -t "$HOME/.defenseclaw/.." backup/.defenseclaw`, project, want},
			{"source-dotdot-no-write", "cp -rt ~ .defenseclaw/..", home, "allow"},
			{"project-dotdot", `cp -r -t "$HOME/proj/backup/.." notes.txt`, project, "allow"},
		} {
			got := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap1261-stepup",
				ToolName: "Bash", CWD: row.cwd, ToolInput: map[string]interface{}{"command": row.command},
			}).Action
			if got != row.want {
				t.Errorf("%s %s: %s, want %s", tier.name, row.id, got, row.want)
			}
		}
	}
}
