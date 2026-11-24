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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestEffectStateFolderWriteTiers: a copy, move, archive extraction or
// write that lands in the DefenseClaw state folder itself or as a new child
// of it is a state write in every tier, on both connectors, in the build's
// default configuration: an alert in default, permissive and managed
// default, a block in strict and managed strict (the GAP-0747 cell). The
// same copies into a project folder stay allowed (rel-1-0-10:GAP-1261,
// GAP-1285, GAP-2127). The shell text is never run.
func TestEffectStateFolderWriteTiers(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{".defenseclaw/config.yaml", "proj/notes.txt", "proj/alpha", "proj/beta", "backup/keep.txt", "proj.tar",
		"proj/.defenseclaw/config.yaml", "proj/backup/.defenseclaw/config.yaml", "proj/newstate/config.yaml", "proj/config.yaml",
		"proj/src/x", "proj/out/keep"} {
		p := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	useDefaultLaneGeneration(t)
	rows := []struct {
		id, cmd, cwd string
		attack       bool
	}{
		{"cp -r", "cp -r proj ~/.defenseclaw", ".", true},
		{"cp -r slash", "cp -r proj ~/.defenseclaw/", ".", true},
		{"cp -R absolute", "cp -R proj " + home + "/.defenseclaw", ".", true},
		{"cp -a", "cp -a proj ~/.defenseclaw", ".", true},
		{"cp -r new child", "cp -r proj ~/.defenseclaw/proj", ".", true},
		{"cp file", "cp proj/notes.txt ~/.defenseclaw", ".", true},
		{"cp file new child", "cp proj/notes.txt ~/.defenseclaw/new.txt", ".", true},
		{"redirect new child", "echo x > ~/.defenseclaw/new.txt", ".", true},
		{"rsync -a", "rsync -a proj ~/.defenseclaw/", ".", true},
		{"tar -x -C", "tar -xf proj.tar -C ~/.defenseclaw", ".", true},
		{"mv dir", "mv proj ~/.defenseclaw/", ".", true},
		{"mv brace (GAP-1285)", "mv {alpha,beta} ~/.defenseclaw/", "proj", true},
		// the GAP-1261 rows: a folder named .defenseclaw copied onto the
		// state root, the state folder moved away as a source
		{"cp -rt home", "cp -rt ~ .defenseclaw", "proj", true},
		{"cp -rt $HOME", `cp -rt "$HOME" backup/.defenseclaw`, "proj", true},
		{"cp -rt $HOME/ slash", `cp -rt "$HOME/" "$HOME/proj/backup/.defenseclaw/"`, "proj", true},
		{"cp -r onto $HOME/", `cp -r backup/.defenseclaw "$HOME/"`, "proj", true},
		{"cp -rT onto $HOME state", `cp -rT backup/.defenseclaw "$HOME/.defenseclaw"`, "proj", true},
		{"cp -rT onto state", "cp -rT newstate ~/.defenseclaw", "proj", true},
		{"env cp -rt", "env cp -rt ~ .defenseclaw", "proj", true},
		{"mv -St state source", "mv -St ~/.defenseclaw config.yaml", "proj", true},
		// controls the 1.0.10 readers already hold
		{"mv state folder away", "mv ~/.defenseclaw /tmp/dcx", ".", true},
		{"mv -S state folder away", "mv -S .bak ~/.defenseclaw /tmp/dcx", ".", true},
		{"rm -rf state folder", "rm -rf ~/.defenseclaw", ".", true},
		{"xargs cp -t", "printf '%s\\n' config.yaml | xargs cp -t ~/.defenseclaw", "proj", true},
		{"benign cp -r", "cp -r proj backup", ".", false},
		{"benign cp -a", "cp -a proj backup", ".", false},
		{"benign cp file", "cp proj/notes.txt backup", ".", false},
		{"benign rsync -a", "rsync -a proj backup/", ".", false},
		{"benign tar -x -C", "tar -xf proj.tar -C backup", ".", false},
		{"benign mv dir", "mv proj backup/", ".", false},
		{"benign mv brace", "mv {alpha,beta} ../backup/", "proj", false},
		{"benign cp -r beside state", "cp -r proj " + home + "/.defenseclaw-copy", ".", false},
		// a stale lifecycle lock removed: a benign agent trace shape that
		// keeps its 1.0.10 cell (decision_effect_fold_test)
		{"benign stale lock rm", "rm -f ~/.defenseclaw/.codex-lifecycle.lock", ".", false},
		{"benign cp -rt", "cp -rt ~/proj/out src", "proj", false},
		{"benign cp -r $HOME project", `cp -r src "$HOME/proj/out/"`, "proj", false},
		{"benign redirect $HOME project", `echo x > "$HOME/proj/out/notes.txt"`, "proj", false},
	}
	for _, tier := range boundedTestTiers {
		want := "alert"
		if strings.Contains(tier.name, "strict") {
			want = "block"
		}
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				cwd := filepath.Join(home, row.cwd)
				var action string
				if connector == "codex" {
					action = api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
						ToolInput: map[string]interface{}{"command": row.cmd},
					}).Action
				} else {
					action = api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "state-folder-write",
						ToolName: "Bash", CWD: cwd,
						ToolInput: map[string]interface{}{"command": row.cmd},
					}).Action
				}
				if !row.attack {
					if action != "allow" {
						t.Errorf("%s %s %s: %s, want allow", tier.name, connector, row.id, action)
					}
					continue
				}
				if action != want {
					t.Errorf("%s %s %s: %s, want %s", tier.name, connector, row.id, action, want)
				}
			}
		}
	}
}

// useDefaultLaneGeneration installs a live generation whose cascade lanes are
// unset, so every lane runs in the build's own default mode (the effects lane
// as shipped), with the placed-path resolver of the effect-lane tests.
func useDefaultLaneGeneration(t *testing.T) {
	t.Helper()
	previous := liveGeneration.Load()
	cfg := &config.Config{}
	cfg.Guardrail.EffectsRulesTier = string(tierRestricted)
	liveGeneration.Store(&Generation{Config: cfg})
	prevResolver := effectResolverOverride
	effectResolverOverride = func(path string) (string, bool) { return path, true }
	t.Cleanup(func() {
		liveGeneration.Store(previous)
		effectResolverOverride = prevResolver
	})
}
