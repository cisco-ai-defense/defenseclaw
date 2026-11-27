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

// A recursive removal of the agent's hook folder gets the cell of the plain
// spelling in every tier and for both connectors:
//
//   - rel-1-0-10:GAP-2285: with HOME reached through a directory link, by ~,
//     by $HOME, by the physical path, by a relative step or after cd ~, the
//     cell rm of the folder gets under a plain HOME (and find ~/.claude
//     -delete got under either); before, each allowed in every tier.
//   - rel-1-0-10:GAP-2286: the removal a prefix wrapper runs in a folder it
//     names (sudo -D/--chdir DIR, env -C/--chdir DIR) gets the cell of cd DIR
//     and the same removal; plain sudo, nice and sudo -u the cell of the
//     unwrapped call; sudo -i (the target user's home, a folder the words do
//     not name) the cell of a cd the walk cannot place. Before, each allowed
//     or got only the sudo cell.
//
// Benign twins (a project folder, a wrapper folder elsewhere, another dot
// folder) stay allowed, or keep the sudo cell of the same call.
func TestGAP2285GAP2286HookFolderRemovalVerdict(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	for _, name := range []string{".claude/settings.json", ".codex/hooks.json", ".defenseclaw/config.yaml", "proj/build/out.o"} {
		path := filepath.Join(real, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(real, linked); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	type cell struct{ action, severity string }
	type row struct{ command, cwd string }
	for _, home := range []string{real, linked} {
		t.Setenv("HOME", home)
		proj := filepath.Join(home, "proj")
		plain := row{"cd ~ && rm -rf .claude", proj}
		unplaced := row{"cd \"$D\" && rm -rf .claude", proj}
		attacks := map[string]row{
			"tilde":        {"rm -rf ~/.claude", proj},
			"home-var":     {"rm -rf \"$HOME/.claude\"", proj},
			"physical":     {"rm -rf " + real + "/.claude", proj},
			"spelled":      {"rm -rf " + home + "/.claude", proj},
			"relative":     {"rm -rf ../.claude", proj},
			"in-home":      {"rm -rf .claude", home},
			"codex-folder": {"rm -rf ~/.codex", proj},
			"sudo-chdir":   {"sudo -D \"$HOME\" rm -rf .claude", proj},
			"sudo-chdir=":  {"sudo --chdir=\"$HOME\" rm -rf .claude", proj},
			"env-chdir":    {"env -C \"$HOME\" rm -rf .claude", proj},
			"env-chdir=":   {"env --chdir=\"$HOME\" rm -rf .claude", proj},
			"env-relative": {"env -C ~/proj rm -rf ../.claude", proj},
			"sudo-user":    {"sudo -u nobody -D \"$HOME\" rm -rf .claude", proj},
			"cd-sudo":      {"cd ~ && sudo rm -rf .claude", proj},
			"sudo":         {"sudo rm -rf ~/.claude", proj},
			"nice":         {"nice rm -rf ~/.claude", proj},
			"sudo-dotdot":  {"sudo -D " + home + "/proj/.. rm -rf .claude", proj},
		}
		benign := map[string]row{
			"project":        {"rm -rf ~/proj/build", proj},
			"build":          {"rm -rf build", proj},
			"wrapped-build":  {"sudo -D \"$HOME\" rm -rf proj/build", proj},
			"env-build":      {"env -C \"$HOME/proj\" rm -rf build", proj},
			"env-elsewhere":  {"env -C /tmp rm -rf .claude", proj},
			"sudo-elsewhere": {"sudo -D /tmp rm -rf .claude", proj},
			"env-cache":      {"env -C ~ rm -rf .cache", proj},
		}
		for _, tier := range boundedTestTiers {
			for _, connector := range []string{"claudecode", "codex"} {
				api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
				judge := func(r row) cell {
					if connector == "codex" {
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", ToolName: "shell", CWD: r.cwd,
							ToolInput: map[string]interface{}{"command": r.command},
						})
						return cell{resp.Action, resp.Severity}
					}
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap2285-rm",
						ToolName: "Bash", CWD: r.cwd,
						ToolInput: map[string]interface{}{"command": r.command},
					})
					return cell{resp.Action, resp.Severity}
				}
				name := filepath.Base(home) + " " + tier.name + " " + connector
				want := judge(plain)
				if want.action == "allow" {
					t.Fatalf("%s: the plain hook folder removal allows; the pin has no reference cell", name)
				}
				for id, r := range attacks {
					if got := judge(r); got != want {
						t.Errorf("%s %s: %s/%s, want the plain removal cell %s/%s", name, id, got.action, got.severity, want.action, want.severity)
					}
				}
				if got, unplacedCell := judge(row{"sudo -i rm -rf .claude", proj}), judge(unplaced); got != unplacedCell {
					t.Errorf("%s sudo -i: %s/%s, want the cell of an unplaced cd %s/%s", name, got.action, got.severity, unplacedCell.action, unplacedCell.severity)
				}
				for id, r := range benign {
					if got := judge(r); got.action != "allow" {
						t.Errorf("%s benign %s: %s/%s, want allow", name, id, got.action, got.severity)
					}
				}
			}
		}
	}
}
