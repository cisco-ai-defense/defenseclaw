// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	managedconfig "github.com/defenseclaw/defenseclaw/internal/managed"
)

// powerShellProtectedRoute sends one PowerShell command through the Windows
// hook route of a connector (Claude Code's PowerShell tool, Codex's shell
// tool) in one of the five tiers and returns the action and its rule ids.
func powerShellProtectedRoute(t *testing.T, home, cwd, connector, posture string, managed bool, command string) (string, []string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connector, posture)
	cfg := &config.Config{}
	if managed {
		cfg.DeploymentMode = managedconfig.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managedconfig.ProfileStandalone
	}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	ctx := context.Background()
	if managed {
		ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
	}
	raw, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	req := agentHookRequest{ConnectorName: connector, CWD: cwd, HookEventName: "PreToolUse", ToolArgs: raw}
	req.ToolName = "shell_command"
	if connector == "claudecode" {
		req.ToolName = "PowerShell"
	}
	resp := api.evaluateAgentHook(ctx, req)
	var ids []string
	for _, finding := range resp.Findings {
		ids = append(ids, strings.SplitN(finding, ":", 2)[0])
	}
	return resp.Action, ids
}

// rel-1-0-10:GAP-0749 (TW, dc-win2, Windows hook, every pack): New-Item
// -ItemType SymbolicLink, then Move-Item of that link, blocked as
// persistence.ssh_authorized_keys_command, the Windows twin of GAP-0571. The
// link and the move are read as the ln and mv they are: a link inside the
// project folder, moved, removed or written through, makes no key write. The
// rows are built with the host's own path syntax, so a Windows host runs them
// with drive paths and backslashes. A link to the keys file or to the .ssh
// folder, a link made in a protected name, a move onto the keys file, and a
// link the call makes from a dynamic operand keep the verdict they have on
// rel 52df5211d7 in every cell, with the GAP-0988 floor for a partial reading.
func TestGAP0749PowerShellLinkAndMoveAreNotAKeyWrite(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"), filepath.Join(proj, "uuid")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(home, ".defenseclaw", "config.yaml")} {
		if err := os.WriteFile(file, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sep := string(filepath.Separator)
	rel := func(name string) string { return "." + sep + name }
	abs := func(name string) string { return filepath.Join(proj, name) }
	newLink := func(name, target string) string {
		return fmt.Sprintf("New-Item -ItemType SymbolicLink -Path %s -Target %s", name, target)
	}
	const keysRule = "persistence.ssh_authorized_keys_command"
	allow := map[string]string{"default": "allow", "permissive": "allow", "strict": "allow", "managed": "allow", "managed-strict": "allow"}
	block := map[string]string{"default": "block", "permissive": "block", "strict": "block", "managed": "block", "managed-strict": "block"}
	dynamicRule, dynamicWant := "", allow
	if runtime.GOOS == "windows" {
		dynamicRule, dynamicWant = keysRule, block
	}
	rows := []struct {
		name, command, rule string
		want                map[string]string
	}{
		{"link then move (relative)", newLink(rel("link"), rel("uuid")) + "; Move-Item " + rel("link") + " " + rel("link2"), "", allow},
		{"link, move, remove (relative)", newLink(rel("link"), rel("uuid")) + "; Move-Item " + rel("link") + " " + rel("link2") + "; Remove-Item " + rel("link2"), "", allow},
		{"link then move (absolute)", newLink(abs("link"), abs("uuid")) + "; Move-Item " + abs("link") + " " + abs("link2"), "", allow},
		{"link then write through it", newLink(abs("link"), abs("uuid")) + "; Add-Content " + abs("link") + " marker", "", allow},
		{"link, move, write through the moved link", newLink(abs("link"), abs("uuid")) + "; Move-Item " + abs("link") + " " + abs("link2") + "; Add-Content " + abs("link2") + " marker", "", allow},
		{"junction then move", "New-Item -ItemType Junction -Path " + abs("j") + " -Target " + abs("uuid") + "; Move-Item " + abs("j") + " " + abs("j2"), "", allow},
		{"-Value for the target", "New-Item -ItemType SymbolicLink -Path " + abs("link") + " -Value " + abs("uuid") + "; Move-Item " + abs("link") + " " + abs("link2"), "", allow},
		{"a folder and a file, no link", "New-Item -ItemType Directory -Path " + abs("d") + "; New-Item -ItemType File -Path " + abs("d") + sep + "f", "", allow},
		// Positive rows: what rel blocks stays blocked.
		{"link to the keys file, write through it", newLink(abs("link"), keys) + "; Add-Content " + abs("link") + " marker", keysRule, block},
		{"link to the keys file, move, write through", newLink(abs("link"), keys) + "; Move-Item " + abs("link") + " " + abs("link2") + "; Add-Content " + abs("link2") + " marker", keysRule, block},
		{"link to the keys file, move only", newLink(abs("link"), keys) + "; Move-Item " + abs("link") + " " + abs("link2"), keysRule, block},
		{"link to the .ssh folder, write a key through it", newLink(abs("d"), filepath.Join(home, ".ssh")) + "; Add-Content " + filepath.Join(abs("d"), "authorized_keys") + " marker", keysRule, block},
		{"link made in the keys name", newLink(keys, abs("uuid")), keysRule, block},
		{"move of a link onto the keys file", newLink(abs("link"), abs("uuid")) + "; Move-Item " + abs("link") + " " + keys, keysRule, block},
		// A link target the call computes keeps the opaque reading: the write through
		// the link is an unproven key write on a Windows host, where the link text
		// is read opaque, exactly as on rel; a POSIX host reads the write operand
		// alone.
		{"link to a dynamic target, write through it", newLink(abs("link"), "$env:GAP0749") + "; Add-Content " + abs("link") + " marker", dynamicRule, dynamicWant},
		{"direct write of the keys file", "Add-Content " + keys + " marker", keysRule, block},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			for _, cell := range []string{"default", "permissive", "strict", "managed", "managed-strict"} {
				posture, managed := cell, false
				switch cell {
				case "managed":
					posture, managed = "default", true
				case "managed-strict":
					posture, managed = "strict", true
				}
				t.Run(fmt.Sprintf("%s %s %s", connector, cell, row.name), func(t *testing.T) {
					action, rules := powerShellProtectedRoute(t, home, proj, connector, posture, managed, row.command)
					want := row.want[cell]
					reading := actionfacts.Analyze(actionfacts.Input{Tool: "PowerShell", Command: row.command,
						CWD: proj, ActiveHome: home, DialectHint: actionfacts.DialectPowerShell})
					partial := reading.Parse.Status == actionfacts.StatusPartial
					if partial {
						floor := "alert"
						if managed || posture == "strict" {
							floor = "block"
						}
						if shapeParityRank[floor] > shapeParityRank[want] {
							want = floor
						}
					}
					if action != want {
						t.Fatalf("action = %q (rules %v), want %q", action, rules, want)
					}
					if row.rule != "" && !slices.Contains(rules, row.rule) {
						t.Fatalf("rules = %v, want %s", rules, row.rule)
					}
					if row.rule == "" {
						for _, id := range rules {
							if !partial || id != evaluationLimitRuleID {
								t.Fatalf("rules = %v, want no semantic finding (a partial floor may remain)", rules)
							}
						}
					}
				})
			}
		}
	}
}
