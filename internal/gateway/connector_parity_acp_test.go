// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestACPTerminalCreateShellStringNeverWeakerThanTheHook: terminal/create
// {bash, [-c, <command>]} is judged at least as the Claude Code Bash call of
// <command> (GAP-0783).
func TestACPTerminalCreateShellStringNeverWeakerThanTheHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("terminal/create runs PowerShell on a Windows gateway")
	}
	var commands []struct{ id, command string }
	for _, c := range loadACPParityCases(t) {
		if !strings.EqualFold(c.Tool, "bash") {
			continue
		}
		var args struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(c.Args, &args) == nil && strings.TrimSpace(args.Command) != "" {
			commands = append(commands, struct{ id, command string }{c.ID, args.Command})
		}
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		env := newACPActionEnv(t, p.pack)
		policies, _ := filepath.Abs(filepath.Join("..", "..", "policies"))
		env.acpAPI.scannerCfg.PolicyDir = policies
		if p.managed {
			env.acpAPI.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
			env.acpAPI.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
		}
		env.setMode(acp.ModeAction)
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		for _, c := range commands {
			base := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode", conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", env.project, "Bash", map[string]any{"command": c.command})}, p.managed)
			frame := acpFrameJSON(t, 1, "terminal/create", map[string]any{"sessionId": "s", "command": "bash",
				"args": []string{"-c", c.command}, "cwd": env.project})
			v := gap0486ACPEvaluate(t, env, acp.AgentToClient, frame, p.managed)
			if shapeParityRank[v.Action] < shapeParityRank[base] {
				t.Errorf("%s %s: ACP terminal/create answered %s, Claude Code Bash %s", p.name, c.id, v.Action, base)
			}
		}
	})
}
