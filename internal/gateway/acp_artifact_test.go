// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestACPTerminalCreateScriptBodyAndChmodMatchTheHook: a script a shell frame
// runs is read as the Claude Code Bash call reads it (a body that touches an
// authorized_keys file blocks, a benign one is allowed), and a world-writable
// chmod through terminal/create is never weaker than that call
// (rel-1-0-10:GAP-0783).
func TestACPTerminalCreateScriptBodyAndChmodMatchTheHook(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("terminal/create runs PowerShell on a Windows gateway")
	}
	commands := []string{"chmod -R u=rwX,go=rX ~/proj", "chmod -R 777 ~/proj", "chmod -R a+w ~/proj", "chmod 777 /tmp/x", "sh Snonesh_prog.sh", "LC_ALL=C sh Senvprefixsh_prog.sh", "sh Sbenign_prog.sh"}
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
		for name, body := range map[string]string{
			"Snonesh_prog.sh":      "touch ~/.ssh/authorized_keys\n",
			"Senvprefixsh_prog.sh": "touch ~/.ssh/authorized_keys\n",
			"Sbenign_prog.sh":      "echo hello\n",
		} {
			if err := os.WriteFile(filepath.Join(env.project, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, command := range commands {
			base := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode", conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", env.project, "Bash", map[string]any{"command": command})}, p.managed)
			frame := acpFrameJSON(t, 1, "terminal/create", map[string]any{"sessionId": "s", "command": "bash",
				"args": []string{"-c", command}, "cwd": env.project})
			v := gap0486ACPEvaluate(t, env, acp.AgentToClient, frame, p.managed)
			t.Logf("%s %q: hook=%s acp=%s", p.name, command, base, v.Action)
			if strings.HasPrefix(strings.TrimPrefix(command, "LC_ALL=C "), "sh S") && v.Action != base {
				t.Errorf("%s %q: ACP terminal/create answered %s, Claude Code Bash %s (a script body is read the same)", p.name, command, v.Action, base)
			}
			if shapeParityRank[v.Action] < shapeParityRank[base] {
				t.Errorf("%s %q: ACP terminal/create answered %s, Claude Code Bash %s", p.name, command, v.Action, base)
			}
		}
	})
}
