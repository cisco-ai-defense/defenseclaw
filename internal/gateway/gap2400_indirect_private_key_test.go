// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"
)

func TestGAP2400LiteralIndirectPrivateKeyReadersReachGateway(t *testing.T) {
	home, cwd := r104ReviewHome(t)
	installDefaultProfileConnector(t, "claudecode")
	api := activeClaudeCodeTestAPI()
	ctx := withManagedHookPeer(context.Background(), managedHookPeer{Home: home})
	glob := "~/.ssh/" + "id_*"
	for _, tc := range []struct {
		name, tool, command string
		blocked             bool
	}{
		{"pipeline into PowerShell reader", "PowerShell", "Get-ChildItem " + glob + " | Get-Content", true},
		{"pipeline into POSIX reader", "Bash", "ls " + glob + " | xargs cat", true},
		{"literal variable into reader", "PowerShell", "$p = ~/.ssh/" + "id_ed25519; Get-Content $p", true},
		{"M02 trailing gc", "PowerShell", "gci " + glob + " | gc", true},
		{"M18 assigned type", "PowerShell", `$k = "$HOME\.ssh\` + "id_ed25519" + `"; type $k`, true},
		{"M20 xargs head", "Bash", "ls $HOME/.ssh/" + "id_* | xargs head", true},
		{"Raw parameter", "PowerShell", "Get-ChildItem " + glob + " | Get-Content -Raw", true},
		{"Encoding parameter", "PowerShell", "gci " + glob + " | gc -Encoding utf8", true},
		{"B26 bare cat in Bash", "Bash", "ls " + glob + " | cat", false},
		{"B26 PowerShell alias", "PowerShell", "ls " + glob + " | cat", true},
		{"explicit project path with Raw", "PowerShell", "Get-ChildItem " + glob + " | Get-Content -Raw -Path ~/project/notes.txt", false},
		{"bare head", "Bash", "ls " + glob + " | head", false},
		{"bare tail", "Bash", "ls " + glob + " | tail", false},
		{"bare base64", "Bash", "ls " + glob + " | base64", false},
		{"project pipeline into reader", "PowerShell", "Get-ChildItem ~/project/notes* | Get-Content", false},
		{"directory listing", "PowerShell", "Get-ChildItem ~/.ssh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap2400-static-reader", CWD: cwd,
				ToolName: tc.tool, ToolInput: map[string]interface{}{"command": tc.command},
				Payload: map[string]interface{}{"tool_name": tc.tool},
			})
			got := resp.Action == "block" && strings.Contains(strings.Join(resp.Findings, ","), "PATH-SSH-KEY:")
			if got != tc.blocked {
				t.Errorf("command %q: action=%q findings=%v, want PATH-SSH-KEY block=%t", tc.command, resp.Action, resp.Findings, tc.blocked)
			}
		})
	}
}
