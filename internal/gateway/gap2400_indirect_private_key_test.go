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
		name, command string
		blocked       bool
	}{
		{"pipeline into PowerShell reader", "Get-ChildItem " + glob + " | Get-Content", true},
		{"pipeline into POSIX reader", "ls " + glob + " | xargs cat", true},
		{"literal variable into reader", "$p = ~/.ssh/" + "id_ed25519; Get-Content $p", true},
		{"project pipeline into reader", "Get-ChildItem ~/project/notes* | Get-Content", false},
		{"directory listing", "Get-ChildItem ~/.ssh", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "gap2400-static-reader", CWD: cwd,
				ToolName: "PowerShell", ToolInput: map[string]interface{}{"command": tc.command},
				Payload: map[string]interface{}{"tool_name": "PowerShell"},
			})
			got := resp.Action == "block" && strings.Contains(strings.Join(resp.Findings, ","), "PATH-SSH-KEY:")
			if got != tc.blocked {
				t.Errorf("command %q: action=%q findings=%v, want PATH-SSH-KEY block=%t", tc.command, resp.Action, resp.Findings, tc.blocked)
			}
		})
	}
}
