// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"strings"
	"testing"
)

// TestSandboxDefaultPackFlagsHomeCredentialReads pins that the default rule
// pack's home credential rules judge a sandboxed tool call as they judge the
// same call on the host. A harness names the sandbox HOME as "~", which the
// shell parser treats as an expansion; with the trusted sandbox home that
// expansion is exact, so PATH-SSH-KEY, whose owner needs an executed read,
// fires for `cat ~/.ssh/id_rsa` (it used to be judged clean in and out of a
// sandbox), and rules that match a home path by its spelling still fire.
func TestSandboxDefaultPackFlagsHomeCredentialReads(t *testing.T) {
	installDefaultProfileConnector(t, "claudecode")
	p := newSandboxProject(t)
	api := activeClaudeCodeTestAPI()
	contexts := map[string]context.Context{
		"sandbox": sandboxCtx(p.mount),
		"host":    withAuthenticatedHookConnector(context.Background(), "claudecode"),
	}
	cases := []struct {
		command string
		want    string // rule ID, or "" for none of the home credential rules
	}{
		{command: "cat ~/.ssh/id_rsa", want: "PATH-SSH-KEY"},
		{command: "head -n 5 ~/.ssh/id_ed25519", want: "PATH-SSH-KEY"},
		{command: "cat ~/.aws/credentials", want: "PATH-AWS-CREDS"},
		{command: "cat ~/.gnupg/pubring.kbx", want: "PATH-GNUPG"},
		{command: "cat ~/.ssh/id_rsa.pub"},
		{command: "ssh -i ~/.ssh/id_rsa build.example.com true"},
	}
	for _, tc := range cases {
		for name, ctx := range contexts {
			resp := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
				HookEventName: "PreToolUse", SessionID: "home-rules", CWD: p.root, ToolName: "Bash",
				ToolInput: map[string]interface{}{"command": tc.command},
				Payload:   map[string]interface{}{"tool_name": "Bash"},
			})
			var got []string
			for _, finding := range resp.Findings {
				id, _, _ := strings.Cut(finding, ":")
				if strings.HasPrefix(id, "PATH-") {
					got = append(got, id)
				}
			}
			switch {
			case tc.want == "" && len(got) != 0:
				t.Errorf("%s %q: findings %v, want no home credential rule", name, tc.command, resp.Findings)
			case tc.want != "" && !containsRuleID(got, tc.want):
				t.Errorf("%s %q: findings %v, want %s", name, tc.command, resp.Findings, tc.want)
			}
		}
	}
}
