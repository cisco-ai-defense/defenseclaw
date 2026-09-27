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
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestSandboxHookDecisionsNameEachHarnessCall pins the gateway half of hook
// tamper detection for the hook-only harnesses: each one's pre-tool and
// post-tool events reach the manager under the harness's own event names,
// with what names the call. Cursor, OpenCode and Amp send a per-call ID;
// Kiro CLI sends none (measured on 2.24.1), so the call's session and tool
// input must reach the manager byte for byte the same from both events.
func TestSandboxHookDecisionsNameEachHarnessCall(t *testing.T) {
	var mu sync.Mutex
	var decisions []SandboxHookDecision
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) {
		c.OnHookDecision = func(d SandboxHookDecision) {
			mu.Lock()
			defer mu.Unlock()
			decisions = append(decisions, d)
		}
	})
	for _, tc := range []struct {
		spec      *harness.Spec
		path      string
		pre, post string
		// preBody and postBody are the harness's payloads (the plugins'
		// for OpenCode and Amp).
		preBody, postBody string
		id, session       string
		status            string
	}{
		{
			spec: harness.Kiro, path: "/api/v1/kiro/hook", pre: "preToolUse", post: "postToolUse",
			// Kiro CLI 2.24.1's own payloads.
			preBody: `{"hook_event_name":"preToolUse","cwd":"/work/app","session_id":"c2197843-ce66-4011-a627-052241fa9da8",` +
				`"tool_name":"shell","tool_input":{"command":"echo dce2e-pair"}}`,
			postBody: `{"hook_event_name":"postToolUse","cwd":"/work/app","session_id":"c2197843-ce66-4011-a627-052241fa9da8",` +
				`"tool_name":"shell","tool_input":{"command":"echo dce2e-pair"},"tool_response":{"items":[{"Text":"dce2e-pair\n"}]}}`,
			session: "c2197843-ce66-4011-a627-052241fa9da8",
		},
		{
			spec: harness.Cursor, path: "/api/v1/cursor/hook", pre: "preToolUse", post: "postToolUse",
			preBody: `{"hook_event_name":"preToolUse","conversation_id":"conv-pair","generation_id":"gen-pair",` +
				`"tool_name":"Shell","tool_input":{"command":"echo dce2e-pair"},"tool_use_id":"tool_cursor_pair","cwd":"/work/app"}`,
			postBody: `{"hook_event_name":"postToolUse","conversation_id":"conv-pair","generation_id":"gen-pair",` +
				`"tool_name":"Shell","tool_input":{"command":"echo dce2e-pair"},"tool_output":"dce2e-pair\n","tool_use_id":"tool_cursor_pair","cwd":"/work/app"}`,
			id: "tool_cursor_pair",
		},
		{
			spec: harness.OpenCode, path: "/api/v1/opencode/hook", pre: "tool.execute.before", post: "tool.execute.after",
			preBody: `{"hook_event_name":"tool.execute.before","tool_name":"bash","tool_input":{"command":"echo dce2e-pair"},` +
				`"session_id":"ses_pair","turn_id":"msg_pair","tool_call_id":"call_opencode_pair","cwd":"/work/app",` +
				`"load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp"}`,
			postBody: `{"hook_event_name":"tool.execute.after","tool_name":"bash","tool_input":{"command":"echo dce2e-pair"},` +
				`"session_id":"ses_pair","turn_id":"msg_pair","tool_call_id":"call_opencode_pair","cwd":"/work/app",` +
				`"load_heartbeat":true,"arguments_authoritative":true,"mcp_identity_status":"not_mcp",` +
				`"tool_response":{"title":"echo","output":"dce2e-pair\n","metadata":{"exit":0}}}`,
			id: "call_opencode_pair",
		},
		{
			spec: harness.Amp, path: "/api/v1/amp/hook", pre: "tool.call", post: "tool.result",
			preBody: `{"hook_event_name":"tool.call","thread_id":"T-pair","session_id":"T-pair","tool_call_id":"toolu_amp_pair",` +
				`"tool_name":"Bash","tool_input":{"cmd":"echo dce2e-pair"},"cwd":"/work/app"}`,
			postBody: `{"hook_event_name":"tool.result","thread_id":"T-pair","session_id":"T-pair","tool_call_id":"toolu_amp_pair",` +
				`"tool_name":"Bash","tool_input":{"cmd":"echo dce2e-pair"},"tool_response":{"output":"dce2e-pair\n"},` +
				`"status":"done","error":"","cwd":"/work/app"}`,
			id: "toolu_amp_pair", status: "done",
		},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			version := tc.spec.DefaultVersion
			contract := connector.ResolveSandboxHookContract(tc.spec.Name, version)
			if contract.Status != connector.HookCompatibilityKnown {
				t.Fatalf("%s %s: no sandbox hook contract: %s", tc.spec.Name, version, contract.Reason)
			}
			_, token, err := f.store.Mint(sandboxauth.Spec{
				SandboxName: "dc-pair-" + tc.spec.Name, Connector: tc.spec.Name,
				AgentVersion: version, HookContractID: contract.Contract.ContractID,
				Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
				HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
			})
			if err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			decisions = nil
			mu.Unlock()
			for _, body := range []string{tc.preBody, tc.postBody} {
				if rec := f.do(t, http.MethodPost, tc.path, token, body); rec.Code != http.StatusOK {
					t.Fatalf("%s: %d %s", body[:40], rec.Code, rec.Body.String())
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if len(decisions) != 2 {
				t.Fatalf("decisions = %+v", decisions)
			}
			pre, post := decisions[0], decisions[1]
			if pre.Connector != tc.spec.Name || pre.Event != tc.pre || post.Event != tc.post || pre.Action != "allow" {
				t.Fatalf("events: pre %+v post %+v", pre, post)
			}
			if pre.ToolUseID != tc.id || post.ToolUseID != tc.id {
				t.Fatalf("tool-use IDs %q and %q, want %q", pre.ToolUseID, post.ToolUseID, tc.id)
			}
			if pre.ResultStatus != "" || post.ResultStatus != tc.status {
				t.Fatalf("result status: pre %q post %q, want %q", pre.ResultStatus, post.ResultStatus, tc.status)
			}
			if tc.session != "" && (pre.SessionID != tc.session || post.SessionID != tc.session) {
				t.Fatalf("sessions %q and %q, want %q", pre.SessionID, post.SessionID, tc.session)
			}
			if len(pre.ToolInput) == 0 || !bytes.Equal(pre.ToolInput, post.ToolInput) || pre.Tool == "" || pre.Tool != post.Tool {
				t.Fatalf("the call's tool and input differ: pre %q %s, post %q %s", pre.Tool, pre.ToolInput, post.Tool, post.ToolInput)
			}
			var input map[string]interface{}
			if err := json.Unmarshal(pre.ToolInput, &input); err != nil || len(input) != 1 {
				t.Fatalf("tool input %s is not the call's input: %v", pre.ToolInput, err)
			}
		})
	}
}

// A hook event without a tool input names no call by content: ToolArgs
// falls back to the whole payload there, which a call's pre-tool and
// post-tool events do not share.
func TestSandboxDecisionToolInput(t *testing.T) {
	withInput := agentHookRequest{
		Payload:  map[string]interface{}{"tool_input": map[string]interface{}{"command": "ls"}},
		ToolArgs: json.RawMessage(`{"command":"ls"}`),
	}
	if got := sandboxDecisionToolInput(withInput); string(got) != `{"command":"ls"}` {
		t.Fatalf("tool input = %s", got)
	}
	without := agentHookRequest{
		Payload:  map[string]interface{}{"hook_event_name": "stop", "assistant_response": "done"},
		ToolArgs: json.RawMessage(`{"assistant_response":"done","hook_event_name":"stop"}`),
	}
	if got := sandboxDecisionToolInput(without); got != nil {
		t.Fatalf("an event without a tool input named %s", got)
	}
}
