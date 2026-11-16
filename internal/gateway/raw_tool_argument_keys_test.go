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
	"encoding/json"
	"strings"
	"testing"
)

// The generic /inspect/tool path and the guardrail proxy judge a tool call
// whose arguments repeat a key, or name one field twice inside an input,
// parameters or request wrapper, as each call it can be, like the hook path.
func TestRawToolArgumentsWithRepeatedOrNestedKeysReachTheRules(t *testing.T) {
	rows := []struct {
		name, tool, args string
		block            bool
	}{
		{"alone", "shell", `{"command":"rm -rf /"}`, true},
		{"same value repeated", "shell", `{"command":"rm -rf /","command":"rm -rf /"}`, true},
		{"unreviewed key repeated", "shell", `{"command":"rm -rf /","timeout":1,"timeout":2}`, true},
		{"wrapper case twin", "exec", `{"input":{"command":"rm -rf /","Command":"true"}}`, true},
		{"wrapper alias", "exec", `{"input":{"command":"rm -rf /","cmd":"true"}}`, true},
		{"parameters case twin", "exec", `{"parameters":{"command":"rm -rf /","Command":"true"}}`, true},
		{"wrapper key repeated", "exec", `{"input":{"command":"rm -rf /","command":"true"}}`, true},
		{"wrapper alone", "exec", `{"input":{"command":"rm -rf /"}}`, true},
		{"benign same value repeated", "shell", `{"command":"echo ok","command":"echo ok"}`, false},
		{"benign unreviewed key repeated", "shell", `{"command":"echo ok","timeout":1,"timeout":2}`, false},
		{"benign", "shell", `{"command":"echo ok"}`, false},
	}
	api := testAPIServerWithConfig(t, "action")
	for _, row := range rows {
		verdict := api.inspectToolPolicy(&ToolInspectRequest{Tool: row.tool, Args: json.RawMessage(row.args), Direction: "tool_call"})
		if blocked := verdict.Action == "block"; blocked != row.block {
			t.Errorf("inspect %s: action=%s findings=%v, want block=%v", row.name, verdict.Action, verdict.Findings, row.block)
		}
	}
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	for _, row := range rows {
		tool := row.tool
		if tool == "shell" {
			tool = "bash"
		}
		calls, _ := json.Marshal([]map[string]any{{"id": "c1", "type": "function", "function": map[string]any{"name": tool, "arguments": row.args}}})
		verdict := proxy.inspectToolCalls(context.Background(), calls)
		action, findings := "allow", ""
		if verdict != nil {
			action, findings = verdict.Action, strings.Join(verdict.Findings, " | ")
		}
		if blocked := action == "block"; blocked != row.block {
			t.Errorf("proxy %s: action=%s findings=%s, want block=%v", row.name, action, findings, row.block)
		}
	}
}
