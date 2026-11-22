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

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestTicketRequestAsksInDefaultPerConnector (rel-1-0-10:GAP-0067,
// GAP-0017, GAP-0371): a Kerberos ticket request in the default tier (per-user
// and managed) asks where the agent can ask and alerts where it cannot, never
// a block: Claude Code asks in Manual (permission mode default) and alerts in
// every other mode, Codex (no native ask) alerts, /inspect/tool asks through
// the OpenClaw native approval surface and alerts without it. Strict blocks
// it on every connector; permissive alerts. At a64bfdb931 the default tier
// alerted everywhere.
func TestTicketRequestAsksInDefaultPerConnector(t *testing.T) {
	const ticket = "credential.directory_ticket_request"
	commands := []string{
		"impacket-GetUserSPNs -request -dc-ip 198.51.100.10 example.com/svc:S3cretP4ss",
		"nxc smb 198.51.100.10 -u svc -p S3cretP4ss --shares",
	}
	project := t.TempDir()
	for _, p := range gap0437Packs {
		want := map[string]string{
			"claudecode/default": "confirm", "claudecode/acceptEdits": "alert", "claudecode/bypassPermissions": "alert",
			"claudecode/plan": "alert", "codex": "alert", "inspect": "alert",
		}
		switch p.pack {
		case "strict":
			for k := range want {
				want[k] = "block"
			}
		case "permissive":
			for k := range want {
				want[k] = "alert"
			}
		}
		claude := gap0437Server(t, p, "claudecode", "action")
		codex := gap0437Server(t, p, "codex", "action")
		inspect := gap0437Server(t, p, "openclaw", "action")
		// The OpenClaw plugin with its native approval surface asks.
		if p.pack != "strict" {
			native := gap0437Serve(t, inspect.handleInspectTool, "/api/v1/inspect/tool", map[string]any{
				"tool": "exec", "connector": "openclaw", "approval_surface": "native",
				"args": map[string]any{"command": commands[0], "workdir": project},
			})
			wantNative := "confirm"
			if p.pack == "permissive" {
				wantNative = "alert"
			}
			if got, _ := native["action"].(string); got != wantNative {
				t.Errorf("%s inspect native approval: %s, want %s", p.name, got, wantNative)
			}
		}
		for ci, command := range commands {
			got := map[string]string{}
			rules := map[string][]string{}
			for _, mode := range []string{"default", "acceptEdits", "bypassPermissions", "plan"} {
				out := gap0437Serve(t, claude.handleAgentHook("claudecode"), "/api/v1/claude-code/hook", map[string]any{
					"hook_event_name": "PreToolUse", "session_id": fmt.Sprintf("g0067-%s-%s-%d", p.name, mode, ci), "cwd": project,
					"permission_mode": mode, "tool_name": "Bash", "tool_use_id": fmt.Sprintf("tu-g0067-%s-%d", mode, ci),
					"tool_input": map[string]any{"command": command},
				})
				key := "claudecode/" + mode
				got[key], _, rules[key] = gap0067Verdict(out)
			}
			body, _ := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "session_id": fmt.Sprintf("g0067-codex-%s-%d", p.name, ci), "cwd": project,
				"tool_name": "Bash", "tool_use_id": fmt.Sprintf("tu-g0067-codex-%d", ci), "tool_input": map[string]any{"command": command},
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			w := httptest.NewRecorder()
			codex.handleAgentHook("codex").ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("%s codex: status %d body %s", p.name, w.Code, w.Body.String())
			}
			var out map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			got["codex"], _, rules["codex"] = gap0067Verdict(out)
			got["inspect"], _ = gap0437Inspect(t, inspect, project, command)["action"].(string)
			for key, action := range got {
				t.Logf("ROW %s %d %s %s %v", p.name, ci, key, action, rules[key])
				if action != want[key] {
					t.Errorf("%s %s %q: %s, want %s (rules %v)", p.name, key, command, action, want[key], rules[key])
				}
				if r, ok := rules[key]; ok && len(r) > 0 && !slices.Contains(r, ticket) {
					t.Errorf("%s %s %q: rules %v do not name %s", p.name, key, command, r, ticket)
				}
			}
		}
	}
}

// gap0067Verdict is the action and rule ids of a hook answer.
func gap0067Verdict(out map[string]any) (action, severity string, rules []string) {
	action, _ = out["action"].(string)
	if action == "" {
		action = "allow"
	}
	severity, _ = out["severity"].(string)
	if raw, ok := out["rule_ids"].([]any); ok {
		for _, rule := range raw {
			rules = append(rules, fmt.Sprint(rule))
		}
	}
	return action, severity, rules
}
