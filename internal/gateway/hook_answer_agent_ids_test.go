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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/agentidentity"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// postHookAs sends body to connectorName's hook route as the per-user
// caller peer and returns the decoded answer.
func postHookAs(t *testing.T, peer context.Context, connectorName, path, body string) map[string]interface{} {
	t.Helper()
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = connectorName
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(peer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	http.HandlerFunc(api.handleAgentHook(connectorName)).ServeHTTP(w, req)
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s answer %d is not JSON: %v %s", connectorName, w.Code, err, w.Body.String())
	}
	return out
}

// The hook answer carries the agent identity (agt-) and the session or
// sub-agent instance (ais-) the gateway derived for the hook, the ids its
// audit rows and telemetry carry, on the Claude Code route and on a generic
// route.
func TestHookAnswerCarriesTheDerivedAgentIDs(t *testing.T) {
	agentIdentityTestSetup(t)
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 5151, Name: "gina", Home: t.TempDir()})
	for _, tc := range []struct {
		connector, path, body, subagent string
	}{
		{"claudecode", "/api/v1/claude-code/hook",
			`{"session_id":"sess-ids","hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`, ""},
		{"claudecode", "/api/v1/claude-code/hook",
			`{"session_id":"sess-ids","agent_id":"task-7","hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`, "task-7"},
		{"devin", "/api/v1/devin/hook",
			`{"session_id":"sess-ids","hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"exec","tool_input":{"command":"ls"}}`, ""},
	} {
		t.Run(tc.connector+"/"+tc.subagent, func(t *testing.T) {
			identity := resolveHookAgentIdentity(peer, agentHookRequest{ConnectorName: tc.connector}).ID
			if !strings.HasPrefix(identity, agentidentity.AgentIDPrefix) {
				t.Fatalf("test peer derived no agent identity: %q", identity)
			}
			instance := agentidentity.InstanceID(identity, "sess-ids")
			if tc.subagent != "" {
				instance = agentidentity.SubagentInstanceID(instance, tc.subagent)
			}
			got := postHookAs(t, peer, tc.connector, tc.path, tc.body)
			if got["agent_identity_id"] != identity || got["agent_instance_id"] != instance {
				t.Fatalf("answer ids = %v / %v, want %s / %s (answer %v)",
					got["agent_identity_id"], got["agent_instance_id"], identity, instance, got)
			}
		})
	}
}

// A hook with no session has no instance, and the field is omitted; Secure
// Client keeps its answer shape and gets neither field.
func TestHookAnswerOmitsAgentIDsItDidNotDerive(t *testing.T) {
	agentIdentityTestSetup(t)
	peer := withManagedHookPeer(context.Background(), managedHookPeer{UID: 5252, Name: "hank", Home: t.TempDir()})
	noSession := postHookAs(t, peer, "claudecode", "/api/v1/claude-code/hook",
		`{"hook_event_name":"PreToolUse","cwd":"/tmp","tool_name":"Bash","tool_input":{"command":"ls"}}`)
	if _, ok := noSession["agent_instance_id"]; ok {
		t.Fatalf("a hook with no session carries an instance id: %v", noSession)
	}

	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(false) })
	sc := (&APIServer{}).withHookAnswerAgentIDs(
		ContextWithAgentIdentity(context.Background(), AgentIdentity{IdentityID: "agt-0000000000000001", AgentInstanceID: "ais-0000000000000001"}),
		agentHookResponse{Action: "allow"})
	if sc.AgentIdentityID != "" || sc.AgentInstanceID != "" {
		t.Fatalf("Secure Client answer got agent ids: %+v", sc)
	}
}
