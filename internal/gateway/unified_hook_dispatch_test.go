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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestUnifiedHookDispatch_SingleEntryPoint proves every connector
// flows through the same unified pipeline (handleAgentHook). Prior
// to PR #284, codex and claudecode each had a separate bespoke HTTP
// handler that re-implemented audit / metrics / dedup wiring — the
// F2 audit-correlation regression bit live Splunk verification
// because the bespoke claudecode handler had drifted. PR #284
// deleted both bespoke handlers and routed everyone through
// handleAgentHook; this test pins that contract so a future
// "let's reintroduce a bespoke handler for X" change immediately
// fails CI.
//
// The contract we assert: an empty POST body produces the unified
// handler's "hook event name is required" error (lowercase
// _event_). The pre-PR-#284 bespoke handlers emitted
// "hook_event_name is required" (with underscore), so if a future
// regression reintroduces a bespoke handler we'd see the
// underscored variant and this test fails.
func TestUnifiedHookDispatch_SingleEntryPoint(t *testing.T) {
	api := &APIServer{}
	connectors := []string{
		"codex",
		"claudecode",
		"hermes",
		"cursor",
		"windsurf",
		"geminicli",
		"copilot",
		"made-up",
	}
	for _, name := range connectors {
		t.Run(name, func(t *testing.T) {
			h := api.handleUnifiedConnectorHook(name)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/x/hook", bytes.NewReader([]byte(`{}`)))
			h(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for empty body, got %d: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			// "hook event name is required" is handleAgentHook's
			// error message (lowercase _event_). The deleted
			// bespoke handlers used "hook_event_name is required"
			// (underscored). Asserting the lowercase form pins
			// the unified-handler routing for every connector.
			if !contains(body, "hook event name is required") {
				t.Errorf("connector %s did not flow through unified pipeline; body=%q", name, body)
			}
		})
	}
}

// TestHookProfileForConnector validates that the gateway's
// HookProfile lookup returns the right declarative profile for each
// connector, with the Decode/MapVerdict/Respond callbacks wired up
// where expected. This is the gateway-side mirror of
// TestHookProfile_HasDispatchCallbacks in the connector package and
// guards against a registration drift where the connector ships
// callbacks but the gateway's lookup never sees them.
func TestHookProfileForConnector(t *testing.T) {
	api := &APIServer{}
	cases := []struct {
		name           string
		connector      string
		wantName       string
		wantDecode     bool
		wantMapVerdict bool
		wantRespond    bool
	}{
		{"codex", "codex", "codex", true, true, true},
		{"claudecode", "claudecode", "claudecode", true, true, true},
		{"hermes", "hermes", "hermes", false, false, false},
		{"cursor", "cursor", "cursor", false, false, false},
		{"unknown_returns_zero", "made-up", "made-up", false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := api.hookProfileForConnector(tc.connector)
			if p.Name != tc.wantName {
				t.Errorf("Name=%q want %q", p.Name, tc.wantName)
			}
			if (p.Decode != nil) != tc.wantDecode {
				t.Errorf("Decode set=%v want=%v", p.Decode != nil, tc.wantDecode)
			}
			if (p.MapVerdict != nil) != tc.wantMapVerdict {
				t.Errorf("MapVerdict set=%v want=%v", p.MapVerdict != nil, tc.wantMapVerdict)
			}
			if (p.Respond != nil) != tc.wantRespond {
				t.Errorf("Respond set=%v want=%v", p.Respond != nil, tc.wantRespond)
			}
		})
	}
}

// TestUnifiedDispatch_PreservesConnectorWireShape asserts that
// after the bespoke-handler deletion, the unified pipeline still
// emits the connector-specific top-level JSON field (codex_output
// for codex, claude_code_output for claudecode, hook_output for
// everything else). This is the regression guard for the contract
// each agent CLI expects when reading hook responses — Claude Code
// rejects responses without "claude_code_output", Codex rejects
// without "codex_output".
//
// Pre-PR-#284 the wire shape came from the bespoke handler's
// connector-specific response struct (claudeCodeHookResponse with
// `json:"claude_code_output"` tag, etc.). Post-PR-#284 it comes
// from renderAgentHookResponse + hookOutputFieldName(connectorName).
// The two paths must stay byte-identical for live agents to keep
// working — this test pins the field-name mapping so a future
// refactor of renderAgentHookResponse cannot silently rename a key
// and break Claude Code / Codex hook traffic.
func TestUnifiedDispatch_PreservesConnectorWireShape(t *testing.T) {
	resp := agentHookResponse{
		Action:     "block",
		Severity:   "HIGH",
		Mode:       "action",
		WouldBlock: false,
		HookOutput: map[string]interface{}{"decision": "block", "reason": "test"},
	}
	cases := []struct {
		connector     string
		wantFieldName string
	}{
		{"codex", "codex_output"},
		{"claudecode", "claude_code_output"},
		{"hermes", "hook_output"},
		{"cursor", "hook_output"},
		{"windsurf", "hook_output"},
		{"geminicli", "hook_output"},
		{"copilot", "hook_output"},
		{"made-up", "hook_output"},
	}
	for _, tc := range cases {
		t.Run(tc.connector, func(t *testing.T) {
			out := renderAgentHookResponse(tc.connector, resp)
			if _, ok := out[tc.wantFieldName]; !ok {
				t.Errorf("connector %s: expected output map under key %q, got keys=%v", tc.connector, tc.wantFieldName, jsonKeys(out))
			}
			// Negative: the OTHER connectors' keys must not appear.
			for _, other := range cases {
				if other.wantFieldName == tc.wantFieldName {
					continue
				}
				if _, ok := out[other.wantFieldName]; ok {
					t.Errorf("connector %s: must not emit key %q (would confuse %s agent CLI)", tc.connector, other.wantFieldName, other.connector)
				}
			}
		})
	}
}

// jsonKeys returns the sorted keys of a map for error messages.
func jsonKeys(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// runHookHandler invokes a hook handler with the supplied JSON body
// and returns the response body. We cannot use httptest.NewServer
// because that would require a fully wired APIServer with audit +
// otel + scanner dependencies — the parity contract is about wire
// shape, so a minimal handler invocation is enough.
func runHookHandler(t *testing.T, h http.HandlerFunc, body []byte) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/x/hook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", w.Code, w.Body.String())
	}
	return w.Body.Bytes()
}

// jsonEq is a lightweight JSONEq used by the parity tests. We do not
// import testify in this package to keep the gateway test surface
// dependency-light; reflect.DeepEqual on json.Unmarshal output is
// sufficient because Go's json package normalizes map iteration.
func jsonEq(a, b map[string]interface{}) bool {
	ab, err := json.Marshal(a)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}

func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}

// Compile-time assertion that the test file references the public
// API surface this PR locks in. If a future refactor renames any of
// these the build breaks here rather than at the test runtime,
// which makes a regression easier to bisect.
var _ = []interface{}{
	connector.HookProfile{}.Decode,
	connector.HookProfile{}.MapVerdict,
	connector.HookProfile{}.Respond,
}
