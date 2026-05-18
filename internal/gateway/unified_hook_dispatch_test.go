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

// TestUnifiedHookDispatch_BespokeFallback proves the wrapper's
// bespoke fallback table: codex and claudecode resolve to their
// dedicated handlers (so wire responses are byte-identical to today),
// while the rest fall through to handleAgentHook. Without this test a
// future rename of a bespoke handler could silently route through the
// generic agent path and ship a behavior regression for codex /
// claudecode operators.
func TestUnifiedHookDispatch_BespokeFallback(t *testing.T) {
	api := &APIServer{}
	cases := []struct {
		name        string
		connector   string
		wantBespoke bool
	}{
		{"codex_uses_bespoke", "codex", true},
		{"claudecode_uses_bespoke", "claudecode", true},
		{"hermes_uses_generic", "hermes", false},
		{"cursor_uses_generic", "cursor", false},
		{"windsurf_uses_generic", "windsurf", false},
		{"geminicli_uses_generic", "geminicli", false},
		{"copilot_uses_generic", "copilot", false},
		{"unknown_falls_back_generic", "made-up", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// We cannot directly compare function pointers in Go,
			// so we exercise each handler's contract: the bespoke
			// codex/claudecode handlers reject an empty POST body
			// via the "hook_event_name is required" branch (because
			// json.Unmarshal into codexHookRequest succeeds on
			// `{}`); the generic handleAgentHook emits "hook event
			// name is required" (lowercase _event_). The exact
			// message lets us disambiguate which handler ran.
			h := api.bespokeHookHandlerForUnifiedCollector(tc.connector)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/x/hook", bytes.NewReader([]byte(`{}`)))
			h(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 for empty body, got %d: %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if tc.wantBespoke {
				if !contains(body, "hook_event_name is required") {
					t.Errorf("%s should run bespoke handler, got body=%q", tc.connector, body)
				}
			} else {
				if !contains(body, "hook event name is required") {
					t.Errorf("connector %s should run generic handler, got body=%q", tc.connector, body)
				}
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

// TestUnifiedDispatchParity_Codex asserts the unified dispatch
// wrapper produces a JSONEq response body to the bespoke handler for
// codex when both run against the same payload. Since the wrapper
// delegates directly to the bespoke handler, this guards against a
// future refactor that breaks the contract.
func TestUnifiedDispatchParity_Codex(t *testing.T) {
	api := &APIServer{}

	payload, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-codex-parity",
		"turn_id":         "turn-1",
		"model":           "gpt-5",
		"tool_name":       "Bash",
		"agent_id":        "openai_codex",
		"agent_type":      "codex",
		"tool_input":      map[string]interface{}{"command": "ls /"},
	})

	bespokeBody := runHookHandler(t, api.handleCodexHook, payload)
	unifiedBody := runHookHandler(t, api.handleUnifiedConnectorHook("codex"), payload)

	var bespokeJSON, unifiedJSON map[string]interface{}
	if err := json.Unmarshal(bespokeBody, &bespokeJSON); err != nil {
		t.Fatalf("bespoke body not JSON: %v body=%s", err, bespokeBody)
	}
	if err := json.Unmarshal(unifiedBody, &unifiedJSON); err != nil {
		t.Fatalf("unified body not JSON: %v body=%s", err, unifiedBody)
	}
	if !jsonEq(bespokeJSON, unifiedJSON) {
		t.Errorf("dispatch parity broken for codex.\nbespoke=%s\nunified=%s", bespokeBody, unifiedBody)
	}
}

// TestUnifiedDispatchParity_ClaudeCode is the claudecode-side mirror
// of TestUnifiedDispatchParity_Codex.
func TestUnifiedDispatchParity_ClaudeCode(t *testing.T) {
	api := &APIServer{}

	payload, _ := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      "sess-claude-parity",
		"model":           "claude-3-7-sonnet",
		"tool_name":       "Read",
		"agent_id":        "anthropic_claudecode",
		"agent_type":      "claudecode",
		"tool_input":      map[string]interface{}{"file_path": "/etc/passwd"},
	})

	bespokeBody := runHookHandler(t, api.handleClaudeCodeHook, payload)
	unifiedBody := runHookHandler(t, api.handleUnifiedConnectorHook("claudecode"), payload)

	var bespokeJSON, unifiedJSON map[string]interface{}
	if err := json.Unmarshal(bespokeBody, &bespokeJSON); err != nil {
		t.Fatalf("bespoke body not JSON: %v body=%s", err, bespokeBody)
	}
	if err := json.Unmarshal(unifiedBody, &unifiedJSON); err != nil {
		t.Fatalf("unified body not JSON: %v body=%s", err, unifiedBody)
	}
	if !jsonEq(bespokeJSON, unifiedJSON) {
		t.Errorf("dispatch parity broken for claudecode.\nbespoke=%s\nunified=%s", bespokeBody, unifiedBody)
	}
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
