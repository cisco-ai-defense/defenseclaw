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
// flows through the same unified pipeline (handleAgentHook). Before
// the unified collector landed, codex and claudecode each had a
// separate bespoke HTTP handler that re-implemented audit / metrics
// / dedup wiring, and the bespoke claudecode handler had drifted
// far enough to silently drop session_id from the audit envelope —
// only caught when Splunk verification spotted the gap. The bespoke
// handlers were deleted and every connector now routes through
// handleAgentHook; this test pins that contract so a future
// "let's reintroduce a bespoke handler for X" change immediately
// fails CI.
//
// The contract we assert: an empty POST body produces the unified
// handler's "hook event name is required" error (lowercase
// _event_). The legacy bespoke handlers emitted
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
		"openhands",
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
// through the connector registry. This is the gateway-side mirror of
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
		// hermes has no Decode: its `extra` content is recovered by the
		// generic decoder's ContentEnvelopeKey fallback.
		{"hermes", "hermes", "hermes", false, true, true},
		{"cursor", "cursor", "cursor", false, true, true},
		{"openhands", "openhands", "openhands", false, true, true},
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
// Before the unified collector, the wire shape came from the
// bespoke handler's connector-specific response struct
// (claudeCodeHookResponse with `json:"claude_code_output"` tag, etc.).
// It now comes from renderAgentHookResponse +
// hookOutputFieldName(connectorName). The two paths must stay
// byte-identical for live agents to keep working — this test pins
// the field-name mapping so a future refactor of
// renderAgentHookResponse cannot silently rename a key and break
// Claude Code / Codex hook traffic.
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
		{"openhands", "hook_output"},
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

// TestUnifiedDispatch_SurfacesEvaluationIDAndRuleIDs pins the
// HTTP-response contract for the unified runtime-finding
// observability pipeline: when the evaluator stamps an
// evaluation_id + rule_ids on the agentHookResponse,
// renderAgentHookResponseForProfile MUST project them onto the
// JSON output map so hook scripts (and any downstream consumer
// of the HTTP response body) can pivot on the same join key
// surfaced via gateway.jsonl, scan_findings, and the audit DB
// structured envelope.
//
// Regression guard: the original render projection built a
// hardcoded subset map that silently dropped the new fields. The
// JSONL / audit DB surfaces still carried the join key, but
// callers consuming only the HTTP body were left orphaned — the
// "absolute observability" contract said every surface, so an
// in-test assertion is the only way to keep that promise.
//
// Negative half: when the evaluator emits an allow/no-findings
// response (the empty hookEvaluationContext path), neither
// evaluation_id nor rule_ids should appear in the wire shape —
// older hook scripts must continue parsing the same minimal
// envelope.
func TestUnifiedDispatch_SurfacesEvaluationIDAndRuleIDs(t *testing.T) {
	t.Run("populated", func(t *testing.T) {
		resp := agentHookResponse{
			Action:       "allow",
			RawAction:    "block",
			Severity:     "CRITICAL",
			Mode:         "observe",
			WouldBlock:   true,
			EvaluationID: "eval-fixture-uuid-1234",
			RuleIDs:      []string{"SEC-ANTHROPIC", "SEC-AWS-KEY"},
		}
		for _, connectorName := range []string{"codex", "claudecode", "hermes"} {
			out := renderAgentHookResponse(connectorName, resp)
			if got, ok := out["evaluation_id"].(string); !ok || got != "eval-fixture-uuid-1234" {
				t.Errorf("connector %s: evaluation_id = %v, want %q", connectorName, out["evaluation_id"], "eval-fixture-uuid-1234")
			}
			ids, ok := out["rule_ids"].([]string)
			if !ok || len(ids) != 2 || ids[0] != "SEC-ANTHROPIC" || ids[1] != "SEC-AWS-KEY" {
				t.Errorf("connector %s: rule_ids = %v, want [SEC-ANTHROPIC SEC-AWS-KEY]", connectorName, out["rule_ids"])
			}
		}
	})

	t.Run("empty_context_omits_fields", func(t *testing.T) {
		resp := agentHookResponse{
			Action:     "allow",
			Severity:   "NONE",
			Mode:       "observe",
			WouldBlock: false,
		}
		out := renderAgentHookResponse("codex", resp)
		if _, ok := out["evaluation_id"]; ok {
			t.Errorf("no-findings path must omit evaluation_id; got keys=%v", jsonKeys(out))
		}
		if _, ok := out["rule_ids"]; ok {
			t.Errorf("no-findings path must omit rule_ids; got keys=%v", jsonKeys(out))
		}
	})
}

// TestCodexResponseToAgentHookResponse_CarriesCorrelationIDs and
// TestClaudeCodeResponseToAgentHookResponse_CarriesCorrelationIDs
// guard the adapter layer that bridges codex/claudecode bespoke
// response structs into the unified agentHookResponse. The
// previous adapter dropped the EvaluationID + RuleIDs fields, so
// the codex_hook.go / claude_code_hook.go evaluators happily
// stamped them on the bespoke struct but they evaporated before
// the render projection ever saw them. These two tests pin the
// adapter contract so the regression cannot resurface.
func TestCodexResponseToAgentHookResponse_CarriesCorrelationIDs(t *testing.T) {
	src := codexHookResponse{
		Action:       "allow",
		RawAction:    "block",
		Severity:     "CRITICAL",
		Mode:         "observe",
		EvaluationID: "eval-codex-fixture",
		RuleIDs:      []string{"SEC-ANTHROPIC"},
	}
	out := codexResponseToAgentHookResponse(src)
	if out.EvaluationID != "eval-codex-fixture" {
		t.Errorf("EvaluationID = %q, want eval-codex-fixture", out.EvaluationID)
	}
	if len(out.RuleIDs) != 1 || out.RuleIDs[0] != "SEC-ANTHROPIC" {
		t.Errorf("RuleIDs = %v, want [SEC-ANTHROPIC]", out.RuleIDs)
	}
}

func TestClaudeCodeResponseToAgentHookResponse_CarriesCorrelationIDs(t *testing.T) {
	src := claudeCodeHookResponse{
		Action:       "allow",
		RawAction:    "block",
		Severity:     "CRITICAL",
		Mode:         "observe",
		EvaluationID: "eval-claude-fixture",
		RuleIDs:      []string{"SEC-AWS-KEY", "SEC-GITHUB-TOKEN"},
	}
	out := claudeCodeResponseToAgentHookResponse(src)
	if out.EvaluationID != "eval-claude-fixture" {
		t.Errorf("EvaluationID = %q, want eval-claude-fixture", out.EvaluationID)
	}
	if len(out.RuleIDs) != 2 {
		t.Errorf("RuleIDs len = %d, want 2", len(out.RuleIDs))
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
