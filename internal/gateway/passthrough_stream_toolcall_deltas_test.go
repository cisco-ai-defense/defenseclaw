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

// GAP-0321: a streamed tool call whose arguments come only in deltas (and
// the item's *_call_*.done event), with no response.output_item.done, still
// goes through the tool-call rules: at response.completed (failed,
// incomplete) or at the end of the stream. A stream cut inside a call keeps
// the fail mode (refused in the strict and managed tiers), and a benign call
// reaches the client whole. Every streaming adapter shape is run in the five
// tiers; each run logs a TGWPROBE row (the probe matrix of train
// T-SUB-GWSTATE).

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	streamToolCallBad  = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	streamToolCallGood = "ls -la /tmp/build-output"
)

// streamToolCallCase is one streamed reply shape. end says how it ends:
// "" whole; "cut" inside a call of an SSE stream (the fail mode applies:
// refused in the fail-closed tiers); "cut-judged" inside a Bedrock call,
// whose partial call is judged and, when allowed, forwarded (its own state
// machine, not asserted here); "unnamed" a call whose name never comes
// (logged only: what the rules make of an unnamed call is theirs).
type streamToolCallCase struct {
	passthroughFieldCase
	end string
}

var streamToolCallTiers = []struct {
	name, pack string
	managed    bool
	// failClosed: a reply that cannot be inspected is refused
	// (refuseUninspectable: the strict tier; a managed standalone install on
	// the default pack forwards it with an alert, as an OSS install does).
	failClosed bool
}{
	{"default", "default", false, false},
	{"permissive", "permissive", false, false},
	{"strict", "strict", false, true},
	{"managed", "default", true, false},
	{"managed-strict", "strict", true, true},
}

// streamToolCallCases are the streamed shapes of every adapter, carrying the
// shell command cmd only in a tool call's arguments.
func streamToolCallCases(t *testing.T, cmd string) []streamToolCallCase {
	C := jsonText(cmd)
	args := jsonText(`{"command":` + C + `}`)
	raw := `{"command":` + C + `}`
	h1, h2 := jsonText(raw[:20]), jsonText(raw[20:])
	added := `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":""}}`
	d1 := `{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":` + h1 + `}`
	d2 := `{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":` + h2 + `}`
	argsDone := `{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":` + args + `}`
	itemDone := `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":` + args + `,"status":"completed"}}`
	completedEmpty := `{"type":"response.completed","response":{"id":"r","status":"completed","output":[]}}`
	completedFull := `{"type":"response.completed","response":{"id":"r","status":"completed","output":[{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":` + args + `}]}}`
	incomplete := `{"type":"response.incomplete","response":{"id":"r","status":"incomplete","output":[]}}`
	c := func(name, provider, path, ct, body string, end string) streamToolCallCase {
		return streamToolCallCase{passthroughFieldCase{name, provider, path, ct, body}, end}
	}
	R, A, G := "/v1/responses", "/v1/messages", "/v1beta/models/g:streamGenerateContent"
	return []streamToolCallCase{
		// Responses.
		c("responses/full", "openai", R, ctSSE, sseBody(added, d1, d2, argsDone, itemDone, completedFull), ""),
		c("responses/args_done_eof", "openai", R, ctSSE, sseBody(added, d1, d2, argsDone), "cut"),
		c("responses/args_done_completed", "openai", R, ctSSE, sseBody(added, d1, d2, argsDone, completedEmpty), ""),
		c("responses/deltas_completed", "openai", R, ctSSE, sseBody(added, d1, d2, completedEmpty), ""),
		c("responses/deltas_incomplete", "openai", R, ctSSE, sseBody(added, d1, d2, incomplete), ""),
		c("responses/deltas_eof", "openai", R, ctSSE, sseBody(added, d1, d2), "cut"),
		c("responses/no_added_index_only", "openai", R, ctSSE, sseBody(
			`{"type":"response.function_call_arguments.delta","output_index":0,"delta":`+h1+`}`,
			`{"type":"response.function_call_arguments.delta","output_index":0,"delta":`+h2+`}`,
			`{"type":"response.function_call_arguments.done","output_index":0,"name":"Bash","arguments":`+args+`}`, completedEmpty), ""),
		c("responses/no_added_unnamed", "openai", R, ctSSE, sseBody(
			`{"type":"response.function_call_arguments.delta","output_index":0,"delta":`+h1+`}`,
			`{"type":"response.function_call_arguments.delta","output_index":0,"delta":`+h2+`}`,
			`{"type":"response.function_call_arguments.done","output_index":0,"arguments":`+args+`}`, completedEmpty), "unnamed"),
		c("responses/item_done_only", "openai", R, ctSSE, sseBody(itemDone, completedFull), ""),
		c("responses/custom_tool_input", "openai", R, ctSSE, sseBody(
			`{"type":"response.output_item.added","output_index":0,"item":{"type":"custom_tool_call","id":"ct_1","name":"Bash","call_id":"c","input":""}}`,
			`{"type":"response.custom_tool_call_input.delta","item_id":"ct_1","output_index":0,"delta":`+h1+`}`,
			`{"type":"response.custom_tool_call_input.delta","item_id":"ct_1","output_index":0,"delta":`+h2+`}`,
			`{"type":"response.custom_tool_call_input.done","item_id":"ct_1","output_index":0,"input":`+args+`}`, completedEmpty), ""),
		// Chat Completions.
		c("chat/split_finish", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c","type":"function","function":{"name":"Bash","arguments":`+h1+`}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+h2+`}}]}}]}`,
			`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`, `[DONE]`), ""),
		c("chat/no_finish_eof", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c","type":"function","function":{"name":"Bash","arguments":`+h1+`}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+h2+`}}]}}]}`), ""),
		c("chat/legacy_function_call", "openai", "/v1/completions", ctSSE, sseBody(
			`{"choices":[{"index":0,"delta":{"function_call":{"name":"Bash","arguments":`+h1+`}}}]}`,
			`{"choices":[{"index":0,"delta":{"function_call":{"arguments":`+h2+`}}}]}`,
			`{"choices":[{"index":0,"delta":{},"finish_reason":"function_call"}]}`, `[DONE]`), ""),
		// Anthropic Messages.
		c("anthropic/input_json_delta", "anthropic", A, ctSSE, sseBody(
			`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Bash","input":{}}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h1+`}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h2+`}}`,
			`{"type":"content_block_stop","index":0}`, `{"type":"message_stop"}`), ""),
		c("anthropic/eof_in_block", "anthropic", A, ctSSE, sseBody(
			`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Bash","input":{}}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h1+`}}`,
			`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h2+`}}`), "cut"),
		// Bedrock ConverseStream.
		c("bedrock/converse_toolUse", "bedrock", "/model/m/converse-stream", ctEvents, eventStreamBody(t,
			"contentBlockStart", `{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"t1","name":"Bash"}}}`,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+h1+`}}}`,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+h2+`}}}`,
			"contentBlockStop", `{"contentBlockIndex":0}`,
			"messageStop", `{"stopReason":"tool_use"}`), ""),
		c("bedrock/eof_in_block", "bedrock", "/model/m/converse-stream", ctEvents, eventStreamBody(t,
			"contentBlockStart", `{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"t1","name":"Bash"}}}`,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+h1+`}}}`,
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+h2+`}}}`), "cut-judged"),
		// Gemini.
		c("gemini/functionCall", "gemini", G, ctSSE, sseBody(
			`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"Bash","args":{"command":`+C+`}}}]}}]}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}]}`), ""),
		// Ollama NDJSON.
		c("ollama/tool_calls", "ollama", "/api/chat", ctNDJSON, ndjsonBody(
			`{"model":"llama3","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"Bash","arguments":{"command":`+C+`}}}]},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":""},"done":true}`), ""),
	}
}

// streamToolCallRun sends the case through the passthrough proxy in action
// mode in one tier; chunk > 0 writes the reply in pieces of that size.
func streamToolCallRun(t *testing.T, c passthroughFieldCase, pack string, managedInstall bool, chunk int) string {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", c.contentType)
		b := []byte(c.body)
		if chunk <= 0 {
			_, _ = w.Write(b)
			return
		}
		f, _ := w.(http.Flusher)
		for i := 0; i < len(b); i += chunk {
			_, _ = w.Write(b[i:min(i+chunk, len(b))])
			if f != nil {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()
	registerRawForwardProviderDomain(t, upstream.URL, c.provider)
	allowRawForwardPrivateTargets(t)
	// A managed standalone install (the managed tiers): the process-wide
	// managed flag is the Secure Client posture, which a standalone install
	// leaves off (guardrailActionForGuardrailFindings).
	prev := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(false)
	defer managedEnterpriseActive.Store(prev)
	proxy := newTestProxy(t, &mockProvider{}, &fieldMarkerInspector{}, "action")
	req := httptest.NewRequest(http.MethodPost, c.path, strings.NewReader(passthroughRequestBody(c.provider)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", upstream.URL)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	req.RemoteAddr = "127.0.0.1:12345"
	cfg := config.DefaultConfig()
	cfg.Guardrail.RulePack = pack
	if managedInstall {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	req = req.WithContext(withPinnedGeneration(req.Context(), &Generation{N: 1, Config: cfg}))
	rec := httptest.NewRecorder()
	_ = captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
	return rec.Body.String()
}

// streamToolCallOutcome reads what the client got: "pass" (the call reached
// it: the end of the command, which every shape carries in one piece),
// "block" (a DefenseClaw block in its place) or "empty".
func streamToolCallOutcome(out, cmd string) string {
	switch {
	case strings.Contains(out, cmd[len(cmd)-16:]):
		return "pass"
	case strings.Contains(strings.ToLower(out), "defenseclaw"):
		return "block"
	}
	return "empty"
}

func TestStreamToolCallDeltasReachTheToolRules(t *testing.T) {
	for _, tier := range streamToolCallTiers {
		for _, kind := range []string{"bad", "good"} {
			cmd := map[string]string{"bad": streamToolCallBad, "good": streamToolCallGood}[kind]
			for _, c := range streamToolCallCases(t, cmd) {
				for _, chunk := range []int{0, 7} {
					name := tier.name + "/" + kind + "/" + c.name + map[bool]string{true: "/whole", false: "/chunked"}[chunk == 0]
					t.Run(name, func(t *testing.T) {
						got := streamToolCallOutcome(streamToolCallRun(t, c.passthroughFieldCase, tier.pack, tier.managed, chunk), cmd)
						t.Logf("TGWPROBE %s %s %s chunk=%d %s", tier.name, kind, c.name, chunk, got)
						want := "block"
						switch {
						case c.end == "unnamed" || (c.end == "cut-judged" && kind == "good"):
							return
						case kind == "good" && !(c.end == "cut" && tier.failClosed):
							want = "pass"
						}
						if got != want {
							t.Errorf("client got %s, want %s", got, want)
						}
					})
				}
			}
		}
	}
}

// The state machine itself: what each Responses ending hands the rules.
func TestSSEToolCallsResponsesItemEndings(t *testing.T) {
	added := `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":""}}`
	delta := func(s string) string {
		return `{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":` + jsonText(s) + `}`
	}
	argsDone := func(s string) string {
		return `{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":` + jsonText(s) + `}`
	}
	itemDone := func(s string) string {
		return `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":` + jsonText(s) + `}}`
	}
	const completed = `{"type":"response.completed","response":{"id":"r","output":[]}}`
	type call struct{ Name, Args string }
	take := func(s *sseToolCalls) []call {
		var raw []sseToolCall
		if b := s.Take(); b != nil {
			_ = json.Unmarshal(b, &raw)
		}
		var out []call
		for _, c := range raw {
			out = append(out, call{c.Function.Name, c.Function.Arguments})
		}
		return out
	}
	for _, tc := range []struct {
		name       string
		events     []string
		finish     bool
		want       []call
		wantBroken bool
	}{
		{"item done: one call, deltas not judged twice", []string{added, delta(`{"a":`), delta(`1}`), argsDone(`{"a":1}`), itemDone(`{"a":1}`), completed}, true,
			[]call{{"Bash", `{"a":1}`}}, false},
		{"args done, then completed", []string{added, delta(`{"a":`), delta(`1}`), argsDone(`{"a":1}`), completed}, true,
			[]call{{"Bash", `{"a":1}`}}, false},
		{"deltas, then completed", []string{added, delta(`{"a":`), delta(`1}`), completed}, true,
			[]call{{"Bash", `{"a":1}`}}, false},
		{"args done, then the end of the stream: judged and broken", []string{added, delta(`{"a":`), delta(`1}`), argsDone(`{"a":1}`)}, true,
			[]call{{"Bash", `{"a":1}`}}, true},
		{"deltas differ from the done text: both judged", []string{added, delta(`{"a":2}`), argsDone(`{"a":1}`), completed}, true,
			[]call{{"Bash", `{"a":2}`}, {"Bash", `{"a":1}`}}, false},
		{"deltas differ from the finished item: both judged", []string{added, delta(`{"a":2}`), itemDone(`{"a":1}`)}, true,
			[]call{{"Bash", `{"a":1}`}, {"Bash", `{"a":2}`}}, false},
		{"no added: named by the item type", []string{delta(`{"a":1}`), completed}, true,
			[]call{{"function_call", `{"a":1}`}}, false},
		{"added, nothing else, completed: judged with no arguments", []string{added, completed}, true,
			[]call{{"Bash", `{}`}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSSEToolCalls(0)
			for _, ev := range tc.events {
				s.Feed(ev)
			}
			if tc.finish {
				s.Finish()
			}
			got := take(s)
			if len(got) != len(tc.want) {
				t.Fatalf("calls = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("calls = %v, want %v", got, tc.want)
				}
			}
			if s.Broken() != tc.wantBroken {
				t.Fatalf("Broken = %v, want %v", s.Broken(), tc.wantBroken)
			}
			if s.Open() {
				t.Fatalf("an item is still open after the end")
			}
		})
	}
}

// An open item holds the stream until it is judged; the response.completed
// that ends it releases the hold.
func TestSSEToolCallsResponsesCompletedEndsTheHold(t *testing.T) {
	s := newSSEToolCalls(0)
	s.Feed(`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":"{}"}`)
	if !s.Open() {
		t.Fatal("a delta did not open the item")
	}
	s.Feed(`{"type":"response.completed","response":{"output":[]}}`)
	if s.Open() || s.Take() == nil {
		t.Fatal("response.completed did not judge and close the open item")
	}
}
