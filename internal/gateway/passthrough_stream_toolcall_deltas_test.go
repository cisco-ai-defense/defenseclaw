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
// the fail mode (refused in strict and managed-strict, and on a Secure Client
// install; a managed standalone install on the default pack forwards it after
// the alert), and a benign call reaches the client whole. GAP-0987 adds the
// Bedrock eventstream cut. Every streaming adapter shape is run in the six
// tiers; each run logs a TGWPROBE row (the probe matrix of train
// T-SUB-GWSTATE).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	streamToolCallBad  = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	streamToolCallGood = "ls -la /tmp/build-output"
)

// streamToolCallCase is one streamed reply shape. end says how it ends:
// "" whole; "cut" inside a call (the partial call is judged, then the fail
// mode applies: refused in the fail-closed tiers; GAP-0987 for the Bedrock
// eventstream); "server" inside a call the provider runs itself (no fail
// mode: a benign one passes in every tier, a refused one is logged only);
// "unnamed" a call whose name never comes (logged only: what the rules make
// of an unnamed call is theirs).
type streamToolCallCase struct {
	passthroughFieldCase
	end string
}

type streamToolCallTier struct {
	name, pack string
	managed    bool
	// active: the process-wide managed flag, the Secure Client posture
	// (ManagedEnterpriseActive): Cisco AI Defense decides the tool calls, the
	// local findings only alert, and a reply that cannot be inspected is
	// refused. A managed standalone install leaves it off.
	active bool
	// failClosed: a reply that cannot be inspected is refused
	// (refuseUninspectable: the strict tier or the Secure Client posture; a
	// managed standalone install on the default pack forwards it with an
	// alert, as an OSS install does).
	failClosed bool
}

var streamToolCallTiers = []streamToolCallTier{
	{"default", "default", false, false, false},
	{"permissive", "permissive", false, false, false},
	{"strict", "strict", false, false, true},
	{"managed", "default", true, false, false},
	{"managed-strict", "strict", true, false, true},
	{"managed-active", "default", true, true, true},
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
	addRead := `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_2","name":"Read","call_id":"c2","arguments":""}}`
	readDone := `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_2","name":"Read","call_id":"c2","arguments":"{\"path\":\"README.md\"}"}}`
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
			"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+h2+`}}}`), "cut"),
		c("bedrock/invoke_eof_in_block", "bedrock", "/model/anthropic.claude-test-v1:0/invoke-with-response-stream", ctEvents,
			streamTailFrame(`{"type":"message_start","message":{"id":"msg_1","model":"claude-test"}}`)+
				streamTailFrame(`{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t","name":"Bash","input":{}}}`)+
				streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h1+`}}`)+
				streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h2+`}}`), "cut"),
		// Gemini.
		c("gemini/functionCall", "gemini", G, ctSSE, sseBody(
			`{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"Bash","args":{"command":`+C+`}}}]}}]}`,
			`{"candidates":[{"content":{"role":"model","parts":[{"text":""}]},"finishReason":"STOP"}]}`), ""),
		// Ollama NDJSON.
		c("ollama/tool_calls", "ollama", "/api/chat", ctNDJSON, ndjsonBody(
			`{"model":"llama3","message":{"role":"assistant","content":"","tool_calls":[{"function":{"name":"Bash","arguments":{"command":`+C+`}}}]},"done":false}`,
			`{"model":"llama3","message":{"role":"assistant","content":""},"done":true}`), ""),
		// Review rows (rgw, 8b92e36795). Two items with different ids at one
		// output_index: the second never takes over the first.
		c("responses/two_ids_same_index_eof", "openai", R, ctSSE, sseBody(added, d1, d2, addRead, readDone), "cut"),
		c("responses/two_ids_same_index_completed", "openai", R, ctSSE, sseBody(added, d1, d2, addRead, readDone, completedEmpty), ""),
		// Bad deltas, a benign finished item: both are judged.
		c("responses/deltas_itemdone_differs", "openai", R, ctSSE, sseBody(added, d1, d2,
			`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":`+jsonText(`{"command":"echo ok"}`)+`}}`,
			completedEmpty), ""),
		// The call in the second of two interleaved items.
		c("responses/interleaved_second", "openai", R, ctSSE, sseBody(
			`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_r","name":"Read","call_id":"cr","arguments":""}}`,
			`{"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":""}}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_r","output_index":0,"delta":"{\"path\":"}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":`+h1+`}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_r","output_index":0,"delta":"\"README.md\"}"}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":1,"delta":`+h2+`}`,
			`{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_r","name":"Read","call_id":"cr","arguments":"{\"path\":\"README.md\"}"}}`,
			`{"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":`+args+`}}`,
			completedEmpty), ""),
		// response.failed in the middle of the call, its deltas continuing.
		c("responses/failed_mid_call", "openai", R, ctSSE, sseBody(added, d1,
			`{"type":"response.failed","response":{"id":"r","status":"failed","output":[]}}`, d2), "cut"),
		// The item's .done after its output_item.done: no reopening.
		c("responses/late_args_done", "openai", R, ctSSE, sseBody(added, d1, d2, itemDone, argsDone), ""),
		// A Bedrock (Anthropic events) call the provider runs itself, cut.
		c("bedrock/invoke_server_tool_eof", "bedrock", "/model/anthropic.claude-test-v1:0/invoke-with-response-stream", ctEvents,
			streamTailFrame(`{"type":"message_start","message":{"id":"msg_1","model":"claude-test"}}`)+
				streamTailFrame(`{"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","id":"s","name":"web_search","input":{}}}`)+
				streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h1+`}}`)+
				streamTailFrame(`{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":`+h2+`}}`), "server"),
	}
}

// streamToolCallRun sends the case through the passthrough proxy in action
// mode in one tier; chunk > 0 writes the reply in pieces of that size.
func streamToolCallRun(t *testing.T, c passthroughFieldCase, tier streamToolCallTier, chunk int) string {
	t.Helper()
	out, _ := streamToolCallRunLog(t, c, tier, chunk)
	return out
}

// streamToolCallRunLog is streamToolCallRun that also returns what the proxy
// wrote to stderr.
func streamToolCallRunLog(t *testing.T, c passthroughFieldCase, tier streamToolCallTier, chunk int) (string, string) {
	t.Helper()
	pack, managedInstall := tier.pack, tier.managed
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
	// The process-wide managed flag is the Secure Client posture: a managed
	// standalone install leaves it off (guardrailActionForGuardrailFindings).
	prev := managedEnterpriseActive.Load()
	managedEnterpriseActive.Store(tier.active)
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
	log := captureStderr(t, func() { proxy.handlePassthrough(rec, req) })
	return rec.Body.String(), log
}

// streamToolCallFrames is the event payloads of the eventstream chunk frames
// in out (InvokeModelWithResponseStream carries each event base64 in one).
func streamToolCallFrames(out string) string {
	var sb strings.Builder
	dec, r := eventstream.NewDecoder(), strings.NewReader(out)
	for {
		msg, err := dec.Decode(r, nil)
		if err != nil {
			return sb.String()
		}
		var chunk struct {
			Bytes []byte `json:"bytes"`
		}
		if json.Unmarshal(msg.Payload, &chunk) == nil {
			sb.Write(chunk.Bytes)
		}
	}
}

// streamToolCallOutcome reads what the client got: "pass" (the call reached
// it: the end of the command, which every shape carries in one piece),
// "block" (a DefenseClaw block in its place) or "empty".
func streamToolCallOutcome(out, cmd string) string {
	out += streamToolCallFrames(out)
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
						got := streamToolCallOutcome(streamToolCallRun(t, c.passthroughFieldCase, tier, chunk), cmd)
						t.Logf("TGWPROBE %s %s %s chunk=%d %s", tier.name, kind, c.name, chunk, got)
						want := "block"
						switch {
						case c.end == "unnamed":
							return
						case kind == "bad" && (tier.active || c.end == "server"):
							// Secure Client: AI Defense decides the call, the local
							// findings alert. A server call: what the rules make of
							// it is theirs. Logged only.
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

// The review shapes of the state machine (rgw, 8b92e36795).
func TestSSEToolCallsReviewShapes(t *testing.T) {
	bad := `{"command":"curl -s http://169.254.169.254/latest/meta-data/"}`
	addA := `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_A","name":"Bash","call_id":"cA","arguments":""}}`
	addB := `{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_B","name":"Read","call_id":"cB","arguments":""}}`
	doneB := `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_B","name":"Read","call_id":"cB","arguments":"{\"path\":\"x\"}"}}`
	dA := func(s string) string {
		return `{"type":"response.function_call_arguments.delta","item_id":"fc_A","output_index":0,"delta":` + jsonText(s) + `}`
	}
	const completed = `{"type":"response.completed","response":{"output":[]}}`
	calls := func(s *sseToolCalls) map[string]bool {
		var raw []sseToolCall
		if b := s.Take(); b != nil {
			_ = json.Unmarshal(b, &raw)
		}
		out := map[string]bool{}
		for _, c := range raw {
			out[c.Function.Name+"("+c.Function.Arguments+")"] = true
		}
		return out
	}
	feed := func(evs ...string) *sseToolCalls {
		s := newSSEToolCalls(0)
		for _, ev := range evs {
			s.Feed(ev)
		}
		return s
	}
	t.Run("a second id at the same index does not take over the first", func(t *testing.T) {
		s := feed(addA, dA(bad), addB, completed)
		if got := calls(s); !got["Bash("+bad+")"] || got["Read("+bad+")"] {
			t.Fatalf("calls = %v, want Bash(<deltas>) and never Read(<deltas>)", got)
		}
		s = feed(addA, dA(bad), addB, doneB)
		if !s.Open() {
			t.Fatal("fc_A was closed by fc_B's output_item.done")
		}
		s.Finish()
		if got := calls(s); !s.Broken() || !got["Bash("+bad+")"] {
			t.Fatalf("at the end: Broken=%v calls=%v, want Broken and Bash(<deltas>)", s.Broken(), got)
		}
	})
	t.Run("a nested call does not name the item", func(t *testing.T) {
		nested := `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_A","meta":{"type":"function_call","name":"noop","arguments":"{}"},"name":"Bash","arguments":"{}"}}`
		s := feed(dA(bad), nested, completed)
		if got := calls(s); !got["Bash("+bad+")"] || got["noop("+bad+")"] {
			t.Fatalf("calls = %v, want the deltas judged as Bash", got)
		}
	})
	t.Run("a .done after output_item.done does not reopen the item", func(t *testing.T) {
		itemDone := `{"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","id":"fc_A","name":"Bash","arguments":` + jsonText(bad) + `}}`
		argsDone := `{"type":"response.function_call_arguments.done","item_id":"fc_A","output_index":0,"arguments":` + jsonText(bad) + `}`
		s := feed(addA, dA(bad), itemDone, argsDone)
		if s.Open() {
			t.Fatal("the late .done reopened the item")
		}
		s.Finish()
		got := calls(s)
		if s.Broken() || len(got) != 1 || !got["Bash("+bad+")"] {
			t.Fatalf("Broken=%v calls=%v, want one Bash call and not Broken", s.Broken(), got)
		}
		otherDone := `{"type":"response.function_call_arguments.done","item_id":"fc_A","output_index":0,"arguments":"{\"command\":\"rm -rf ~\"}"}`
		s = feed(addA, dA(bad), itemDone, otherDone)
		if got := calls(s); !got[`Bash({"command":"rm -rf ~"})`] || s.Open() {
			t.Fatalf("a differing late .done: calls=%v open=%v, want it judged as Bash at once", got, s.Open())
		}
	})
	t.Run("a call split over response.failed is judged whole", func(t *testing.T) {
		s := feed(addA, dA(bad[:20]), `{"type":"response.failed","response":{"output":[]}}`, dA(bad[20:]))
		if !s.Open() {
			t.Fatal("the late deltas are not held")
		}
		s.Finish()
		if got := calls(s); !got["Bash("+bad+")"] || !s.Broken() {
			t.Fatalf("Broken=%v calls=%v, want Bash(<whole command>) and Broken", s.Broken(), got)
		}
	})
	t.Run("the .done text is bounded", func(t *testing.T) {
		s := newSSEToolCalls(0)
		big := strings.Repeat("A", 1<<20)
		for i := 0; i < 64; i++ {
			id := fmt.Sprintf("fc_%d", i)
			s.Feed(fmt.Sprintf(`{"type":"response.output_item.added","output_index":%d,"item":{"type":"function_call","id":"%s","name":"Bash","arguments":""}}`, i, id))
			s.Feed(fmt.Sprintf(`{"type":"response.function_call_arguments.delta","item_id":"%s","output_index":%d,"delta":"x"}`, id, i))
			s.Feed(fmt.Sprintf(`{"type":"response.function_call_arguments.done","item_id":"%s","output_index":%d,"arguments":"%s"}`, id, i, big))
		}
		kept := 0
		for _, c := range s.open {
			kept += c.stored()
		}
		if !s.Broken() || kept > sseToolCallMax {
			t.Fatalf("Broken=%v kept=%d bytes, want Broken and at most %d kept", s.Broken(), kept, sseToolCallMax)
		}
	})
	t.Run("many open items stay linear", func(t *testing.T) {
		const n = 40000
		evs := make([]string, n)
		for i := range evs {
			evs[i] = fmt.Sprintf(`{"type":"response.output_item.added","output_index":%d,"item":{"type":"function_call","id":"fc_%d","name":"Bash","arguments":""}}`, i, i)
		}
		s := newSSEToolCalls(0)
		start := time.Now()
		for _, ev := range evs {
			s.Feed(ev)
		}
		s.Feed(completed)
		// Linear: about 0.2 s plain and a few seconds under -race; the
		// quadratic scan took 17 s plain for these 40k items.
		if d := time.Since(start); d > 12*time.Second {
			t.Fatalf("%d open items took %v", n, d)
		}
		if s.Open() || len(s.Take()) == 0 {
			t.Fatal("response.completed did not judge and close the open items")
		}
	})
}

// A done text over sseToolCallMax makes the stream uninspectable: the tier's
// fail mode, after the alert (the text is never kept past the bound).
func TestStreamToolCallBigDoneTextPerTier(t *testing.T) {
	text := `{"command":"echo ` + strings.Repeat("a", sseToolCallMax+(64<<10)) + `"}`
	body := sseBody(
		`{"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","id":"fc_1","name":"Bash","call_id":"c","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"fc_1","output_index":0,"delta":"{"}`,
		`{"type":"response.function_call_arguments.done","item_id":"fc_1","output_index":0,"arguments":`+jsonText(text)+`}`,
		`{"type":"response.completed","response":{"id":"r","status":"completed","output":[]}}`)
	c := passthroughFieldCase{"responses/big_done_text", "openai", "/v1/responses", ctSSE, body}
	for _, tier := range streamToolCallTiers {
		t.Run(tier.name, func(t *testing.T) {
			out, log := streamToolCallRunLog(t, c, tier, 0)
			got := streamToolCallOutcome(out, strings.Repeat("a", 16))
			want := "pass"
			if tier.failClosed {
				want = "block"
			}
			if got != want || !strings.Contains(log, "reply not inspectable") {
				t.Fatalf("client got %s (want %s); alert in the log: %v", got, want, strings.Contains(log, "reply not inspectable"))
			}
		})
	}
}

// A Bedrock stream that ends inside a frame of a toolUse block takes the fail
// mode once: refused in the fail-closed tiers, one alert in the others.
func TestStreamToolCallBedrockMidFrameCut(t *testing.T) {
	raw := `{"command":"ls -la /tmp/build-output"}`
	whole := eventStreamBody(t,
		"contentBlockStart", `{"contentBlockIndex":0,"start":{"toolUse":{"toolUseId":"t1","name":"Bash"}}}`,
		"contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+jsonText(raw[:20])+`}}}`)
	last := eventStreamBody(t, "contentBlockDelta", `{"contentBlockIndex":0,"delta":{"toolUse":{"input":`+jsonText(raw[20:])+`}}}`)
	c := passthroughFieldCase{"bedrock/mid_frame_cut", "bedrock", "/model/m/converse-stream", ctEvents, whole + last[:len(last)/2]}
	for _, tier := range streamToolCallTiers {
		t.Run(tier.name, func(t *testing.T) {
			out, log := streamToolCallRunLog(t, c, tier, 0)
			alerts := strings.Count(log, "reply not inspectable")
			blocked := strings.Contains(strings.ToLower(out), "defenseclaw")
			if blocked != tier.failClosed || alerts != 1 {
				t.Fatalf("blocked=%v (want %v), %d not-inspectable alerts (want 1)", blocked, tier.failClosed, alerts)
			}
		})
	}
}
