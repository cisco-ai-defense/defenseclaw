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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sseEvents(events ...string) string {
	var b strings.Builder
	for _, e := range events {
		var head struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal([]byte(e), &head)
		if head.Type != "" {
			fmt.Fprintf(&b, "event: %s\n", head.Type)
		}
		fmt.Fprintf(&b, "data: %s\n\n", e)
	}
	return b.String()
}

// responsesToolStream is a Luna Responses stream: optional text, then one
// function_call item running command.
func responsesToolStream(text, tool, command string) string {
	args, _ := json.Marshal(map[string]string{"command": command})
	argStr, _ := json.Marshal(string(args))
	ev := []string{`{"type":"response.created","response":{"id":"resp_1","status":"in_progress","output":[]}}`}
	if text != "" {
		t, _ := json.Marshal(text)
		ev = append(ev,
			`{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
			`{"type":"response.output_text.delta","output_index":0,"item_id":"msg_1","delta":`+string(t)+`}`,
			`{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":`+string(t)+`}]}}`)
	}
	ev = append(ev,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"`+tool+`","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","output_index":1,"item_id":"fc_1","delta":`+string(argStr)+`}`,
		`{"type":"response.function_call_arguments.done","output_index":1,"item_id":"fc_1","arguments":`+string(argStr)+`}`,
		`{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"`+tool+`","arguments":`+string(argStr)+`}}`,
		`{"type":"response.completed","response":{"id":"resp_1","status":"completed"}}`)
	return sseEvents(ev...)
}

func chatToolStream(command string) string {
	args, _ := json.Marshal(map[string]string{"command": command})
	half := len(args) / 2
	a1, _ := json.Marshal(string(args[:half]))
	a2, _ := json.Marshal(string(args[half:]))
	return sseEvents(
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"bash","arguments":""}}]}}]}`,
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+string(a1)+`}}]}}]}`,
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":`+string(a2)+`}}]}}]}`,
		`{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		`[DONE]`)
}

func TestSSEToolCallsCollectsResponsesAndChatCalls(t *testing.T) {
	s := newSSEToolCalls()
	for _, line := range strings.Split(responsesToolStream("hi", "shell", "ls -la"), "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			s.Feed(d)
			if strings.Contains(d, `"response.function_call_arguments.delta"`) && !s.Open() {
				t.Fatal("an open function_call is not held")
			}
		}
	}
	var calls []sseToolCall
	if err := json.Unmarshal(s.Take(), &calls); err != nil || len(calls) != 1 || calls[0].Function.Name != "shell" ||
		calls[0].Function.Arguments != `{"command":"ls -la"}` || calls[0].Type != "function" || s.Open() || s.Broken() {
		t.Fatalf("responses calls %+v %v", calls, err)
	}
	if s.Take() != nil {
		t.Fatal("a call was returned twice")
	}

	c := newSSEToolCalls()
	for _, line := range strings.Split(chatToolStream("rm -rf /"), "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			c.Feed(d)
		}
	}
	calls = nil
	if err := json.Unmarshal(c.Take(), &calls); err != nil || len(calls) != 1 || calls[0].Function.Name != "bash" || calls[0].Function.Arguments != `{"command":"rm -rf /"}` {
		t.Fatalf("chat calls %+v %v", calls, err)
	}

	// Custom and local shell tools are calls too; a stream cut inside a call
	// cannot be inspected.
	x := newSSEToolCalls()
	x.Feed(`{"type":"response.output_item.done","item":{"id":"ct","type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch"}}`)
	x.Feed(`{"type":"response.output_item.done","item":{"id":"ls","type":"local_shell_call","action":{"type":"exec","command":["rm","-rf","/"]}}}`)
	calls = nil
	if err := json.Unmarshal(x.Take(), &calls); err != nil || len(calls) != 2 || calls[0].Function.Arguments != "*** Begin Patch" ||
		calls[1].Function.Name != "local_shell" || !strings.Contains(calls[1].Function.Arguments, `"rm"`) {
		t.Fatalf("custom/local calls %+v %v", calls, err)
	}
	x.Feed(`{"type":"response.output_item.added","item":{"id":"fc","type":"function_call","name":"shell"}}`)
	x.Finish()
	if !x.Broken() {
		t.Fatal("a stream cut inside a call is not broken")
	}
	big := newSSEToolCalls()
	big.Feed(`{"type":"response.output_item.added","item":{"id":"fc","type":"function_call","name":"shell"}}`)
	d, _ := json.Marshal(strings.Repeat("a", sseToolCallMax+1))
	big.Feed(`{"type":"response.function_call_arguments.delta","delta":` + string(d) + `}`)
	if !big.Broken() {
		t.Fatal("an oversized call is not broken")
	}
}

func lunaPassthroughRequest(target, path string, stream bool) *http.Request {
	body := fmt.Sprintf(`{"model":"us.openai.gpt-5.6-luna","input":"list files","messages":[{"role":"user","content":"list files"}],"stream":%v}`, stream)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DC-Target-URL", target)
	req.Header.Set("X-AI-Auth", "Bearer test-key")
	req.RemoteAddr = "127.0.0.1:12345"
	return req
}

func sseUpstream(t *testing.T, ctype, reply string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// GAP-0187: a Luna reply on Bedrock Runtime's OpenAI-compatible API whose
// tool call the rules block is stopped by the proxy, streamed (Responses
// and Chat Completions SSE, before and after the first bytes went out) or
// not; an allowed call passes unchanged.
func TestPassthroughBlocksStreamedToolCalls(t *testing.T) {
	const blocked = "rm -rf /"
	// Chat Completions goes through handleChatCompletion, whose SSRF guard
	// refuses the loopback fake upstream.
	prev := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = prev })
	probe, _ := bedrockPassthroughProxy(t, sseUpstream(t, "application/json", "{}"))
	if v := probe.inspectToolCalls(context.Background(), json.RawMessage(`[{"type":"function","function":{"name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}}]`)); v == nil || v.Action != "block" {
		t.Fatalf("the rules do not block %q: %+v", blocked, v)
	}
	long := strings.Repeat("Listing the files now. ", 80) // past the stream buffer: the first bytes are sent
	for _, c := range []struct {
		name, path, ctype, reply string
		stream                   bool
	}{
		{"responses stream", "/openai/v1/responses", "text/event-stream", responsesToolStream("", "bash", blocked), true},
		{"responses stream after text", "/openai/v1/responses", "text/event-stream", responsesToolStream(long, "bash", blocked), true},
		{"chat stream", "/openai/v1/chat/completions", "text/event-stream", chatToolStream(blocked), true},
		{"responses body", "/openai/v1/responses", "application/json",
			`{"id":"resp_1","object":"response","status":"completed","output":[{"type":"function_call","call_id":"c1","name":"bash","arguments":"{\"command\":\"rm -rf /\"}"}]}`, false},
	} {
		up := sseUpstream(t, c.ctype, c.reply)
		proxy, insp := bedrockPassthroughProxy(t, up)
		insp.setVerdict("completion", allowVerdict("mock"))
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, lunaPassthroughRequest(up.URL, c.path, c.stream))
		out := rec.Body.String()
		if strings.Contains(out, `rm -rf`) || strings.Contains(out, `"call_1"`) {
			t.Errorf("%s: the blocked call reached the agent:\n%s", c.name, out)
		}
		if !strings.Contains(strings.ToLower(out), "block") {
			t.Errorf("%s: no block the agent can show:\n%s", c.name, out)
		}
		if c.stream && c.path == "/openai/v1/responses" && !strings.Contains(out, "response.completed") {
			t.Errorf("%s: the stream does not end:\n%s", c.name, out)
		}
	}

	// Allowed: the stream reaches the agent byte for byte.
	for _, reply := range []string{responsesToolStream("ok", "bash", "ls -la"), responsesToolStream(long, "bash", "ls -la")} {
		up := sseUpstream(t, "text/event-stream", reply)
		proxy, insp := bedrockPassthroughProxy(t, up)
		insp.setVerdict("completion", allowVerdict("mock"))
		rec := httptest.NewRecorder()
		proxy.handlePassthrough(rec, lunaPassthroughRequest(up.URL, "/openai/v1/responses", true))
		if rec.Body.String() != reply {
			t.Fatalf("allowed stream changed (%d of %d bytes):\n%s", rec.Body.Len(), len(reply), rec.Body)
		}
	}
}

// The reply text of Bedrock's OpenAI-compatible API is read in the OpenAI
// shape (it was read as Converse and came out empty).
func TestPassthroughInspectsBedrockOpenAIReplyText(t *testing.T) {
	if got := passthroughWireProvider("bedrock", "/openai/v1/responses"); got != "openai" {
		t.Fatalf("wire %q", got)
	}
	if got := passthroughWireProvider("bedrock", "/model/x/converse"); got != "bedrock" {
		t.Fatalf("wire %q", got)
	}
	up := sseUpstream(t, "application/json", `{"output":[{"type":"message","content":[{"type":"output_text","text":"the vault code is 4242"}]}]}`)
	proxy, insp := bedrockPassthroughProxy(t, up)
	insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
	rec := httptest.NewRecorder()
	proxy.handlePassthrough(rec, lunaPassthroughRequest(up.URL, "/openai/v1/responses", false))
	if strings.Contains(rec.Body.String(), "4242") {
		t.Fatalf("a blocked reply text reached the agent: %s", rec.Body)
	}
	up = sseUpstream(t, "text/event-stream", sseEvents(`{"type":"response.output_text.delta","delta":"the vault code is 4242"}`,
		`{"type":"response.completed","response":{"status":"completed"}}`))
	proxy, insp = bedrockPassthroughProxy(t, up)
	insp.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test secret"})
	rec = httptest.NewRecorder()
	proxy.handlePassthrough(rec, lunaPassthroughRequest(up.URL, "/openai/v1/responses", true))
	if strings.Contains(rec.Body.String(), "4242") {
		t.Fatalf("a blocked streamed text reached the agent: %s", rec.Body)
	}
}
