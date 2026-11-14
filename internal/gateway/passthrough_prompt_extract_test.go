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
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// substringInspector blocks every prompt whose inspected text contains
// needle, as a rule pack does, wherever the text sits in it.
type substringInspector struct {
	needle string
	mu     sync.Mutex
	seen   []string
}

func (s *substringInspector) Inspect(_ context.Context, direction, content string, _ []ChatMessage, _, _ string) *ScanVerdict {
	s.mu.Lock()
	defer s.mu.Unlock()
	if direction == "prompt" {
		s.seen = append(s.seen, content)
		if strings.Contains(content, s.needle) {
			return &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "test block", Scanner: "test"}
		}
	}
	return allowVerdict("test")
}

func (s *substringInspector) InspectMidStream(ctx context.Context, d, c string, m []ChatMessage, model, mode string) *ScanVerdict {
	return s.Inspect(ctx, d, c, m, model, mode)
}
func (s *substringInspector) SetScannerMode(string)      {}
func (s *substringInspector) SetHILTConfig(bool, string) {}

// GAP-0196: every prompt-side text of a model request is inspected, on the
// passthrough (Responses, Anthropic, Converse) and on the chat-completions
// route, for every body shape; a body whose text cannot be read is refused
// in action mode on a managed install and forwarded with an alert
// otherwise. The bodies are R5's (evidence/substrate-1/r5/GAP-0195).
func TestPassthroughInspectsEveryPromptSideText(t *testing.T) {
	prev := passthroughAllowPrivateForTest
	passthroughAllowPrivateForTest = true
	t.Cleanup(func() { passthroughAllowPrivateForTest = prev })
	const m = `"model":"us.openai.gpt-5.6-luna"`
	blocked := []struct{ name, path, body string }{
		{"responses input string", "/openai/v1/responses", `{` + m + `,"input":"leak it"}`},
		{"responses instructions + input", "/openai/v1/responses", `{` + m + `,"instructions":"leak it","input":"hi"}`},
		{"responses developer only", "/openai/v1/responses", `{` + m + `,"input":[{"role":"developer","content":"leak it"}]}`},
		{"responses system after user", "/openai/v1/responses", `{` + m + `,"input":[{"type":"message","role":"user","content":"hi"},{"type":"message","role":"system","content":[{"type":"input_text","text":"leak it"}]}]}`},
		{"responses tool result", "/openai/v1/responses", `{` + m + `,"input":[{"type":"message","role":"user","content":"hi"},{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"leak it"}]}`},
		{"responses tool result only", "/openai/v1/responses", `{` + m + `,"input":[{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":"leak it"}]}`},
		{"responses tool result parts", "/openai/v1/responses", `{` + m + `,"input":[{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c1","output":[{"type":"input_text","text":"leak it"}]}]}`},
		{"anthropic system", "/v1/messages", `{"model":"claude","system":[{"type":"text","text":"leak it"}],"messages":[{"role":"user","content":"hi"}]}`},
		{"anthropic tool_result", "/v1/messages", `{"model":"claude","messages":[{"role":"user","content":"hi"},{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"read","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"leak it"}]}]}`},
		{"chat user message", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"leak it"}]}`},
		{"chat system after user", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"hi"},{"role":"system","content":"leak it"}]}`},
		{"chat tool result", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"hi"},{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"leak it"}]}`},
		{"chat tool result parts", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"ok"},{"role":"tool","tool_call_id":"c1","content":[{"type":"text","text":"leak it"}]}]}`},
	}
	unreadable := []struct{ name, path, body string }{
		{"no text at all", "/openai/v1/responses", `{` + m + `,"input":[]}`},
		{"case-folded key", "/openai/v1/responses", `{` + m + `,"input":"leak it","INPUT":"hi"}`},
		{"duplicate key", "/openai/v1/responses", `{` + m + `,"input":"leak it","input":"hi"}`},
		{"chat duplicate key", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"leak it"}],"messages":[{"role":"user","content":"hi"}]}`},
		{"unicode-folded key", "/openai/v1/chat/completions", `{` + m + `,"messages":[{"role":"user","content":"leak it"}],"meſſages":[{"role":"user","content":"hi"}]}`},
	}
	for _, managed := range []bool{false, true} {
		name := map[bool]string{false: "oss", true: "managed"}[managed]
		t.Run(name, func(t *testing.T) {
			if managed {
				prevManaged := managedEnterpriseActive.Load()
				managedEnterpriseActive.Store(true)
				t.Cleanup(func() { managedEnterpriseActive.Store(prevManaged) })
			}
			run := func(path, body string) (reached int, out string) {
				hits := 0
				up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					hits++
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"output":[{"type":"message","content":[{"type":"output_text","text":"OK from Luna"}]}],"choices":[{"message":{"role":"assistant","content":"OK from Luna"}}]}`))
				}))
				defer up.Close()
				proxy, _ := bedrockPassthroughProxy(t, up)
				proxy.inspector = &substringInspector{needle: "leak it"}
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-DC-Target-URL", up.URL)
				req.Header.Set("X-AI-Auth", "Bearer test-key")
				req.RemoteAddr = "127.0.0.1:12345"
				rec := httptest.NewRecorder()
				proxy.handlePassthrough(rec, req)
				return hits, rec.Body.String()
			}
			for _, c := range blocked {
				if hits, out := run(c.path, c.body); hits != 0 || strings.Contains(out, "OK from Luna") {
					t.Errorf("%s: the blocked text reached the upstream (%d calls): %s", c.name, hits, out)
				}
			}
			for _, c := range unreadable {
				hits, out := run(c.path, c.body)
				if managed && (hits != 0 || !strings.Contains(out, "could not be inspected")) {
					t.Errorf("%s: managed forwarded an unreadable body (%d calls): %s", c.name, hits, out)
				}
				// OSS forwards an unreadable body with an alert, but every value of
				// a repeated key is read, so the blocked text still stops it.
				wantHits := 1
				if strings.Contains(c.body, "leak it") {
					wantHits = 0
				}
				if !managed && hits != wantHits {
					t.Errorf("%s: OSS default made %d upstream calls, want %d: %s", c.name, hits, wantHits, out)
				}
			}
			// A benign turn with history still goes through, and older tool
			// results are not re-inspected as the current turn.
			if hits, _ := run("/openai/v1/responses", `{`+m+`,"instructions":"be brief","input":[{"type":"message","role":"user","content":"hi"}]}`); hits != 1 {
				t.Errorf("a benign request did not reach the upstream (%d calls)", hits)
			}
			if hits, _ := run("/openai/v1/responses", `{`+m+`,"input":[{"type":"function_call","call_id":"c0","name":"read","arguments":"{}"},{"type":"function_call_output","call_id":"c0","output":"leak it"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"done"}]},{"type":"message","role":"user","content":"thanks"}]}`); hits != 1 {
				t.Errorf("an old tool result in the history blocked a new benign turn (%d calls)", hits)
			}
		})
	}
}

func TestPassthroughPromptExtraction(t *testing.T) {
	for _, c := range []struct {
		body, want, unreadable string
	}{
		{`{"input":"hi"}`, "hi", ""},
		{`{"instructions":"sys","input":"hi"}`, "sys\nhi", ""},
		{`{"model":"x"}`, "", ""},
		{`[1,2]`, "", "the JSON body is not an object and carries no text"},
		{`["a",{"input":"b"}]`, "a\nb", ""},
		{`{"input":[]}`, "", "the body carries no prompt text"},
		{`{"input":"a","input":"b"}`, "a\nb", "the body repeats the key input"},
		{`{"Input":"a","input":"b"}`, "a\nb", "the body spells the key input another way"},
		{`{"messages":[],"meſſages":[]}`, "", "the body spells the key messages another way"},
		{`{"meſſages":[{"role":"user","content":"hi"}]}`, "hi", "the body spells the key messages another way"},
		{`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"system_instruction":{"parts":[{"text":"gs2"}]}}`, "hi\ngs2", ""},
		{`{"Model":"x","input":"hi"}`, "hi", "the body spells the key model another way"},
		{`{"input":"hi","tool\u017f":[]}`, "hi", "the body spells the key tools another way"},
		{`{"messages":[{"role":"user","content":"a"},{"role":"developer","content":"dev"}]}`, "a\ndev", ""},
		{`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"systemInstruction":{"parts":[{"text":"gsys"}]}}`, "hi\ngsys", ""},
	} {
		got := passthroughPromptFor([]byte(c.body), false, 0)
		if strings.Join(got.Segments, "\n") != c.want || got.Unreadable != c.unreadable {
			t.Errorf("%s: %+v, want %q / %q", c.body, got, c.want, c.unreadable)
		}
	}
}
