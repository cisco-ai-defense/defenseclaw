// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

const (
	noticeChatReply = `{"choices":[{"index":0,"message":{"role":"assistant","content":"ordinary reply"}}]}`
	noticeJSONType  = "application/json"
)

// noticeChatReqFor is a Chat Completions request that carries the tool result
// of the call with the given id.
func noticeChatReqFor(id string) string {
	return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"DefenseClaw: blocked"}]}`
}

// noticeChatReq carries the result of the blocked call of the fixtures.
func noticeChatReq() string { return noticeChatReqFor(noticeTestCallID) }

func noticeServed(out string) bool { return strings.Count(out, "Tool call blocked") == 1 }

// GAP-0644: a notice belongs to the OpenClaw request that carries its block.
func TestGAP0644OtherConnectorNeverTakesTheNotice(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    noticeServe
	}{
		{"prefixed", noticeServe{viaPrefix: true, path: "/c/claudecode/v1/chat/completions"}},
		{"unprefixed, another connector active", noticeServe{path: "/v1/messages", active: "claudecode"}},
		{"unprefixed, active connector unknown", noticeServe{path: "/v1/messages", active: "-"}},
		{"prefixed other, openclaw active", noticeServe{viaPrefix: true, path: "/c/codex/v1/chat/completions"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "r")
			o := tc.o
			o.reqBody, o.ctype, o.respBody = noticeChatReq(), noticeJSONType, noticeChatReply
			out, _ := serveNoticeWith(t, o)
			if out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("another connector took or showed the OpenClaw notice: %s", out)
			}
		})
	}
	// The benign twin: OpenClaw own routes, with and without a connector prefix.
	for _, path := range []string{"/v1/chat/completions", "/c/openclaw/v1/chat/completions"} {
		resetOpenClawBlockNotices(t)
		rememberTestNotice("exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{viaPrefix: true, path: path,
			reqBody: noticeChatReq(), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) {
			t.Fatalf("%s: notice missing: %s", path, out)
		}
	}
}

func TestGAP0644UnauthorizedRequestNeverTakesTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberTestNotice("exec", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{deny: true, reqBody: noticeChatReq(), ctype: noticeJSONType, respBody: noticeChatReply})
	if out != noticeChatReply || !openClawBlockNoticesPending() {
		t.Fatalf("a request without the owner credential took the notice: %s", out)
	}
}

// The call id counts only on a tool-result message. The same token in text a
// user or the model wrote, a system prompt, the call itself, a tool definition
// or any other field takes nothing and leaves the notice for the real result,
// in every provider shape.
func TestGAP0644CallIDOutsideAToolResultTakesNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberTestNotice("exec", []string{noticeTestRule}, "r")
	const id = noticeTestCallID
	outside := []struct{ name, body string }{
		{"chat user text", `{"messages":[{"role":"user","content":"summarize ID"},{"role":"tool","tool_call_id":"ok","content":"ordinary output"}]}`},
		{"chat user parts", `{"messages":[{"role":"user","content":[{"type":"text","text":"ID"}]}]}`},
		{"chat assistant text", `{"messages":[{"role":"assistant","content":"the id was ID"},{"role":"tool","tool_call_id":"ok","content":"fine"}]}`},
		{"chat system", `{"messages":[{"role":"system","content":"ID"},{"role":"user","content":"hi"}]}`},
		{"chat tool call", `{"messages":[{"role":"assistant","tool_calls":[{"id":"ID","function":{"name":"exec","arguments":"{\"x\":\"ID\"}"}}]}]}`},
		{"chat result content", `{"messages":[{"role":"tool","tool_call_id":"ok","content":"ID"}]}`},
		{"responses user message", `{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"ID"}]},{"type":"function_call_output","call_id":"ok","output":"fine"}]}`},
		{"responses call", `{"input":[{"type":"function_call","call_id":"ID","name":"exec","arguments":"{}"}]}`},
		{"responses instructions", `{"instructions":"ID","input":"hi"}`},
		{"responses result output", `{"input":[{"type":"function_call_output","call_id":"ok","output":"ID"}]}`},
		{"anthropic user text", `{"system":"ID","messages":[{"role":"user","content":[{"type":"text","text":"ID"},{"type":"tool_result","tool_use_id":"ok","content":"fine"}]}]}`},
		{"anthropic call", `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"ID","name":"exec","input":{}}]}]}`},
		{"bedrock user text", `{"messages":[{"role":"user","content":[{"text":"ID"},{"toolResult":{"toolUseId":"ok","content":[{"text":"fine"}]}}]}]}`},
		{"bedrock call", `{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"ID","name":"exec","input":{}}}]}]}`},
		{"gemini user text", `{"contents":[{"role":"user","parts":[{"text":"ID"}]},{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"ok":true}}}]}]}`},
		{"gemini call", `{"contents":[{"role":"model","parts":[{"functionCall":{"id":"ID","name":"exec","args":{}}}]}]}`},
		{"gemini system", `{"systemInstruction":{"parts":[{"text":"ID"}]},"contents":[]}`},
		{"ollama user text", `{"messages":[{"role":"user","content":"ID"},{"role":"tool","tool_name":"exec","content":"fine"}]}`},
		{"not json", "tool result ID"},
	}
	for _, c := range outside {
		out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.body, "ID", id), ctype: noticeJSONType, respBody: noticeChatReply})
		if out != noticeChatReply || !openClawBlockNoticesPending() {
			t.Fatalf("%s: a call id outside a tool-result message took the notice: %s", c.name, out)
		}
	}
	// The real result still takes it, once.
	out, _ := serveNoticeWith(t, noticeServe{reqBody: noticeChatReq(), ctype: noticeJSONType, respBody: noticeChatReply})
	if !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the blocked result did not show the notice: %s", out)
	}
}

// The id on the result message of each provider shape is the block, even when
// the result nests its content (an array of parts, a structured response).
func TestGAP0644CallIDInsideEveryResultShapeTakesTheNotice(t *testing.T) {
	shapes := []struct{ name, body string }{
		{"chat string", `{"messages":[{"role":"tool","tool_call_id":"ID","content":"DefenseClaw: blocked"}]}`},
		{"chat parts", `{"messages":[{"role":"tool","tool_call_id":"ID","content":[{"type":"text","text":"DefenseClaw: blocked"}]}]}`},
		{"chat no content", `{"messages":[{"role":"tool","tool_call_id":"ID"}]}`},
		{"chat function role", `{"messages":[{"role":"function","tool_call_id":"ID","name":"exec","content":"DefenseClaw: blocked"}]}`},
		{"responses output string", `{"input":[{"type":"function_call_output","call_id":"ID","output":"DefenseClaw: blocked"}]}`},
		{"responses output parts", `{"input":[{"type":"function_call_output","call_id":"ID","output":[{"type":"input_text","text":"DefenseClaw: blocked"}]}]}`},
		{"anthropic parts", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"ID","content":[{"type":"text","text":"DefenseClaw: blocked"}]}]}]}`},
		{"bedrock", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"ID","content":[{"text":"DefenseClaw: blocked"}]}}]}]}`},
		{"gemini structured", `{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"ID","name":"exec","response":{"error":{"message":"DefenseClaw: blocked"}}}}]}]}`},
		{"ollama with call id", `{"messages":[{"role":"tool","tool_call_id":"ID","tool_name":"exec","content":"DefenseClaw: blocked"}]}`},
	}
	for _, c := range shapes {
		resetOpenClawBlockNotices(t)
		rememberTestNotice("exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.body, "ID", noticeTestCallID), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) || openClawBlockNoticesPending() {
			t.Errorf("%s: the blocked result did not take the notice once: %s", c.name, out)
		}
	}
}

// Results that name no call id cannot be keyed: the notice stays pending, even
// when the result is of the blocked tool or quotes the block text.
func TestGAP0644ResultWithoutACallIDTakesNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberTestNotice("exec", []string{noticeTestRule}, "r")
	for name, body := range map[string]string{
		"gemini result of the same tool": `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"DefenseClaw: blocked"}}}]}]}`,
		"ollama result of the same tool": `{"messages":[{"role":"tool","tool_name":"exec","content":"DefenseClaw: blocked"}]}`,
		"chat result naming the tool":    `{"messages":[{"role":"tool","name":"exec","content":"DefenseClaw: blocked"}]}`,
		"chat result id is the tool":     `{"messages":[{"role":"tool","tool_call_id":"exec","name":"exec","content":"fine"}]}`,
	} {
		if out, _ := serveNoticeWith(t, noticeServe{reqBody: body, ctype: noticeJSONType, respBody: noticeChatReply}); out != noticeChatReply {
			t.Fatalf("%s took a notice: %s", name, out)
		}
	}
	if !openClawBlockNoticesPending() {
		t.Fatal("a request without a call id used up the notice")
	}
	if out, _ := serveNoticeWith(t, noticeServe{reqBody: noticeChatReq(), ctype: noticeJSONType, respBody: noticeChatReply}); !noticeServed(out) {
		t.Fatalf("the blocked result did not show the notice: %s", out)
	}
}

// Two blocks wait: a request that carries one call id takes that block only.
func TestGAP0644RequestTakesOnlyItsOwnBlock(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_a", noticeTestSession, []string{noticeTestRule}, "r")
	rememberOpenClawBlockNotice("read", "call_b", noticeTestSession, []string{noticeTestRule}, "r")
	if out, _ := serveNoticeWith(t, noticeServe{reqBody: noticeChatReqFor("call_b"), ctype: noticeJSONType, respBody: noticeChatReply}); !strings.Contains(out, "Tool call blocked: read") || strings.Contains(out, "exec") {
		t.Fatalf("the read block did not show alone: %s", out)
	}
	if out, _ := serveNoticeWith(t, noticeServe{reqBody: noticeChatReqFor("call_a"), ctype: noticeJSONType, respBody: noticeChatReply}); !strings.Contains(out, "Tool call blocked: exec") {
		t.Fatalf("the exec block did not show: %s", out)
	}
}

// GAP-0644 M4: an unmatched notice stops costing requests once it expires.
func TestGAP0644ExpiredNoticeIsNoLongerPending(t *testing.T) {
	resetOpenClawBlockNotices(t)
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.entries = []openClawBlockNotice{{callID: "call_old", line: "old", at: time.Now().Add(-3 * time.Minute)}}
	openClawBlockNotices.mu.Unlock()
	if openClawBlockNoticesPending() {
		t.Fatal("an expired notice still makes every POST take the buffered path")
	}
	openClawBlockNotices.mu.Lock()
	n := len(openClawBlockNotices.entries)
	openClawBlockNotices.mu.Unlock()
	if n != 0 {
		t.Fatalf("expired notice kept: %d", n)
	}
	// A live notice is still pending.
	rememberTestNotice("exec", nil, "r")
	if !openClawBlockNoticesPending() {
		t.Fatal("a live notice is not pending")
	}
}

// GAP-0644 M3: a reply DefenseClaw wrote keeps its banner prefix, so history
// laundering still drops it; the notice waits for a real reply.
func TestGAP0644SyntheticBlockReplyIsNotPrefixed(t *testing.T) {
	synth := "[DefenseClaw] The model response was blocked due to a potential security concern."
	synthJSON := `{"choices":[{"message":{"role":"assistant","content":"` + synth + `"}}]}`
	synthSSE := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"" + synth + "\"}}]}\n\ndata: [DONE]\n\n"
	for _, tc := range []struct{ name, ctype, body string }{{"json", noticeJSONType, synthJSON}, {"sse", "text/event-stream", synthSSE}} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "r")
			req := noticeChatReq()
			out, _ := serveNotice(t, req, tc.ctype, tc.body, 0)
			if out != tc.body || !openClawBlockNoticesPending() {
				t.Fatalf("synthetic reply was prefixed or used the notice: %s", out)
			}
			history, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": synth}}})
			if _, stripped, err := launderChatCompletionsHistory(history); err != nil || stripped != 1 {
				t.Fatalf("synthetic reply survived laundering: stripped=%d err=%v", stripped, err)
			}
			// The notice lands on the next real reply.
			if out, _ := serveNotice(t, req, noticeJSONType, noticeChatReply, 0); !noticeServed(out) {
				t.Fatalf("notice lost after a synthetic reply: %s", out)
			}
		})
	}
}

// GAP-0644 M5: the operator log reveal flag never reaches a model reply.
func TestGAP0644NoticeLineIgnoresTheLogRevealFlag(t *testing.T) {
	const reason = "matched: sensitive-canary-payload"
	plain := openClawBlockNoticeLine("exec", []string{noticeTestRule}, reason)
	t.Setenv("DEFENSECLAW_REVEAL_PII", "1")
	revealed := openClawBlockNoticeLine("exec", []string{noticeTestRule}, reason)
	if strings.Contains(revealed, "sensitive-canary-payload") || revealed != plain {
		t.Fatalf("reveal flag changed the model reply line: %q vs %q", revealed, plain)
	}
	if !strings.Contains(revealed, "(rule "+noticeTestRule+")") {
		t.Fatalf("rule id lost: %q", revealed)
	}
}

func bedrockStream(t *testing.T, texts ...string) string {
	t.Helper()
	var b bytes.Buffer
	if err := writeBedrockEventStreamFrame(&b, "messageStart", map[string]any{"role": "assistant"}); err != nil {
		t.Fatal(err)
	}
	for _, text := range texts {
		if err := writeBedrockEventStreamFrame(&b, "contentBlockDelta", map[string]any{"contentBlockIndex": 0, "delta": map[string]any{"text": text}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, typ := range []string{"contentBlockStop", "messageStop"} {
		if err := writeBedrockEventStreamFrame(&b, typ, map[string]any{"contentBlockIndex": 0}); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

func bedrockStreamText(t *testing.T, raw string) (string, []string) {
	t.Helper()
	r := bytes.NewReader([]byte(raw))
	dec := eventstream.NewDecoder()
	var text strings.Builder
	var types []string
	for r.Len() > 0 {
		m, err := dec.Decode(r, nil)
		if err != nil {
			t.Fatalf("output is not an event stream: %v", err)
		}
		types = append(types, m.Headers.Get(":event-type").String())
		var p struct {
			Delta struct {
				Text string `json:"text"`
			} `json:"delta"`
		}
		_ = json.Unmarshal(m.Payload, &p)
		text.WriteString(p.Delta.Text)
	}
	return text.String(), types
}

func gzipText(t *testing.T, s string) string {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return b.String()
}

// GAP-0644 M2: every other provider shape OpenClaw can use shows the notice.
func TestGAP0644NoticeLeadsTheReplyForGeminiOllamaBedrockStreamAndGzip(t *testing.T) {
	line := noticeTestLine()
	want := line + "\n\n" + "I could not run that."
	gemReq := `{"contents":[{"role":"user","parts":[{"text":"go"}]},{"role":"user","parts":[{"functionResponse":{"id":"call_blk1","name":"exec","response":{"error":"DefenseClaw: blocked"}}}]}]}`
	gemJSON := `{"candidates":[{"content":{"role":"model","parts":[{"text":"private thought","thought":true},{"text":"I could not run that."}]}}]}`
	gemSSE := "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"I could not \"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"run that.\"}]},\"finishReason\":\"STOP\"}]}\n\n"
	ollReq := `{"model":"m","messages":[{"role":"user","content":"go"},{"role":"tool","tool_call_id":"call_blk1","tool_name":"exec","content":"DefenseClaw: blocked"}]}`
	ollJSON := `{"model":"m","message":{"role":"assistant","content":"I could not run that."},"done":true}`
	ollND := "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"I could not \"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"run that.\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n"
	bedReq := `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"DefenseClaw: blocked"}]}}]}]}`
	chatReq := noticeChatReq()
	chatJSON := `{"choices":[{"index":0,"message":{"role":"assistant","content":"I could not run that."}}]}`

	oneLead := func(t *testing.T, out string) {
		t.Helper()
		if !strings.Contains(out, `\n\nI could not run that.`) || strings.Count(out, "Tool call blocked") != 1 {
			t.Fatalf("out=%s", out)
		}
	}
	cases := []struct {
		name  string
		o     noticeServe
		check func(t *testing.T, out string)
	}{
		{"gemini json", noticeServe{reqBody: gemReq, ctype: noticeJSONType, respBody: gemJSON}, func(t *testing.T, out string) {
			oneLead(t, out)
			if !strings.Contains(out, `"text":"private thought"`) {
				t.Fatalf("thought part changed: %s", out)
			}
		}},
		{"gemini json array", noticeServe{reqBody: gemReq, ctype: noticeJSONType, respBody: "[" + gemJSON + "]"}, oneLead},
		{"gemini sse", noticeServe{reqBody: gemReq, ctype: "text/event-stream", respBody: gemSSE}, func(t *testing.T, out string) {
			var got strings.Builder
			for _, f := range sseData(t, out) {
				c, _ := f["candidates"].([]any)
				parts, _ := c[0].(map[string]any)["content"].(map[string]any)["parts"].([]any)
				got.WriteString(parts[0].(map[string]any)["text"].(string))
			}
			if got.String() != want {
				t.Fatalf("stream text=%q", got.String())
			}
		}},
		{"ollama json", noticeServe{reqBody: ollReq, ctype: noticeJSONType, respBody: ollJSON}, oneLead},
		{"ollama ndjson", noticeServe{reqBody: ollReq, ctype: "application/x-ndjson", respBody: ollND}, func(t *testing.T, out string) {
			var got strings.Builder
			lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
			if len(lines) != 4 {
				t.Fatalf("line count changed: %q", out)
			}
			for _, l := range lines {
				var m struct {
					Message struct {
						Content string `json:"content"`
					} `json:"message"`
				}
				if err := json.Unmarshal([]byte(l), &m); err != nil {
					t.Fatalf("bad ndjson line %q: %v", l, err)
				}
				got.WriteString(m.Message.Content)
			}
			if got.String() != want {
				t.Fatalf("stream text=%q", got.String())
			}
		}},
		{"bedrock converse stream", noticeServe{reqBody: bedReq, ctype: "application/vnd.amazon.eventstream",
			respBody: bedrockStream(t, "I could not ", "run that.")}, func(t *testing.T, out string) {
			text, types := bedrockStreamText(t, out)
			if text != want || strings.Join(types, ",") != "messageStart,contentBlockDelta,contentBlockDelta,contentBlockStop,messageStop" {
				t.Fatalf("text=%q types=%v", text, types)
			}
		}},
		{"gzip json", noticeServe{reqBody: chatReq, ctype: noticeJSONType, enc: "gzip", respBody: gzipText(t, chatJSON)}, oneLead},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
			out, code := serveNoticeWith(t, c.o)
			if code != 200 {
				t.Fatalf("status %d", code)
			}
			c.check(t, out)
			// Exactly once.
			again, _ := serveNoticeWith(t, c.o)
			if again != c.o.respBody {
				t.Fatalf("notice repeated on the next request:\n%q", again)
			}
		})
	}
}
