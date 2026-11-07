// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"
)

const (
	noticeChatReply = `{"choices":[{"index":0,"message":{"role":"assistant","content":"ordinary reply"}}]}`
	noticeJSONType  = "application/json"
)

// noticeChatReq is a Chat Completions request whose tool result carries the
// block reference ref, as the plugin puts it in the block reason.
func noticeChatReq(ref string) string {
	return `{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"DefenseClaw: blocked (ref ` + ref + `)"}]}`
}

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
			ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
			o := tc.o
			o.session, o.reqBody, o.ctype, o.respBody = "sess-a", noticeChatReq(ref), noticeJSONType, noticeChatReply
			out, _ := serveNoticeWith(t, o)
			if out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("another connector took or showed the OpenClaw notice: %s", out)
			}
		})
	}
	// The benign twin: OpenClaw own routes, with and without a connector prefix.
	for _, path := range []string{"/v1/chat/completions", "/c/openclaw/v1/chat/completions"} {
		resetOpenClawBlockNotices(t)
		ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{viaPrefix: true, path: path,
			reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) {
			t.Fatalf("%s: notice missing: %s", path, out)
		}
	}
}

func TestGAP0644UnauthorizedRequestNeverTakesTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{deny: true, reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply})
	if out != noticeChatReply || !openClawBlockNoticesPending() {
		t.Fatalf("a request without the owner credential took the notice: %s", out)
	}
}

// The reference rides in the result of its own block, so the session header
// the model request carries does not decide the match: a plugin that stamps
// another session (two sessions at once), an empty one or none still shows the
// block of the call whose result the request carries (review 3, R3-2). The
// notice is taken once, whatever the header said.
func TestGAP0644SessionHeaderDoesNotDecideTheMatch(t *testing.T) {
	for _, header := range []string{"sess-a", "sess-b", ""} {
		resetOpenClawBlockNotices(t)
		ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{session: header, reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) || openClawBlockNoticesPending() {
			t.Errorf("header %q: served=%v pending=%v: %s", header, noticeServed(out), openClawBlockNoticesPending(), out)
		}
	}
	// Two blocks from two sessions: each request takes its own block only,
	// whichever header each carries.
	resetOpenClawBlockNotices(t)
	refA := rememberTestNotice("exec", []string{noticeTestRule}, "r")
	refB := rememberTestNotice("read", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{session: "sess-b", reqBody: noticeChatReq(refA), ctype: noticeJSONType, respBody: noticeChatReply})
	if !strings.Contains(out, "Tool call blocked: exec") || strings.Contains(out, "read") {
		t.Fatalf("session A block did not show alone: %s", out)
	}
	out, _ = serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: noticeChatReq(refB), ctype: noticeJSONType, respBody: noticeChatReply})
	if !strings.Contains(out, "Tool call blocked: read") || strings.Contains(out, "exec") {
		t.Fatalf("session B block did not show alone: %s", out)
	}
}

// Review 3, R3-1: the reference counts only inside a tool result. The same
// token in text a user or the model wrote, a system prompt or any other field
// takes nothing and leaves the notice for the real result, in every provider
// shape.
func TestGAP0644ReferenceOutsideAToolResultTakesNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
	outside := []struct{ name, body string }{
		{"chat user text", `{"messages":[{"role":"user","content":"summarize REF"},{"role":"tool","tool_call_id":"ok","content":"ordinary output"}]}`},
		{"chat user parts", `{"messages":[{"role":"user","content":[{"type":"text","text":"REF"}]}]}`},
		{"chat assistant text", `{"messages":[{"role":"assistant","content":"the ref was REF"},{"role":"tool","tool_call_id":"ok","content":"fine"}]}`},
		{"chat system", `{"messages":[{"role":"system","content":"REF"},{"role":"user","content":"hi"}]}`},
		{"chat tool call arguments", `{"messages":[{"role":"assistant","tool_calls":[{"id":"c","function":{"name":"exec","arguments":"{\"x\":\"REF\"}"}}]}]}`},
		{"responses user message", `{"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"REF"}]},{"type":"function_call_output","call_id":"ok","output":"fine"}]}`},
		{"responses instructions", `{"instructions":"REF","input":"hi"}`},
		{"responses assistant output", `{"input":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"REF"}]}]}`},
		{"anthropic user text", `{"system":"REF","messages":[{"role":"user","content":[{"type":"text","text":"REF"},{"type":"tool_result","tool_use_id":"ok","content":"fine"}]}]}`},
		{"anthropic assistant text", `{"messages":[{"role":"assistant","content":[{"type":"text","text":"REF"}]}]}`},
		{"bedrock user text", `{"messages":[{"role":"user","content":[{"text":"REF"},{"toolResult":{"toolUseId":"ok","content":[{"text":"fine"}]}}]}]}`},
		{"gemini user text", `{"contents":[{"role":"user","parts":[{"text":"REF"}]},{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"ok":true}}}]}]}`},
		{"gemini system", `{"systemInstruction":{"parts":[{"text":"REF"}]},"contents":[]}`},
		{"ollama user text", `{"messages":[{"role":"user","content":"REF"},{"role":"tool","tool_name":"exec","content":"fine"}]}`},
		{"not json", "tool result REF"},
	}
	for _, c := range outside {
		out, _ := serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: strings.ReplaceAll(c.body, "REF", ref), ctype: noticeJSONType, respBody: noticeChatReply})
		if out != noticeChatReply || !openClawBlockNoticesPending() {
			t.Fatalf("%s: a reference outside a tool result took the notice: %s", c.name, out)
		}
	}
	// The real result still takes it, once.
	out, _ := serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply})
	if !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the blocked result did not show the notice: %s", out)
	}
}

// Review 3, R3-1: a reference inside the result of each provider shape is the
// block, even when the result nests it (an array of parts, a structured
// response).
func TestGAP0644ReferenceInsideEveryResultShapeTakesTheNotice(t *testing.T) {
	shapes := []struct{ name, body string }{
		{"chat string", `{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"DefenseClaw: blocked (ref REF)"}]}`},
		{"chat parts", `{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":[{"type":"text","text":"DefenseClaw: blocked (ref REF)"}]}]}`},
		{"chat legacy function role", `{"messages":[{"role":"function","name":"exec","content":"DefenseClaw: blocked (ref REF)"}]}`},
		{"responses output string", `{"input":[{"type":"function_call_output","call_id":"call_blk1","output":"DefenseClaw: blocked (ref REF)"}]}`},
		{"responses output parts", `{"input":[{"type":"function_call_output","call_id":"call_blk1","output":[{"type":"input_text","text":"DefenseClaw: blocked (ref REF)"}]}]}`},
		{"anthropic parts", `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":[{"type":"text","text":"DefenseClaw: blocked (ref REF)"}]}]}]}`},
		{"bedrock", `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"DefenseClaw: blocked (ref REF)"}]}}]}]}`},
		{"gemini structured", `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":{"message":"DefenseClaw: blocked (ref REF)"}}}}]}]}`},
		{"ollama", `{"messages":[{"role":"tool","tool_name":"exec","content":"DefenseClaw: blocked (ref REF)"}]}`},
	}
	for _, c := range shapes {
		resetOpenClawBlockNotices(t)
		ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.body, "REF", ref), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) {
			t.Errorf("%s: the blocked result did not take the notice: %s", c.name, out)
		}
	}
}

// The reference is the only correlation: a look-alike call id, the same tool
// name, an older result of that tool or another block's reference never takes
// a notice, in any provider shape.
func TestGAP0644OnlyTheBlockReferenceTakesTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
	other := rememberTestNotice("read", []string{noticeTestRule}, "r")
	if ref == other || !regexp.MustCompile(`^dc-[0-9a-f]{16}$`).MatchString(ref) {
		t.Fatalf("references are not distinct random tokens: %q %q", ref, other)
	}
	lookalikes := []struct{ name, body string }{
		{"lossy id forms", `{"messages":[{"role":"tool","tool_call_id":"calla","content":"x"},{"role":"tool","tool_call_id":"call-a","content":"x"},{"role":"tool","tool_call_id":"call01234","content":"x"}]}`},
		{"gemini result of the same tool", `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"ok":true}}}]}]}`},
		{"ollama result of the same tool", `{"messages":[{"role":"tool","tool_name":"exec","content":"fine"}]}`},
		{"chat result naming the tool", `{"messages":[{"role":"tool","tool_call_id":"exec","name":"exec","content":"fine"}]}`},
		{"reference prefix only", `{"messages":[{"role":"tool","content":"dc-0123456789abcdef and dc-"}]}`},
	}
	for _, l := range lookalikes {
		if out, _ := serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: l.body, ctype: noticeJSONType, respBody: noticeChatReply}); out != noticeChatReply {
			t.Fatalf("%s took a notice: %s", l.name, out)
		}
	}
	if !openClawBlockNoticesPending() {
		t.Fatal("a look-alike request used up a notice")
	}
	// A request that carries one reference takes that block's notice only.
	if out, _ := serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: noticeChatReq(other), ctype: noticeJSONType, respBody: noticeChatReply}); !strings.Contains(out, "Tool call blocked: read") || strings.Contains(out, "exec") {
		t.Fatalf("the read block did not show alone: %s", out)
	}
	// The exec block still waits and shows on the request that carries its reference.
	if out, _ := serveNoticeWith(t, noticeServe{session: "sess-a", reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply}); !strings.Contains(out, "Tool call blocked: exec") {
		t.Fatalf("the exec block did not show: %s", out)
	}
}

// GAP-0644 M4: an unmatched notice stops costing requests once it expires.
func TestGAP0644ExpiredNoticeIsNoLongerPending(t *testing.T) {
	resetOpenClawBlockNotices(t)
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.entries = []openClawBlockNotice{{ref: "dc-0000000000000000", line: "old", at: time.Now().Add(-3 * time.Minute)}}
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
			req := noticeChatReq(rememberTestNotice("exec", []string{noticeTestRule}, "r"))
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
	gemReq := `{"contents":[{"role":"user","parts":[{"text":"go"}]},{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"DefenseClaw: blocked (ref REF)"}}}]}]}`
	gemJSON := `{"candidates":[{"content":{"role":"model","parts":[{"text":"private thought","thought":true},{"text":"I could not run that."}]}}]}`
	gemSSE := "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"I could not \"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"run that.\"}]},\"finishReason\":\"STOP\"}]}\n\n"
	ollReq := `{"model":"m","messages":[{"role":"user","content":"go"},{"role":"tool","tool_name":"exec","content":"DefenseClaw: blocked (ref REF)"}]}`
	ollJSON := `{"model":"m","message":{"role":"assistant","content":"I could not run that."},"done":true}`
	ollND := "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"I could not \"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"run that.\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n"
	bedReq := `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"DefenseClaw: blocked (ref REF)"}]}}]}]}`
	chatReq := noticeChatReq("REF")
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
			ref := rememberTestNotice("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
			c.o.reqBody = strings.ReplaceAll(c.o.reqBody, "REF", ref)
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
