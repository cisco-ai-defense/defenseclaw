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

func noticeChatReq(id string) string {
	return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"result"}]}`
}

func noticeServed(out string) bool { return strings.Count(out, "Tool call blocked") == 1 }

// GAP-0644 M1: a notice belongs to the OpenClaw request that carries its call.
func TestGAP0644OtherConnectorRouteNeverTakesTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("", "call_same", "exec", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{viaPrefix: true, path: "/c/claudecode/v1/chat/completions",
		reqBody: noticeChatReq("call_same"), ctype: noticeJSONType, respBody: noticeChatReply})
	if out != noticeChatReply || !openClawBlockNoticesPending("") {
		t.Fatalf("another connector took or showed the OpenClaw notice: %s", out)
	}
	// The benign twin: OpenClaw own routes, with and without a connector prefix.
	for _, path := range []string{"/v1/chat/completions", "/c/openclaw/v1/chat/completions"} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("", "call_same", "exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{viaPrefix: true, path: path,
			reqBody: noticeChatReq("call_same"), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) {
			t.Fatalf("%s: notice missing: %s", path, out)
		}
	}
}

func TestGAP0644UnauthorizedRequestNeverTakesTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("", "call_same", "exec", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{deny: true, reqBody: noticeChatReq("call_same"), ctype: noticeJSONType, respBody: noticeChatReply})
	if out != noticeChatReply || !openClawBlockNoticesPending("") {
		t.Fatalf("a request without the owner credential took the notice: %s", out)
	}
}

func TestGAP0644NoticeStaysInItsSession(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("sess-a", "call_same", "exec", []string{noticeTestRule}, "r")
	out, _ := serveNoticeWith(t, noticeServe{session: "sess-b", reqBody: noticeChatReq("call_same"), ctype: noticeJSONType, respBody: noticeChatReply})
	if out != noticeChatReply || !openClawBlockNoticesPending("sess-a") {
		t.Fatalf("another session took the notice: %s", out)
	}
	// Benign twins: the same session, and a request that names no session.
	for _, session := range []string{"sess-a", ""} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("sess-a", "call_same", "exec", []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{session: session, reqBody: noticeChatReq("call_same"), ctype: noticeJSONType, respBody: noticeChatReply})
		if !noticeServed(out) {
			t.Fatalf("session %q: notice missing: %s", session, out)
		}
	}
}

// GAP-0644 M1: distinct calls never share a notice, however long their ids.
func TestGAP0644DistinctLongIdsStayDistinct(t *testing.T) {
	resetOpenClawBlockNotices(t)
	prefix := "call_" + strings.Repeat("a", 40)
	rememberOpenClawBlockNotice("", prefix+"1", "exec", []string{noticeTestRule}, "r")
	if out, _ := serveNotice(t, noticeChatReq(prefix+"2"), noticeJSONType, noticeChatReply, 0); out != noticeChatReply {
		t.Fatalf("a distinct id took the notice: %s", out)
	}
	if out, _ := serveNotice(t, noticeChatReq(prefix+"1"), noticeJSONType, noticeChatReply, 0); !noticeServed(out) {
		t.Fatalf("the exact id did not take the notice: %s", out)
	}
}

// The plugin id and the id a provider adapter sends back compare equal only
// when the adapter rewrote the id by a rule OpenClaw has.
func TestGAP0644CallIdFormsMatchOnlyProviderRewrites(t *testing.T) {
	for _, tc := range []struct {
		recorded, requested string
		want                bool
	}{
		{"call_abc|fc_1", "call_abc", true},
		{"call.a|fc_1", "call_a", true},
		{"call.a", "calla", true},
		{"call_0123456789abcdef", "call01234", true},
		{"call_abc", "call_abd", false},
		{"call_abcdef123", "call_abc", false},
		{"call_abc", "call_abc_extra", false},
	} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("", tc.recorded, "exec", nil, "r")
		got := len(takeOpenClawBlockNotices([]byte(noticeChatReq(tc.requested)), "")) == 1
		if got != tc.want {
			t.Errorf("recorded %q requested %q: took=%v want %v", tc.recorded, tc.requested, got, tc.want)
		}
	}
}

// GAP-0644 M4: an unmatched notice stops costing requests once it expires.
func TestGAP0644ExpiredNoticeIsNoLongerPending(t *testing.T) {
	resetOpenClawBlockNotices(t)
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.entries = []openClawBlockNotice{{ids: []string{"call_old"}, line: "old", at: time.Now().Add(-3 * time.Minute)}}
	openClawBlockNotices.mu.Unlock()
	if openClawBlockNoticesPending("") {
		t.Fatal("an expired notice still makes every POST take the buffered path")
	}
	openClawBlockNotices.mu.Lock()
	n := len(openClawBlockNotices.entries)
	openClawBlockNotices.mu.Unlock()
	if n != 0 {
		t.Fatalf("expired notice kept: %d", n)
	}
	// A live notice is still pending.
	rememberOpenClawBlockNotice("", "call_new", "exec", nil, "r")
	if !openClawBlockNoticesPending("") {
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
			rememberOpenClawBlockNotice("", "call_block", "exec", []string{noticeTestRule}, "r")
			out, _ := serveNotice(t, noticeChatReq("call_block"), tc.ctype, tc.body, 0)
			if out != tc.body || !openClawBlockNoticesPending("") {
				t.Fatalf("synthetic reply was prefixed or used the notice: %s", out)
			}
			history, _ := json.Marshal(map[string]any{"messages": []any{map[string]any{"role": "assistant", "content": synth}}})
			if _, stripped, err := launderChatCompletionsHistory(history); err != nil || stripped != 1 {
				t.Fatalf("synthetic reply survived laundering: stripped=%d err=%v", stripped, err)
			}
			// The notice lands on the next real reply.
			if out, _ := serveNotice(t, noticeChatReq("call_block"), noticeJSONType, noticeChatReply, 0); !noticeServed(out) {
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
	gemReq := `{"contents":[{"role":"user","parts":[{"text":"go"}]},{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"blocked"}}}]}]}`
	gemJSON := `{"candidates":[{"content":{"role":"model","parts":[{"text":"private thought","thought":true},{"text":"I could not run that."}]}}]}`
	gemSSE := "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"I could not \"}]}}]}\n\n" +
		"data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"run that.\"}]},\"finishReason\":\"STOP\"}]}\n\n"
	ollReq := `{"model":"m","messages":[{"role":"user","content":"go"},{"role":"tool","tool_name":"exec","content":"blocked"}]}`
	ollJSON := `{"model":"m","message":{"role":"assistant","content":"I could not run that."},"done":true}`
	ollND := "{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"I could not \"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"run that.\"},\"done\":false}\n" +
		"{\"model\":\"m\",\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true}\n"
	bedReq := `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"blocked"}]}}]}]}`
	chatReq := noticeChatReq("call_blk1")
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
			rememberOpenClawBlockNotice("", "call_blk1", "exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
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

// Providers that name no call id key a notice by the tool name of the result.
func TestGAP0644ToolNameKeyedProvidersTakeOnlyTheirTool(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("", "call_blk1", "exec", []string{noticeTestRule}, "r")
	other := `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"read","response":{"ok":true}}}]}]}`
	reply := `{"candidates":[{"content":{"parts":[{"text":"done"}]}}]}`
	if out, _ := serveNotice(t, other, noticeJSONType, reply, 0); out != reply {
		t.Fatalf("a result of another tool took the notice: %s", out)
	}
	// A request that names a call id is matched by id only.
	withID := `{"messages":[{"role":"tool","tool_call_id":"call_other","tool_name":"exec","content":"x"}]}`
	if out, _ := serveNotice(t, withID, noticeJSONType, noticeChatReply, 0); out != noticeChatReply {
		t.Fatalf("a request naming another call id took the notice by tool name: %s", out)
	}
	mine := `{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"blocked"}}}]}]}`
	if out, _ := serveNotice(t, mine, noticeJSONType, reply, 0); !noticeServed(out) {
		t.Fatalf("the blocked tool result did not take the notice: %s", out)
	}
}
