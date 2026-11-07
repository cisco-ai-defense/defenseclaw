// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func resetOpenClawBlockNotices(t *testing.T) {
	t.Helper()
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.entries, openClawBlockNotices.seen = nil, nil
	openClawBlockNotices.mu.Unlock()
	t.Cleanup(func() {
		openClawBlockNotices.mu.Lock()
		openClawBlockNotices.entries, openClawBlockNotices.seen = nil, nil
		openClawBlockNotices.mu.Unlock()
	})
}

const noticeTestRule = "persistence.ssh_authorized_keys_command"

// noticeTestCallID is the id of the blocked call in the fixtures.
const noticeTestCallID = "call_blk1"

// noticeTestSession is the session of the blocked call and of the requests that
// follow it in the fixtures, unless a test says otherwise.
const noticeTestSession = "sess-n"

func rememberTestNotice(tool string, ruleIDs []string, reason string) {
	rememberOpenClawBlockNotice(tool, noticeTestCallID, noticeTestSession, ruleIDs, reason)
}

func noticeTestLine() string {
	return openClawBlockNoticeLine("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
}

// noticeServe describes one model request sent through the notice middleware.
type noticeServe struct {
	path       string // request path, /v1/x when empty
	session    string // X-DefenseClaw-Session-Id; noticeTestSession when empty
	noSession  bool   // the request names no session
	unbound    bool   // the plugin did not mark the session as observed for this request
	enc        string // Content-Encoding of the reply
	deny       bool   // the request does not present the owner credential
	active     string // connector this gateway serves; openclaw when empty, none when "-"
	viaPrefix  bool   // run behind connectorPrefixStripper, as the proxy does
	ctype      string
	status     int // 200 when zero
	reqBody    string
	respBody   string
	streamType bool // the reply arrives in two writes split mid-frame
}

// serveNoticeWith runs the request through the middleware in front of an
// upstream that answers with the described reply.
func serveNoticeWith(t *testing.T, o noticeServe) (string, int) {
	t.Helper()
	var seen string
	h := openClawBlockNoticeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.Header().Set("Content-Type", o.ctype)
		if o.enc != "" {
			w.Header().Set("Content-Encoding", o.enc)
		}
		streaming := o.streamType || strings.Contains(o.ctype, "event-stream") || strings.Contains(o.ctype, "ndjson") || strings.Contains(o.ctype, "eventstream")
		if !streaming {
			w.Header().Set("Content-Length", strconv.Itoa(len(o.respBody)))
		}
		if o.status != 0 {
			w.WriteHeader(o.status)
		}
		fl, _ := w.(http.Flusher)
		if streaming {
			// Split mid-frame to prove frames are reassembled.
			half := len(o.respBody) / 2
			_, _ = io.WriteString(w, o.respBody[:half])
			if fl != nil {
				fl.Flush()
			}
			_, _ = io.WriteString(w, o.respBody[half:])
			if fl != nil {
				fl.Flush()
			}
			return
		}
		_, _ = io.WriteString(w, o.respBody)
	}), func(*http.Request) bool { return !o.deny })
	if o.viaPrefix {
		h = connectorPrefixStripper(h, nil)
	}
	path := o.path
	if path == "" {
		path = "/v1/x"
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(o.reqBody))
	switch o.active {
	case "":
		req = req.WithContext(withThresholdConnector(req.Context(), "openclaw"))
	case "-":
	default:
		req = req.WithContext(withThresholdConnector(req.Context(), o.active))
	}
	if o.session == "" && !o.noSession {
		o.session = noticeTestSession
	}
	if o.session != "" {
		req.Header.Set(SessionIDHeader, o.session)
		if !o.unbound {
			req.Header.Set(SessionBoundHeader, "1")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if seen != o.reqBody {
		t.Fatalf("upstream saw a changed request body: %q", seen)
	}
	return rec.Body.String(), rec.Code
}

// serveNotice runs one model request through the notice middleware in front of
// an upstream that answers with ctype/body (status 200 unless status is set).
func serveNotice(t *testing.T, reqBody, ctype, respBody string, status int) (string, int) {
	t.Helper()
	return serveNoticeWith(t, noticeServe{reqBody: reqBody, ctype: ctype, respBody: respBody, status: status})
}

func sseData(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, frame := range strings.Split(stream, "\n\n") {
		for _, l := range strings.Split(frame, "\n") {
			if p, ok := strings.CutPrefix(l, "data: "); ok && p != "[DONE]" {
				var m map[string]any
				if err := json.Unmarshal([]byte(p), &m); err != nil {
					t.Fatalf("bad frame %q: %v", p, err)
				}
				out = append(out, m)
			}
		}
	}
	return out
}

func streamText(frames []map[string]any, kind string) string {
	var b strings.Builder
	for _, f := range frames {
		switch kind {
		case "chat":
			ch, _ := f["choices"].([]any)
			if len(ch) > 0 {
				d, _ := ch[0].(map[string]any)["delta"].(map[string]any)
				s, _ := d["content"].(string)
				b.WriteString(s)
			}
		case "responses":
			if f["type"] == "response.output_text.delta" {
				b.WriteString(f["delta"].(string))
			}
		case "anthropic":
			if d, _ := f["delta"].(map[string]any); f["type"] == "content_block_delta" {
				b.WriteString(d["text"].(string))
			}
		}
	}
	return b.String()
}

func TestGAP0644NoticeLeadsTheReplyInEveryFormat(t *testing.T) {
	line := noticeTestLine()
	want := line + "\n\n" + "I could not run that."
	chatReq := `{"messages":[{"role":"user","content":"go"},{"role":"assistant","tool_calls":[{"id":"call_blk1"}]},{"role":"tool","tool_call_id":"call_blk1","content":"DefenseClaw: blocked"}]}`
	respReq := `{"input":[{"type":"function_call_output","call_id":"call_blk1","output":"blocked"}]}`
	antReq := `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":"blocked"}]}]}`
	bedReq := `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"blocked"}]}}]}]}`

	chatJSON := `{"id":"c1","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"I could not run that."},"finish_reason":"stop"}]}`
	chatSSE := "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"I could not \"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"run that.\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	respJSON := `{"id":"r1","output":[{"type":"reasoning","summary":[]},{"type":"message","id":"msg_1","content":[{"type":"output_text","text":"I could not run that."}]}]}`
	respSSE := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\",\"output\":[]}}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"I could not \"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"run that.\"}\n\n" +
		"event: response.output_text.done\ndata: {\"type\":\"response.output_text.done\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"text\":\"I could not run that.\"}\n\n" +
		"event: response.content_part.done\ndata: {\"type\":\"response.content_part.done\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"part\":{\"type\":\"output_text\",\"text\":\"I could not run that.\"}}\n\n" +
		"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"type\":\"message\",\"id\":\"msg_1\",\"content\":[{\"type\":\"output_text\",\"text\":\"I could not run that.\"}]}}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"output\":[{\"type\":\"message\",\"id\":\"msg_1\",\"content\":[{\"type\":\"output_text\",\"text\":\"I could not run that.\"}]}]}}\n\n"
	antJSON := `{"id":"m1","type":"message","role":"assistant","content":[{"type":"text","text":"I could not run that."}],"stop_reason":"end_turn"}`
	antSSE := "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"content\":[]}}\n\n" +
		"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"I could not \"}}\n\n" +
		"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"run that.\"}}\n\n" +
		"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	bedJSON := `{"output":{"message":{"role":"assistant","content":[{"text":"I could not run that."}]}},"stopReason":"end_turn"}`

	jsonLead := func(t *testing.T, out string) {
		t.Helper()
		if !strings.Contains(out, `\n\nI could not run that.`) || strings.Count(out, "Tool call blocked") != 1 {
			t.Fatalf("out=%s", out)
		}
	}
	cases := []struct {
		name, req, ctype, resp string
		check                  func(t *testing.T, out string)
	}{
		{"chat json", chatReq, "application/json", chatJSON, jsonLead},
		{"chat sse", chatReq, "text/event-stream", chatSSE, func(t *testing.T, out string) {
			if got := streamText(sseData(t, out), "chat"); got != want {
				t.Fatalf("stream text=%q", got)
			}
			if !strings.HasSuffix(out, "data: [DONE]\n\n") {
				t.Fatalf("stream end lost: %q", out)
			}
		}},
		{"responses json", respReq, "application/json", respJSON, jsonLead},
		{"responses sse", respReq, "text/event-stream", respSSE, func(t *testing.T, out string) {
			if got := streamText(sseData(t, out), "responses"); got != want {
				t.Fatalf("stream text=%q", got)
			}
			// The done events and the final response agree with the deltas.
			if n := strings.Count(out, line); n != 5 {
				t.Fatalf("line appears %d times, want the delta and 4 done copies:\n%s", n, out)
			}
			if !strings.Contains(out, "event: response.completed\ndata: ") {
				t.Fatalf("event lines were lost:\n%s", out)
			}
		}},
		{"anthropic json", antReq, "application/json", antJSON, jsonLead},
		{"anthropic sse", antReq, "text/event-stream", antSSE, func(t *testing.T, out string) {
			if got := streamText(sseData(t, out), "anthropic"); got != want {
				t.Fatalf("stream text=%q", got)
			}
		}},
		{"bedrock json", bedReq, "application/json", bedJSON, jsonLead},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
			req := c.req
			out, code := serveNotice(t, req, c.ctype, c.resp, 0)
			if code != 200 {
				t.Fatalf("status %d", code)
			}
			c.check(t, out)
			// Exactly once: the same history on the next request is untouched.
			again, _ := serveNotice(t, req, c.ctype, c.resp, 0)
			if again != c.resp {
				t.Fatalf("notice repeated on the next request:\n%s", again)
			}
		})
	}
}

func TestGAP0644AllowedCallsAndOtherRepliesAreUntouched(t *testing.T) {
	chatReq := `{"messages":[{"role":"tool","tool_call_id":"call_ok9","content":"fine"}]}`
	chatJSON := `{"choices":[{"index":0,"message":{"role":"assistant","content":"done"}}]}`
	chatSSE := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"done\"}}]}\n\ndata: [DONE]\n\n"
	for _, tc := range []struct{ name, ctype, body string }{
		{"json", "application/json", chatJSON}, {"sse", "text/event-stream", chatSSE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			// Nothing recorded: an allowed call has no notice.
			if out, _ := serveNotice(t, chatReq, tc.ctype, tc.body, 0); out != tc.body {
				t.Fatalf("allowed call changed the reply: %q", out)
			}
			// A block of call_blk1 does not leak into the result of call_ok9.
			rememberTestNotice("exec", []string{noticeTestRule}, "r")
			if out, _ := serveNotice(t, chatReq, tc.ctype, tc.body, 0); out != tc.body {
				t.Fatalf("another call notice changed the reply: %q", out)
			}
			if !openClawBlockNoticesPending() {
				t.Fatal("the other call notice was taken")
			}
		})
	}
}

func TestGAP0644NoticeWaitsForAReplyWithText(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberTestNotice("exec", []string{noticeTestRule}, "r")
	req := noticeChatReq()
	toolOnlyJSON := `{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_2"}]}}]}`
	toolOnlySSE := "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_2\"}]}}]}\n\ndata: [DONE]\n\n"
	textJSON := `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`

	if out, _ := serveNotice(t, req, "application/json", toolOnlyJSON, 0); out != toolOnlyJSON {
		t.Fatalf("tool-only reply changed: %q", out)
	}
	if out, _ := serveNotice(t, req, "text/event-stream", toolOnlySSE, 0); out != toolOnlySSE {
		t.Fatalf("tool-only stream changed: %q", out)
	}
	if out, code := serveNotice(t, req, "application/json", `{"error":"busy"}`, 503); code != 503 || strings.Contains(out, "DefenseClaw") {
		t.Fatalf("upstream error carried the notice: %d %q", code, out)
	}
	out, _ := serveNotice(t, req, "application/json", textJSON, 0)
	if strings.Count(out, "Tool call blocked") != 1 {
		t.Fatalf("notice did not reach the first reply with text: %s", out)
	}
	if again, _ := serveNotice(t, req, "application/json", textJSON, 0); again != textJSON {
		t.Fatalf("notice repeated: %s", again)
	}
}

func TestGAP0644UnrewrittenFormatsKeepTheNoticeForALaterReply(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberTestNotice("exec", nil, "r")
	req := noticeChatReq()
	// A reply format that is not rewritten, and a compressed stream, pass
	// through byte for byte and do not use up the notice.
	for _, tc := range []struct{ ctype, enc string }{{"text/plain", ""}, {"text/event-stream", "br"}, {"application/json", "zstd"}} {
		body := "\x00\x01opaque"
		if out, _ := serveNoticeWith(t, noticeServe{reqBody: req, ctype: tc.ctype, enc: tc.enc, respBody: body}); out != body {
			t.Fatalf("unsupported reply %v changed: %q", tc, out)
		}
		if !openClawBlockNoticesPending() {
			t.Fatalf("a reply %v that could not carry the notice used it up", tc)
		}
	}
	later := `{"choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}]}`
	if out, _ := serveNotice(t, req, "application/json", later, 0); strings.Count(out, "Tool call blocked") != 1 {
		t.Fatalf("notice did not reach the next reply that can carry it: %s", out)
	}
}

func TestGAP0644NoticeLineIsOneSafeLine(t *testing.T) {
	line := openClawBlockNoticeLine("exec\nrun", []string{"", noticeTestRule}, "bad\r\nline\x00 "+strings.Repeat("x", 600))
	if strings.ContainsAny(line, "\r\n\x00") || !strings.HasPrefix(line, openClawBlockNoticeMark+": exec run (rule "+noticeTestRule+")") || len(line) > 500 {
		t.Fatalf("line=%q", line)
	}
}

func TestGAP0644LaunderKeepsAModelReplyThatCarriesANotice(t *testing.T) {
	line := noticeTestLine()
	body := func(content string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"messages": []any{
			map[string]any{"role": "user", "content": "go"},
			map[string]any{"role": "assistant", "content": content},
		}})
		return b
	}
	// A reply that carries a notice is the model answer: kept.
	if out, n, err := launderChatCompletionsHistory(body(line + "\n\nI could not run that.")); err != nil || n != 0 || !bytes.Contains(out, []byte("I could not run that.")) {
		t.Fatalf("notice reply laundered: n=%d err=%v out=%s", n, err, out)
	}
	// A block message DefenseClaw wrote is still dropped, even one that starts like a notice.
	for _, text := range []string{"[DefenseClaw] The response was blocked (x).", line, line + "\n\n"} {
		if _, n, err := launderChatCompletionsHistory(body(text)); err != nil || n != 1 {
			t.Fatalf("block message kept: %q n=%d err=%v", text, n, err)
		}
	}
	resp := func(text string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"input": []any{
			map[string]any{"role": "assistant", "id": "msg_1", "content": []any{map[string]any{"type": "output_text", "text": text}}},
		}})
		return b
	}
	if _, n, err := launderResponsesHistory(resp(line + "\n\nI could not run that.")); err != nil || n != 0 {
		t.Fatalf("responses notice reply laundered: n=%d err=%v", n, err)
	}
	if _, n, err := launderResponsesHistory(resp("[DefenseClaw] blocked")); err != nil || n != 1 {
		t.Fatalf("responses block message kept: n=%d err=%v", n, err)
	}
}

// The inspect endpoint records a notice for an enforced OpenClaw block only,
// under the call id the plugin sent.
func TestGAP0644InspectRecordsANoticeOnlyForEnforcedBlocks(t *testing.T) {
	resetOpenClawBlockNotices(t)
	const blocking = `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-n","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`
	api := testAPIServerWithConfig(t, "action")
	_, benign := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_ok9","session_id":"sess-n","args":{"command":"echo hello"}}`)
	if benign.Action != "allow" || openClawBlockNoticesPending() {
		t.Fatalf("benign call: %+v pending=%v", benign, openClawBlockNoticesPending())
	}
	// A block without a call id cannot be tied to its result: no notice.
	_, noID := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
	if noID.Action != "block" || openClawBlockNoticesPending() {
		t.Fatalf("block without a call id: %+v pending=%v", noID, openClawBlockNoticesPending())
	}
	_, blocked := postInspectForConnector(t, api, "openclaw", blocking)
	if blocked.Action != "block" || !openClawBlockNoticesPending() {
		t.Fatalf("protected call: %+v pending=%v", blocked, openClawBlockNoticesPending())
	}
	// The answer the plugin reads is as it was: the notice is the proxy concern.
	if raw, _ := json.Marshal(blocked); strings.Contains(string(raw), "notice") {
		t.Fatalf("the inspect answer carries notice data: %s", raw)
	}
	// The result of the allowed call takes nothing; the result of the blocked call does.
	if got := takeOpenClawBlockNotices([]byte(noticeChatReqFor("call_ok9")), noticeTestSession); len(got) != 0 {
		t.Fatalf("the allowed call result took a notice: %+v", got)
	}
	got := takeOpenClawBlockNotices([]byte(noticeChatReq()), noticeTestSession)
	if len(got) != 1 || !strings.Contains(got[0].line, openClawBlockNoticeMark+": exec") || !strings.Contains(got[0].line, "(rule ") {
		t.Fatalf("notice=%+v", got)
	}
	// Another connector never records one.
	_, other := postInspectForConnector(t, api, "claudecode", blocking)
	if openClawBlockNoticesPending() {
		t.Fatalf("a non-OpenClaw block left a notice: %+v", other)
	}
}

// Review 3, R3-3: the notice follows the final verdict. A strict or managed
// install fails closed when the audit row cannot be written, which turns an
// allow into an enforced block after the policy step; that block gets its
// notice too. The default tier keeps its allow, with no notice, and a block
// the policy made stays one, with a notice, when the audit write fails as
// well.
func TestGAP0644AuditFailureBlockGetsANoticeOnlyWhenEnforced(t *testing.T) {
	type tierCase struct {
		name, pack, command string
		wantAction          string
		wantNotice          bool
	}
	for _, tc := range []tierCase{
		{"strict tier, allowed call, audit fails", "strict", "echo ok", "block", true},
		{"default tier, allowed call, audit fails", "", "echo ok", "allow", false},
		{"default tier, protected call, audit fails", "", "echo k >> ~/.ssh/authorized_keys", "block", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			fixture := newAuditFailureHookFixture(t, "")
			fixture.api.scannerCfg.Guardrail.Connector = "openclaw"
			fixture.api.scannerCfg.Guardrail.RulePack = tc.pack
			fixture.emitter.fail = true
			body, _ := json.Marshal(map[string]any{"tool": "exec", "tool_call_id": noticeTestCallID, "session_id": noticeTestSession, "args": map[string]any{"command": tc.command}, "connector": "openclaw"})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body))
			req = req.WithContext(withAuthenticatedInspectConnector(req.Context(), "openclaw"))
			w, verdict := postInspectHTTP(t, fixture.api, req)
			if w.Code != http.StatusOK || verdict.Action != tc.wantAction {
				t.Fatalf("status=%d verdict=%+v, want action %s", w.Code, verdict, tc.wantAction)
			}
			if openClawBlockNoticesPending() != tc.wantNotice {
				t.Fatalf("pending=%v, want a notice: %v", openClawBlockNoticesPending(), tc.wantNotice)
			}
			if tc.wantNotice {
				// The result of the blocked call shows it.
				got := takeOpenClawBlockNotices([]byte(noticeChatReq()), noticeTestSession)
				if len(got) != 1 || !strings.Contains(got[0].line, openClawBlockNoticeMark+": exec") {
					t.Fatalf("notice=%+v", got)
				}
			}
		})
	}
}

// Secure Client answers stay as they were: no notice. (A
// Secure Client inspect cannot be driven to a block in a unit fixture: its
// local scan is skipped without a wired AI Defense lane, so the policy is
// pinned on the config the handler consults.)
func TestGAP0644SecureClientHasNoNotice(t *testing.T) {
	secure := &config.Config{DeploymentMode: "managed_enterprise"}
	if !secure.SecureClientIntegration() {
		t.Fatal("fixture is not a Secure Client configuration")
	}
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want bool
	}{
		{"no config", nil, true},
		{"default profile", &config.Config{}, true},
		{"Secure Client", secure, false},
	} {
		if got := openClawNoticeAllowed(tc.cfg); got != tc.want {
			t.Errorf("%s: openClawNoticeAllowed=%v, want %v", tc.name, got, tc.want)
		}
	}
}

// The notice reaches a reply the real passthrough handler forwards, stream and
// not, so a wrapper the handler cannot flush or buffer through would show here.
func TestGAP0644NoticeThroughThePassthroughHandler(t *testing.T) {
	sse := "event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"I could not \"}\n\n" +
		"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg_1\",\"output_index\":0,\"content_index\":0,\"delta\":\"run that.\"}\n\n" +
		"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"output\":[{\"type\":\"message\",\"id\":\"msg_1\",\"content\":[{\"type\":\"output_text\",\"text\":\"I could not run that.\"}]}]}}\n\n"
	plain := `{"id":"r1","object":"response","output":[{"type":"message","id":"msg_1","content":[{"type":"output_text","text":"I could not run that."}]}]}`
	for _, stream := range []bool{false, true} {
		name := "json"
		if stream {
			name = "sse"
		}
		t.Run(name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if stream {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = io.WriteString(w, sse)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, plain)
			}))
			defer upstream.Close()
			proxy := newForwardingProxy(t, upstream.URL)
			notice := openClawBlockNoticeMiddleware(http.HandlerFunc(proxy.handlePassthrough), func(*http.Request) bool { return true })
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				notice.ServeHTTP(w, r.WithContext(withThresholdConnector(r.Context(), "openclaw")))
			}))
			defer front.Close()

			rememberTestNotice("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
			send := func() string {
				body := `{"model":"gpt-4.1","stream":` + strconv.FormatBool(stream) + `,"input":[{"type":"function_call_output","call_id":"call_blk1","output":"blocked"}]}`
				req, _ := http.NewRequest(http.MethodPost, front.URL+"/v1/responses", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-DC-Target-URL", upstream.URL)
				req.Header.Set("X-AI-Auth", "Bearer sk-upstream")
				req.Header.Set(SessionIDHeader, noticeTestSession)
				req.Header.Set(SessionBoundHeader, "1")
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				b, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != 200 {
					t.Fatalf("status %d: %s", resp.StatusCode, b)
				}
				return string(b)
			}
			out := send()
			if !strings.Contains(out, "Tool call blocked: exec (rule "+noticeTestRule+")") || !strings.Contains(out, `\n\n`) || !strings.Contains(out, "run that.") {
				t.Fatalf("notice missing from the forwarded reply:\n%s", out)
			}
			if again := send(); strings.Contains(again, "Tool call blocked") {
				t.Fatalf("notice repeated:\n%s", again)
			}
		})
	}
}
