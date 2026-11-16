// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// GAP-0644: a call id is not unique. Two sessions of one account, or a replay
// that rewrites a repeated id, can send the same id for two different calls.
// The notice must never land on the result of another call.

func chatToolResult(id, content string) string {
	return `{"messages":[{"role":"assistant","tool_calls":[{"id":"` + id + `","type":"function","function":{"name":"read","arguments":"{}"}}]},{"role":"tool","tool_call_id":"` + id + `","content":"` + content + `"}]}`
}

// serveInSession sends a request of the session, marked by the plugin as having
// observed it; an empty session names none.
func serveInSession(t *testing.T, session, body string) string {
	t.Helper()
	out, _ := serveNoticeWith(t, noticeServe{session: session, noSession: session == "", reqBody: body, ctype: noticeJSONType, respBody: noticeChatReply})
	return out
}

// serveStaleHeader sends a request whose session header is the plugin's
// last-seen context, which the plugin did not observe for this request.
func serveStaleHeader(t *testing.T, session, body string) string {
	t.Helper()
	out, _ := serveNoticeWith(t, noticeServe{session: session, unbound: true, reqBody: body, ctype: noticeJSONType, respBody: noticeChatReply})
	return out
}

// An ordinary result with the id of a pending block, sent by another session,
// keeps the reply as it was and leaves the block for its own session.
func TestGAP0644OtherSessionSameCallIDKeepsTheReplyAndTheNotice(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared", "sess-blocked", []string{noticeTestRule}, "protected write")
	if out := serveInSession(t, "sess-other", chatToolResult("call_shared", "ordinary output")); out != noticeChatReply || !openClawBlockNoticesPending() {
		t.Fatalf("the result of another session got the block line: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
	}
	if out := serveInSession(t, "sess-blocked", chatToolResult("call_shared", "blocked")); !strings.Contains(out, "Tool call blocked: exec") || openClawBlockNoticesPending() {
		t.Fatalf("the blocked session lost its notice: %s", out)
	}
}

// The session of the request must be the session of the block. A request that
// names no session, or a block recorded with none, cannot prove an equal call id
// is the same call, and two empty sessions are not a session.
func TestGAP0644SessionMustEqualTheRecordedOne(t *testing.T) {
	for _, tc := range []struct {
		name, recorded, request string
		want                    bool
	}{
		{"same session", "sess-a", "sess-a", true},
		{"neither names a session", "", "", false},
		{"request names no session", "sess-a", "", false},
		{"block recorded without a session", "", "sess-a", false},
		{"another session", "sess-a", "sess-b", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_x", tc.recorded, []string{noticeTestRule}, "protected write")
			// An ordinary result with the same id, sent by the request.
			out := serveInSession(t, tc.request, chatToolResult("call_x", "ordinary output"))
			if noticeServed(out) != tc.want || openClawBlockNoticesPending() == tc.want {
				t.Fatalf("served=%v pending=%v, want served=%v", noticeServed(out), openClawBlockNoticesPending(), tc.want)
			}
			if !tc.want && tc.recorded != "" {
				// The block is still there for its own session.
				if out := serveInSession(t, tc.recorded, chatToolResult("call_x", "blocked")); !noticeServed(out) {
					t.Fatalf("the blocked session lost its notice: %s", out)
				}
			}
		})
	}
}

// Two blocks of different sessions that share an id cannot be told apart by a
// request (a session header can be stale): neither shows a line, and each is
// consumed by the first result that claims it.
func TestGAP0644TwoSessionsSameCallIDShowNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "first protected write")
	rememberOpenClawBlockNotice("read", "call_shared", "sess-b", []string{noticeTestRule}, "second protected read")
	for _, session := range []string{"sess-a", "sess-b"} {
		if out := serveInSession(t, session, chatToolResult("call_shared", "blocked")); strings.Contains(out, openClawBlockNoticeMark) {
			t.Fatalf("session %s showed a line for an id two sessions used: %s", session, out)
		}
	}
	if openClawBlockNoticesPending() {
		t.Fatal("an ambiguous block stayed pending")
	}
}

// A second inspected call under the call id of a block makes the block
// ambiguous, whichever was inspected first and whichever session made it: an
// ordinary result with that id is not told from the blocked one by anything the
// request carries (a header can be stale, and a session can reuse an id).
func TestGAP0644CallOfAnotherSessionUnderTheSameIDMakesTheBlockAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func()
	}{
		{"allowed call inspected first", func() {
			observeOpenClawToolCall("call_shared")
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
		}},
		{"allowed call inspected after", func() {
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
			observeOpenClawToolCall("call_shared")
		}},
		{"two allowed calls and the block between", func() {
			observeOpenClawToolCall("call_shared")
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
			observeOpenClawToolCall("call_shared")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			tc.setup()
			// The ordinary result of the other call arrives with the session of
			// the block.
			if out := serveInSession(t, "sess-a", chatToolResult("call_shared", "ordinary output")); strings.Contains(out, openClawBlockNoticeMark) {
				t.Fatalf("a result of a shared id showed a line: %s", out)
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the ambiguous block stayed pending")
			}
		})
	}
}

// Benign twins: calls under other ids, calls without an id, and a call under
// the same id that is older than the memory of the gateway do not make a block
// ambiguous.
func TestGAP0644UnrelatedCallsLeaveTheBlockShown(t *testing.T) {
	resetOpenClawBlockNotices(t)
	observeOpenClawToolCall("call_other")
	observeOpenClawToolCall("")
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.seen = append(openClawBlockNotices.seen, openClawSeenCall{key: "call_x", at: time.Now().Add(-openClawSeenCallTTL - time.Minute)})
	openClawBlockNotices.mu.Unlock()
	rememberOpenClawBlockNotice("exec", "call_x", "sess-a", []string{noticeTestRule}, "protected write")
	if out := serveInSession(t, "sess-a", chatToolResult("call_x", "blocked")); !noticeServed(out) {
		t.Fatalf("an unrelated call hid the notice: %s", out)
	}
}

// The memory of seen calls is bounded.
func TestGAP0644SeenCallMemoryIsBounded(t *testing.T) {
	resetOpenClawBlockNotices(t)
	for i := 0; i < openClawSeenCallCap+50; i++ {
		observeOpenClawToolCall(fmt.Sprintf("call_%d", i))
	}
	openClawBlockNotices.mu.Lock()
	n := len(openClawBlockNotices.seen)
	openClawBlockNotices.mu.Unlock()
	if n != openClawSeenCallCap {
		t.Fatalf("seen calls: %d", n)
	}
}

// When the request does not tell two blocks apart, nothing is shown and nothing
// is taken: an unknown tie shows no line.
func TestGAP0644RequestThatCannotPickBetweenTwoBlocksShowsNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "first protected write")
	rememberOpenClawBlockNotice("read", "call_shared", "sess-b", []string{noticeTestRule}, "second protected read")
	if out := serveInSession(t, "", chatToolResult("call_shared", "blocked")); out != noticeChatReply {
		t.Fatalf("a result claimed by two blocks showed a line: %s", out)
	}
	if out := serveInSession(t, "sess-c", chatToolResult("call_shared", "blocked")); out != noticeChatReply {
		t.Fatalf("a third session showed a line: %s", out)
	}
	openClawBlockNotices.mu.Lock()
	n := len(openClawBlockNotices.entries)
	openClawBlockNotices.mu.Unlock()
	// sess-c matches neither recorded session, so both stay pending.
	if n != 2 {
		t.Fatalf("an unresolved tie consumed a block: %d entries", n)
	}
}

// Two different blocks under one id and one session cannot be told apart: the
// first result shows no reason, and not the reason of the second block.
func TestGAP0644TwoBlocksSameIDSameSessionShowNothing(t *testing.T) {
	for _, session := range []string{"sess-a"} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", "call_shared", session, []string{noticeTestRule}, "first protected write")
		rememberOpenClawBlockNotice("read", "call_shared", session, []string{noticeTestRule}, "second protected read")
		if out := serveInSession(t, session, chatToolResult("call_shared", "blocked")); out != noticeChatReply {
			t.Fatalf("session %q: an ambiguous id showed a line: %s", session, out)
		}
		if openClawBlockNoticesPending() {
			t.Fatalf("session %q: the ambiguous block stayed pending", session)
		}
		// A third record of the first block does not clear the ambiguity.
		rememberOpenClawBlockNotice("exec", "call_shared", session, []string{noticeTestRule}, "first protected write")
		rememberOpenClawBlockNotice("read", "call_shared", session, []string{noticeTestRule}, "second protected read")
		rememberOpenClawBlockNotice("exec", "call_shared", session, []string{noticeTestRule}, "first protected write")
		if out := serveInSession(t, session, chatToolResult("call_shared", "blocked")); out != noticeChatReply {
			t.Fatalf("session %q: a re-recorded ambiguous id showed a line: %s", session, out)
		}
	}
}

// Equal tool, rule and reason do not make two records one event: nothing in
// the inspect call tells a retry from a second block that reused the id, so a
// repeat is ambiguous and shows nothing. A block under another id is not
// touched.
func TestGAP0644RepeatedBlockWithEqualTextShowsNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	for i := 0; i < 2; i++ {
		rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
	}
	rememberOpenClawBlockNotice("exec", "call_single", "sess-a", []string{noticeTestRule}, "protected write")
	if out := serveInSession(t, "sess-a", chatToolResult("call_shared", "first blocked result")); strings.Contains(out, openClawBlockNoticeMark) {
		t.Fatalf("a reused id with equal text was taken for one block: %s", out)
	}
	if out := serveInSession(t, "sess-a", chatToolResult("call_single", "blocked")); !noticeServed(out) {
		t.Fatalf("a block under its own id lost its notice: %s", out)
	}
}

// responsesBody is a Responses request whose input carries the given
// function_call items (call id, item id) and one function_call_output.
func responsesBody(outputType, outputCallID string, calls ...[2]string) string {
	var items []string
	for _, c := range calls {
		item := `{"type":"function_call","call_id":"` + c[0] + `","name":"read","arguments":"{}"`
		if c[1] != "" {
			item += `,"id":"` + c[1] + `"`
		}
		items = append(items, item+"}")
	}
	items = append(items, `{"type":"`+outputType+`","call_id":"`+outputCallID+`","output":"result"}`)
	return `{"input":[` + strings.Join(items, ",") + `]}`
}

// A Responses result names only the call part of the id OpenClaw gave the
// call, so it is tied to the full id through the function_call item of its own
// request. A sibling item of the same call part is another call.
func TestGAP0644ResponsesResultIsTiedToItsOwnItem(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
	sibling := responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_2"})
	if out := serveInSession(t, "sess-a", sibling); out != noticeChatReply || !openClawBlockNoticesPending() {
		t.Fatalf("an ordinary sibling item took the block: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
	}
	blocked := responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_1"})
	if out := serveInSession(t, "sess-a", blocked); !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the blocked item lost its notice: %s", out)
	}
}

// The call part names the function result of the blocked call only: another
// output type of the same call part is another tool, and a result whose
// request names several items of the call shows nothing and consumes the
// block, so a later replay of the result cannot show it on another reply.
func TestGAP0644ResponsesResultThatCannotBeTiedToOneItemShowsNothing(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		consumed   bool
	}{
		{"custom tool output, item present", responsesBody("custom_tool_call_output", "call_shared", [2]string{"call_shared", "fc_1"}), false},
		{"custom tool output, no item", responsesBody("custom_tool_call_output", "call_shared"), false},
		{"two items of one call part", responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_1"}, [2]string{"call_shared", "fc_2"}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, "sess-a", tc.body); out != noticeChatReply || openClawBlockNoticesPending() == tc.consumed {
				t.Fatalf("a result that is not tied to the blocked item took the notice: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
		})
	}
}

// Benign twin: a recorded id without a "|" is matched by the call_id itself,
// with or without its function_call item, on both output types.
func TestGAP0644ResponsesExactCallIDStillTakesTheNotice(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"function output with its item", responsesBody("function_call_output", "call_x", [2]string{"call_x", "fc_1"})},
		{"function output alone", responsesBody("function_call_output", "call_x")},
		{"custom tool output", responsesBody("custom_tool_call_output", "call_x")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_x", "sess-a", []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, "sess-a", tc.body); !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("the result lost its notice: %s", out)
			}
		})
	}
}

// A recorded "<call>|<item>" id is matched through the Responses item only;
// an ordinary result of another adapter that carries the call part is another
// call and keeps the notice pending.
func TestGAP0644CallPartOfAResponsesIDIsNotAKeyOnOtherAdapters(t *testing.T) {
	others := map[string]string{
		"chat":      `{"messages":[{"role":"tool","tool_call_id":"call_shared","content":"ordinary output"}]}`,
		"anthropic": `{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_shared","content":"ordinary output"}]}]}`,
		"bedrock":   `{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_shared","content":[{"text":"ordinary output"}]}}]}]}`,
		"gemini":    `{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"call_shared","name":"read","response":{"output":"ordinary output"}}}]}]}`,
	}
	for name, body := range others {
		t.Run(name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, "sess-a", body); out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("a result with the call part took the notice: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
		})
	}
	// The Responses result of the blocked item still takes it.
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
	if out := serveInSession(t, "sess-a", responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_1"})); !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the Responses result lost its notice: %s", out)
	}
}

// Two blocked Responses items of one call part are not told apart.
func TestGAP0644ResponsesItemsOfOneCallIDShowNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_x|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
	rememberOpenClawBlockNotice("read", "call_x|fc_2", "sess-a", []string{noticeTestRule}, "protected read")
	body := responsesBody("function_call_output", "call_x", [2]string{"call_x", "fc_1"}, [2]string{"call_x", "fc_2"})
	if out := serveInSession(t, "sess-a", body); out != noticeChatReply {
		t.Fatalf("two items shared a call part and one showed: %s", out)
	}
}

// The inspect route records the session the plugin sent, and notes the calls
// it allows, so a block of another session under the same id is ambiguous.
func TestGAP0644InspectRecordsTheSessionOfTheBlock(t *testing.T) {
	resetOpenClawBlockNotices(t)
	api := testAPIServerWithConfig(t, "action")
	_, blocked := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-a","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
	if blocked.Action != "block" {
		t.Fatalf("protected call: %+v", blocked)
	}
	if out := serveInSession(t, "sess-b", noticeChatReq()); out != noticeChatReply {
		t.Fatalf("another session took the notice: %s", out)
	}
	if out := serveInSession(t, "sess-a", noticeChatReq()); !noticeServed(out) {
		t.Fatalf("the blocked session did not get its notice: %s", out)
	}
}

func TestGAP0644InspectOfAnotherCallUnderTheSameIDMakesTheBlockAmbiguous(t *testing.T) {
	// The other call is made by another session, by the same session, or by a
	// session that sent none; it is inspected before or after the block, and the
	// ordinary result arrives first or the blocked one does.
	for _, other := range []string{"sess-b", "sess-a", ""} {
		for _, allowedFirst := range []bool{true, false} {
			resetOpenClawBlockNotices(t)
			api := testAPIServerWithConfig(t, "action")
			allowed := func() {
				_, v := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"callshared","session_id":"`+other+`","args":{"command":"echo hello"}}`)
				if v.Action != "allow" {
					t.Fatalf("benign call: %+v", v)
				}
			}
			if allowedFirst {
				allowed()
			}
			_, blocked := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"callshared","session_id":"sess-a","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
			if blocked.Action != "block" {
				t.Fatalf("protected call: %+v", blocked)
			}
			if !allowedFirst {
				allowed()
			}
			for _, result := range []string{"ordinary output", "blocked"} {
				if out := serveInSession(t, "sess-a", chatToolResult("callshared", result)); strings.Contains(out, openClawBlockNoticeMark) {
					t.Fatalf("other=%q allowedFirst=%v: a call id used twice showed a line on the %s result: %s", other, allowedFirst, result, out)
				}
			}
		}
	}
	// A claudecode inspect under the same id is not an OpenClaw call.
	resetOpenClawBlockNotices(t)
	api := testAPIServerWithConfig(t, "action")
	postInspectForConnector(t, api, "claudecode", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-b","args":{"command":"echo hello"}}`)
	postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-a","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
	if out := serveInSession(t, "sess-a", noticeChatReq()); !noticeServed(out) {
		t.Fatalf("another connector call hid the notice: %s", out)
	}
	// Benign twin: an allowed call under another id leaves the block shown.
	resetOpenClawBlockNotices(t)
	api = testAPIServerWithConfig(t, "action")
	postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_ok9","session_id":"sess-a","args":{"command":"echo hello"}}`)
	postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-a","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
	if out := serveInSession(t, "sess-a", noticeChatReq()); !noticeServed(out) {
		t.Fatalf("an unrelated allowed call hid the notice: %s", out)
	}
}

// The session header is the plugin's last-seen context. A request the plugin
// did not mark as having observed that session claims nothing, even when its
// header equals the session of the block and its result carries the blocked
// call id, and the block stays for the request that is marked.
func TestGAP0644RequestWithAStaleSessionHeaderTakesNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_x", "sess-a", []string{noticeTestRule}, "protected write")
	if out := serveStaleHeader(t, "sess-a", chatToolResult("call_x", "ordinary output of another session")); out != noticeChatReply || !openClawBlockNoticesPending() {
		t.Fatalf("an unmarked request took the notice: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
	}
	if out := serveInSession(t, "sess-a", chatToolResult("call_x", "blocked")); !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the marked request lost its notice: %s", out)
	}
}

// The marker only counts when it says 1.
func TestGAP0644OnlyTheMarkerValueOneBindsTheSession(t *testing.T) {
	for _, v := range []string{"", "0", "true", "yes"} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", "call_x", "sess-a", []string{noticeTestRule}, "protected write")
		var out string
		h := openClawBlockNoticeMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", noticeJSONType)
			_, _ = io.WriteString(w, noticeChatReply)
		}), func(*http.Request) bool { return true })
		req := httptest.NewRequest(http.MethodPost, "/v1/x", strings.NewReader(chatToolResult("call_x", "blocked")))
		req = req.WithContext(withThresholdConnector(req.Context(), "openclaw"))
		req.Header.Set(SessionIDHeader, "sess-a")
		req.Header.Set(SessionBoundHeader, v)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		out = rec.Body.String()
		if out != noticeChatReply || !openClawBlockNoticesPending() {
			t.Fatalf("marker %q bound the session: served=%v", v, noticeServed(out))
		}
	}
}
