// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
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

func serveInSession(t *testing.T, session, body string) string {
	t.Helper()
	out, _ := serveNoticeWith(t, noticeServe{session: session, reqBody: body, ctype: noticeJSONType, respBody: noticeChatReply})
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
// is the same call; two empty sessions (a plugin that sends none) are equal.
func TestGAP0644SessionMustEqualTheRecordedOne(t *testing.T) {
	for _, tc := range []struct {
		name, recorded, request string
		want                    bool
	}{
		{"same session", "sess-a", "sess-a", true},
		{"neither names a session", "", "", true},
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
			if !tc.want {
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

// An allowed call of another session that used the same call id makes a block
// ambiguous, whichever was inspected first. The header of an ordinary result
// can be stale, so this is how the gateway knows the id is shared.
func TestGAP0644CallOfAnotherSessionUnderTheSameIDMakesTheBlockAmbiguous(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func()
	}{
		{"allowed call inspected first", func() {
			observeOpenClawToolCall("call_shared", "sess-b")
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
		}},
		{"allowed call inspected after", func() {
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
			observeOpenClawToolCall("call_shared", "sess-b")
		}},
		{"call of a session that sent none", func() {
			observeOpenClawToolCall("call_shared", "")
			rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "protected write")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			tc.setup()
			// A stale header: the ordinary result of the other session arrives
			// with the session of the block.
			if out := serveInSession(t, "sess-a", chatToolResult("call_shared", "ordinary output")); strings.Contains(out, openClawBlockNoticeMark) {
				t.Fatalf("a result of a shared id showed a line: %s", out)
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the ambiguous block stayed pending")
			}
		})
	}
}

// Benign twins: calls of the same session under the same id (a local model
// that numbers its calls), calls under other ids, and a call of another
// session that is older than the memory of the gateway do not make a block
// ambiguous.
func TestGAP0644UnrelatedCallsLeaveTheBlockShown(t *testing.T) {
	resetOpenClawBlockNotices(t)
	observeOpenClawToolCall("call_x", "sess-a")
	observeOpenClawToolCall("call_other", "sess-b")
	observeOpenClawToolCall("", "sess-b")
	openClawBlockNotices.mu.Lock()
	openClawBlockNotices.seen = append(openClawBlockNotices.seen, openClawSeenCall{callID: "call_x", session: "sess-b", at: time.Now().Add(-openClawSeenCallTTL - time.Minute)})
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
		observeOpenClawToolCall(fmt.Sprintf("call_%d", i), "sess-a")
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
	for _, session := range []string{"", "sess-a"} {
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
// request does not name exactly one item of the call shows nothing.
func TestGAP0644ResponsesResultThatCannotBeTiedToOneItemShowsNothing(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"custom tool output, item present", responsesBody("custom_tool_call_output", "call_shared", [2]string{"call_shared", "fc_1"})},
		{"custom tool output, no item", responsesBody("custom_tool_call_output", "call_shared")},
		{"no function_call item", responsesBody("function_call_output", "call_shared")},
		{"function_call without an item id", responsesBody("function_call_output", "call_shared", [2]string{"call_shared", ""})},
		{"two items of one call part", responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_1"}, [2]string{"call_shared", "fc_2"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "sess-a", []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, "sess-a", tc.body); out != noticeChatReply || !openClawBlockNoticesPending() {
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
			rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "", []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, "", body); out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("a result with the call part took the notice: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
		})
	}
	// The Responses result of the blocked item still takes it.
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "", []string{noticeTestRule}, "protected write")
	if out := serveInSession(t, "", responsesBody("function_call_output", "call_shared", [2]string{"call_shared", "fc_1"})); !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the Responses result lost its notice: %s", out)
	}
}

// Two blocked Responses items of one call part are not told apart.
func TestGAP0644ResponsesItemsOfOneCallIDShowNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_x|fc_1", "", []string{noticeTestRule}, "protected write")
	rememberOpenClawBlockNotice("read", "call_x|fc_2", "", []string{noticeTestRule}, "protected read")
	body := responsesBody("function_call_output", "call_x", [2]string{"call_x", "fc_1"}, [2]string{"call_x", "fc_2"})
	if out := serveInSession(t, "", body); out != noticeChatReply {
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

func TestGAP0644InspectOfAnAllowedCallInAnotherSessionMakesTheBlockAmbiguous(t *testing.T) {
	for _, allowedFirst := range []bool{true, false} {
		resetOpenClawBlockNotices(t)
		api := testAPIServerWithConfig(t, "action")
		allowed := func() {
			_, v := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-b","args":{"command":"echo hello"}}`)
			if v.Action != "allow" {
				t.Fatalf("benign call: %+v", v)
			}
		}
		if allowedFirst {
			allowed()
		}
		_, blocked := postInspectForConnector(t, api, "openclaw", `{"tool":"exec","tool_call_id":"call_blk1","session_id":"sess-a","args":{"command":"echo k >> ~/.ssh/authorized_keys"}}`)
		if blocked.Action != "block" {
			t.Fatalf("protected call: %+v", blocked)
		}
		if !allowedFirst {
			allowed()
		}
		if out := serveInSession(t, "sess-a", noticeChatReq()); strings.Contains(out, openClawBlockNoticeMark) {
			t.Fatalf("allowedFirst=%v: a call id two sessions used showed a line: %s", allowedFirst, out)
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
}
