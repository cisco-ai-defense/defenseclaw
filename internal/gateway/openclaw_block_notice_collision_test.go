// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
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

// Benign twin: a result of the blocked session itself, a request that names no
// session, and a block recorded without a session all still show the notice.
func TestGAP0644SessionOnlyVetoesAMismatch(t *testing.T) {
	for _, tc := range []struct{ name, recorded, request string }{
		{"same session", "sess-a", "sess-a"},
		{"request names no session", "sess-a", ""},
		{"block recorded without a session", "", "sess-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_x", tc.recorded, []string{noticeTestRule}, "protected write")
			if out := serveInSession(t, tc.request, chatToolResult("call_x", "blocked")); !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("notice not shown: %s", out)
			}
		})
	}
}

// Two blocks of different sessions that share an id each show their own
// reason; the session of the request picks the block.
func TestGAP0644TwoSessionsSameCallIDEachShowTheirOwnBlock(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared", "sess-a", []string{noticeTestRule}, "first protected write")
	rememberOpenClawBlockNotice("read", "call_shared", "sess-b", []string{noticeTestRule}, "second protected read")
	out := serveInSession(t, "sess-a", chatToolResult("call_shared", "blocked"))
	if !strings.Contains(out, "Tool call blocked: exec") || strings.Contains(out, "Tool call blocked: read") {
		t.Fatalf("session a showed the wrong block: %s", out)
	}
	out = serveInSession(t, "sess-b", chatToolResult("call_shared", "blocked"))
	if !strings.Contains(out, "Tool call blocked: read") || strings.Contains(out, "Tool call blocked: exec") || openClawBlockNoticesPending() {
		t.Fatalf("session b showed the wrong block: %s", out)
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

// Benign twin: a retry of the same inspect call records the same block and
// still shows it once.
func TestGAP0644RetriedInspectOfOneBlockShowsItOnce(t *testing.T) {
	resetOpenClawBlockNotices(t)
	for i := 0; i < 2; i++ {
		rememberOpenClawBlockNotice("exec", "call_x", "sess-a", []string{noticeTestRule}, "protected write")
	}
	out := serveInSession(t, "sess-a", chatToolResult("call_x", "blocked"))
	if strings.Count(out, openClawBlockNoticeMark) != 1 || openClawBlockNoticesPending() {
		t.Fatalf("retried block: %s", out)
	}
}

// A recorded "<call>|<item>" id is matched by its call part on the Responses
// adapter only; an ordinary result of another adapter that carries the call
// part is another call and keeps the notice pending.
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
	// The Responses result of the blocked call still takes it.
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_shared|fc_1", "", []string{noticeTestRule}, "protected write")
	responses := `{"input":[{"type":"function_call","call_id":"call_shared","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"call_shared","output":"blocked"}]}`
	if out := serveInSession(t, "", responses); !noticeServed(out) || openClawBlockNoticesPending() {
		t.Fatalf("the Responses result lost its notice: %s", out)
	}
}

// Two Responses items of one call id are not told apart by the call part.
func TestGAP0644ResponsesItemsOfOneCallIDShowNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_x|fc_1", "", []string{noticeTestRule}, "protected write")
	rememberOpenClawBlockNotice("read", "call_x|fc_2", "", []string{noticeTestRule}, "protected read")
	body := `{"input":[{"type":"function_call_output","call_id":"call_x","output":"blocked"}]}`
	if out := serveInSession(t, "", body); out != noticeChatReply {
		t.Fatalf("two items shared a call part and one showed: %s", out)
	}
}

// The inspect route records the session the plugin sent.
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
