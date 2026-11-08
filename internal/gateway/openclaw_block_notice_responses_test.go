// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// OpenClaw replays a Responses function_call without its item id unless it
// replays the reasoning item too, and sends the function_call_output back with
// the call id alone. The block was recorded under "<call id>|<item id>", so the
// result is the block through the call part when the request names no item of
// the call.
const (
	responsesBlockedID = "call_blk9|fc_0a1b"
	responsesReplyText = "I could not run that."
)

// responsesReasoningStream is the reply of a reasoning model over the Responses
// wire: a reasoning item first, then the message item at output index 1.
func responsesReasoningStream() string {
	frame := func(typ, data string) string { return "event: " + typ + "\ndata: " + data + "\n\n" }
	text := `"` + responsesReplyText + `"`
	return frame("response.created", `{"type":"response.created","response":{"id":"r1","output":[]}}`) +
		frame("response.output_item.added", `{"type":"response.output_item.added","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[]}}`) +
		frame("response.output_item.done", `{"type":"response.output_item.done","output_index":0,"item":{"type":"reasoning","id":"rs_1","summary":[]}}`) +
		frame("response.output_item.added", `{"type":"response.output_item.added","output_index":1,"item":{"type":"message","id":"msg_1","content":[]}}`) +
		frame("response.content_part.added", `{"type":"response.content_part.added","item_id":"msg_1","output_index":1,"content_index":0,"part":{"type":"output_text","text":""}}`) +
		frame("response.output_text.delta", `{"type":"response.output_text.delta","item_id":"msg_1","output_index":1,"content_index":0,"delta":"I could not "}`) +
		frame("response.output_text.delta", `{"type":"response.output_text.delta","item_id":"msg_1","output_index":1,"content_index":0,"delta":"run that."}`) +
		frame("response.output_text.done", `{"type":"response.output_text.done","item_id":"msg_1","output_index":1,"content_index":0,"text":`+text+`}`) +
		frame("response.content_part.done", `{"type":"response.content_part.done","item_id":"msg_1","output_index":1,"content_index":0,"part":{"type":"output_text","text":`+text+`}}`) +
		frame("response.output_item.done", `{"type":"response.output_item.done","output_index":1,"item":{"type":"message","id":"msg_1","content":[{"type":"output_text","text":`+text+`}]}}`) +
		frame("response.completed", `{"type":"response.completed","response":{"id":"r1","output":[{"type":"reasoning","id":"rs_1","summary":[]},{"type":"message","id":"msg_1","content":[{"type":"output_text","text":`+text+`}]}]}}`)
}

// The result of a blocked call whose replayed function_call carries no item id
// shows the line once, on the first text of the streamed reply and on the
// finished item OpenClaw reads, and nowhere else.
func TestGAP0644ResponsesCallReplayedWithoutItemIDShowsTheLine(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"function_call without an id", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""})},
		{"no function_call item in the request", responsesBody("function_call_output", "call_blk9")},
		{"another call with an id beside it", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_other", "fc_77"})},
		{"the full id sent back", responsesBody("function_call_output", responsesBlockedID)},
		{"item id replayed with the reasoning", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", "fc_0a1b"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "matched: ssh authorized_keys write")
			out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: tc.body, ctype: "text/event-stream", respBody: responsesReasoningStream()})
			frames := sseData(t, out)
			line := openClawBlockNoticeLine("exec", []string{noticeTestRule}, "matched: ssh authorized_keys write")
			if got, want := streamText(frames, "responses"), line+"\n\n"+responsesReplyText; got != want {
				t.Fatalf("streamed text = %q, want %q", got, want)
			}
			// OpenClaw takes the finished message item over the streamed text.
			for _, f := range frames {
				if f["type"] != "response.output_item.done" {
					continue
				}
				item, _ := f["item"].(map[string]any)
				if item["type"] != "message" {
					continue
				}
				part := item["content"].([]any)[0].(map[string]any)
				if !strings.HasPrefix(part["text"].(string), line+"\n\n") {
					t.Fatalf("finished item text = %q", part["text"])
				}
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the notice stayed pending after it was shown")
			}
			again, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: tc.body, ctype: "text/event-stream", respBody: responsesReasoningStream()})
			if strings.Contains(again, openClawBlockNoticeMark) {
				t.Fatal("the line was shown twice")
			}
		})
	}
}

// The call part is the call only when nothing else is inspected under it: a
// sibling item of the call part, inspected before or after the block, makes the
// block ambiguous, and a request that names an item of the call other than the
// blocked one is not the block.
func TestGAP0644ResponsesCallPartSharedByAnotherInspectedCallShowsNothing(t *testing.T) {
	idless := responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""})
	for _, tc := range []struct {
		name  string
		setup func()
		body  string
	}{
		{"sibling allowed before the block", func() {
			observeOpenClawToolCall("call_blk9|fc_beef")
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
		}, idless},
		{"sibling allowed after the block", func() {
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
			observeOpenClawToolCall("call_blk9|fc_beef")
		}, idless},
		{"sibling blocked in the same session", func() {
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
			rememberOpenClawBlockNotice("read", "call_blk9|fc_beef", noticeTestSession, []string{noticeTestRule}, "r")
		}, idless},
		{"same call id allowed in another session", func() {
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
			observeOpenClawToolCall("call_blk9")
		}, idless},
		{"request names another item of the call", func() {
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
		}, responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", "fc_beef"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			tc.setup()
			out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: tc.body, ctype: "text/event-stream", respBody: responsesReasoningStream()})
			if strings.Contains(out, openClawBlockNoticeMark) {
				t.Fatalf("an unclear tie showed a line: %s", out)
			}
		})
	}
}

// An ordinary Responses call that was inspected and allowed leaves no line, and
// a recorded block of an id without "|" still needs the exact call id.
func TestGAP0644ResponsesAllowedCallAndOtherCallIDShowNothing(t *testing.T) {
	resetOpenClawBlockNotices(t)
	observeOpenClawToolCall("call_ok1|fc_11")
	out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: responsesBody("function_call_output", "call_ok1"), ctype: "text/event-stream", respBody: responsesReasoningStream()})
	if strings.Contains(out, openClawBlockNoticeMark) {
		t.Fatalf("an allowed call got a line: %s", out)
	}
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", "call_blk9|fc_0a1b", noticeTestSession, []string{noticeTestRule}, "r")
	out, _ = serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: responsesBody("function_call_output", "call_blk"), ctype: "text/event-stream", respBody: responsesReasoningStream()})
	if strings.Contains(out, openClawBlockNoticeMark) || !openClawBlockNoticesPending() {
		t.Fatalf("a look-alike call id took the block: %s", out)
	}
}

// Two function_call items of one call part, none with an item id, are two
// candidate calls to the one result that names the call part: the line waits
// for a tie it can prove, and a single anonymous item of the same shape (the
// shape OpenClaw writes) still shows it.
func TestGAP0644ResponsesSeveralAnonymousItemsOfOneCallShowNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"one anonymous item", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}), true},
		{"two anonymous items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}), false},
		{"three anonymous items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}), false},
		{"one anonymous and one named item", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", "fc_beef"}), false},
		{"anonymous item beside an anonymous item of another call", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_other", ""}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "matched: ssh authorized_keys write")
			out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", reqBody: tc.body, ctype: "text/event-stream", respBody: responsesReasoningStream()})
			if got := strings.Contains(out, openClawBlockNoticeMark); got != tc.want {
				t.Fatalf("line shown = %t, want %t:\n%s", got, tc.want, out)
			}
		})
	}
}

// A result the request ties to no single call (several items of its call part) consumes the block with nothing shown. A
// later replay of the same result with fewer items, after a different call
// renewed the session marker, must not attach the line to an unrelated reply.
func TestGAP0644ResponsesAmbiguousResultStaysQuietOnLaterReplay(t *testing.T) {
	const responsesDone = `{"id":"r1","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"reply"}]}]}`
	later := `{"input":[{"type":"function_call_output","call_id":"call_blk9","output":"old result"},{"type":"function_call","call_id":"call_new"},{"type":"function_call_output","call_id":"call_new","output":"new result"}]}`
	for _, tc := range []struct {
		name string
		body string
	}{
		{"two anonymous items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""})},
		{"anonymous and named item", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", "fc_beef"})},
		{"two named items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", "fc_beef"}, [2]string{"call_blk9", "fc_0a1b"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
			for i, body := range []string{tc.body, later} {
				if i == 1 {
					observeOpenClawToolCall("call_new|fc_new")
				}
				out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", session: noticeTestSession, reqBody: body, ctype: "application/json", respBody: responsesDone})
				if strings.Contains(out, openClawBlockNoticeMark) {
					t.Fatalf("request %d showed a line for an ambiguous result: %s", i+1, out)
				}
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the ambiguous block is still pending")
			}
		})
	}
}

// The benign twins: a result of another call part leaves the block pending for
// its own result, and one anonymous item (the OpenClaw replay shape) still shows
// the line on the later request.
func TestGAP0644ResponsesUnrelatedResultKeepsBlockForItsOwnReplay(t *testing.T) {
	const responsesDone = `{"id":"r1","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"reply"}]}]}`
	resetOpenClawBlockNotices(t)
	rememberOpenClawBlockNotice("exec", responsesBlockedID, noticeTestSession, []string{noticeTestRule}, "r")
	other := responsesBody("function_call_output", "call_other", [2]string{"call_other", ""}, [2]string{"call_other", ""})
	out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", session: noticeTestSession, reqBody: other, ctype: "application/json", respBody: responsesDone})
	if strings.Contains(out, openClawBlockNoticeMark) || !openClawBlockNoticesPending() {
		t.Fatalf("an unrelated ambiguous result touched the block: %s", out)
	}
	own := responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""})
	out, _ = serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", session: noticeTestSession, reqBody: own, ctype: "application/json", respBody: responsesDone})
	if !strings.Contains(out, openClawBlockNoticeMark) || openClawBlockNoticesPending() {
		t.Fatalf("the block result did not show the line once: %s", out)
	}
}

// A block recorded under the call id alone (OpenClaw gave the call no item id)
// is held to the same rule as "<call>|<item>": when the request shows several
// function_call items of that call, the result is not provably the block's, so
// the block is consumed with nothing shown, on the reply and on a later replay.
// One item, named or not, still shows the line.
func TestGAP0644ResponsesCallOnlyBlockWithSeveralItemsShowsNothing(t *testing.T) {
	const responsesDone = `{"id":"r1","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"reply"}]}]}`
	later := `{"input":[{"type":"function_call_output","call_id":"call_blk9","output":"old result"},{"type":"function_call","call_id":"call_new"},{"type":"function_call_output","call_id":"call_new","output":"new result"}]}`
	for _, tc := range []struct {
		name string
		body string
		want bool
	}{
		{"two anonymous items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}), false},
		{"three anonymous items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}, [2]string{"call_blk9", ""}), false},
		{"two named items", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", "fc_1"}, [2]string{"call_blk9", "fc_2"}), false},
		{"one anonymous item", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", ""}), true},
		{"one named item", responsesBody("function_call_output", "call_blk9", [2]string{"call_blk9", "fc_1"}), true},
		{"result alone", responsesBody("function_call_output", "call_blk9"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", "call_blk9", noticeTestSession, []string{noticeTestRule}, "r")
			for i, body := range []string{tc.body, later} {
				if i == 1 {
					observeOpenClawToolCall("call_new|fc_new")
				}
				out, _ := serveNoticeWith(t, noticeServe{path: "/openai/v1/responses", session: noticeTestSession, reqBody: body, ctype: "application/json", respBody: responsesDone})
				if got := strings.Contains(out, openClawBlockNoticeMark); got != (tc.want && i == 0) {
					t.Fatalf("request %d: line shown = %t, want %t: %s", i+1, got, tc.want && i == 0, out)
				}
			}
			if openClawBlockNoticesPending() {
				t.Fatal("the block is still pending")
			}
		})
	}
}
