// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
)

// GAP-0644: OpenClaw replay can rewrite the call id of a result in ways the id
// recorded at the block cannot predict (a nine character cap, a new id for a
// repeated call id). The letters-and-digits form of the id, cut to forty, is
// predictable and is matched (see replayToolCallID); any other id on the result
// leaves the tie unknown and nothing is shown: the notice stays pending for
// the result that carries the recorded id, or expires. The block text, the
// tool name and any quoting never decide it.
func TestGAP0644RewrittenResultIDShowsNothing(t *testing.T) {
	chat := func(id, text string) string {
		return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"` + text + `"}]}`
	}
	const blockText = "DefenseClaw: protected write"
	for _, c := range []struct{ name, recorded, req string }{
		{"thirty-nine character cap of a long id", "id_abcdefghijklmnopqrstuvwxyz0123456789LONG", chat("idabcdefghijklmnopqrstuvwxyz0123456789L", blockText)},
		{"new id of a repeated call id", "repeat.abc", chat("call_5052364cf5a38bda784960a6", blockText)},
		{"nine character form of the id", "abcdefghij", chat("abcdefghi", blockText)},
		{"unrelated id quoting the block text", "call_blk1", chat("call_5052364cf5a38bda784960a6", blockText)},
		{"idless result of the same tool", "call_blk1", `{"messages":[{"role":"tool","tool_name":"exec","content":"` + blockText + `"}]}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberOpenClawBlockNotice("exec", c.recorded, noticeTestSession, []string{noticeTestRule}, "protected write")
			out, _ := serveNoticeWith(t, noticeServe{reqBody: c.req, ctype: noticeJSONType, respBody: noticeChatReply})
			if out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("a result with an unknown id took the notice: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
			// The result that carries the recorded id still takes the held notice.
			out, _ = serveNoticeWith(t, noticeServe{reqBody: chat(c.recorded, blockText), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("the result with the recorded id did not take the held notice: %s", out)
			}
		})
	}
}
