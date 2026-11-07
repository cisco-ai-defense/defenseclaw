// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// GAP-0644: OpenClaw replay rewrites the call id of a result in ways the id
// recorded at the block cannot predict (a forty or nine character cap, a new
// id for a repeated call id). The block text decides such a result; an
// ordinary result that echoes the reference never does, whatever its id or
// tool.
func TestGAP0644ReplayRewrittenIDDecidedByBlockText(t *testing.T) {
	const blockText = "DefenseClaw: protected write (ref REF)"
	const echoText = "ordinary echo REF"
	chat := func(id, text string) string {
		return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"` + text + `"}]}`
	}
	ollama := func(text string) string {
		return `{"messages":[{"role":"tool","tool_name":"exec","content":"` + text + `"}]}`
	}
	for _, c := range []struct {
		name, recorded, req string
		want                bool
	}{
		{"forty character cap of a long id", "id_abcdefghijklmnopqrstuvwxyz0123456789LONG", chat("idabcdefghijklmnopqrstuvwxyz0123456789LO", blockText), true},
		{"new id of a repeated call id", "repeat.abc", chat("call_5052364cf5a38bda784960a6", blockText), true},
		{"nine character form of the id", "abcdefghij", chat("abcdefghi", blockText), true},
		{"idless result of the same tool", "call_blk1", ollama(blockText), true},
		{"echo under the nine character form", "abcdefghij", chat("abcdefghi", echoText), false},
		{"echo under a forty character cap", "id_abcdefghijklmnopqrstuvwxyz0123456789LONG", chat("idabcdefghijklmnopqrstuvwxyz0123456789LO", echoText), false},
		{"echo under an unrelated id", "call_blk1", chat("call_5052364cf5a38bda784960a6", echoText), false},
		{"idless echo of the same tool", "call_blk1", ollama(echoText), false},
		{"block text of another reference", "call_blk1", chat("call_5052364cf5a38bda784960a6", "DefenseClaw: protected write (ref dc-0000000000000000) REF"), false},
		{"reference before the block mark", "call_blk1", chat("call_5052364cf5a38bda784960a6", "(ref REF) DefenseClaw: later"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			ref := rememberOpenClawBlockNotice("exec", c.recorded, []string{noticeTestRule}, "protected write")
			out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.req, "REF", ref), ctype: noticeJSONType, respBody: noticeChatReply})
			if noticeServed(out) != c.want || openClawBlockNoticesPending() == c.want {
				t.Fatalf("served=%v pending=%v, want served=%v", noticeServed(out), openClawBlockNoticesPending(), c.want)
			}
			if !c.want {
				// The blocked call own result still takes the held notice.
				out, _ = serveNoticeWith(t, noticeServe{reqBody: noticeChatReq(ref), ctype: noticeJSONType, respBody: noticeChatReply})
				if c.recorded == "call_blk1" && (!noticeServed(out) || openClawBlockNoticesPending()) {
					t.Fatalf("the blocked result did not take the held notice: %s", out)
				}
			}
		})
	}
}
