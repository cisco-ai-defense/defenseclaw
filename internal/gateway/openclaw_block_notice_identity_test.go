// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// GAP-0644: a result that echoes the pending reference takes the notice only
// when it is the result of the blocked call. The blocked tool is exec and its
// call id is noticeTestCallID.
func TestGAP0644OnlyTheBlockedCallResultTakesTheNotice(t *testing.T) {
	type tc struct{ name, ordinary, own string }
	cases := []tc{
		{"chat",
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"other-call","type":"function","function":{"name":"echo","arguments":"{}"}}]},{"role":"tool","tool_call_id":"other-call","content":"ordinary echo REF"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"blocked (ref REF)"}]}`},
		{"chat same tool other call",
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"other-call","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"other-call","content":"ordinary echo REF"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"blocked (ref REF)"}]}`},
		{"responses",
			`{"input":[{"type":"function_call","call_id":"other-call","name":"echo","arguments":"{}"},{"type":"function_call_output","call_id":"other-call","output":"ordinary echo REF"}]}`,
			`{"input":[{"type":"function_call_output","call_id":"call_blk1","output":"blocked (ref REF)"}]}`},
		{"responses same tool other call",
			`{"input":[{"type":"function_call","call_id":"other-call","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"other-call","output":"ordinary echo REF"}]}`,
			`{"input":[{"type":"function_call_output","call_id":"call_blk1","output":"blocked (ref REF)"}]}`},
		{"anthropic",
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"other-call","name":"echo","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"other-call","content":"ordinary echo REF"}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":"blocked (ref REF)"}]}]}`},
		{"anthropic same tool other call",
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"other-call","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"other-call","content":"ordinary echo REF"}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":"blocked (ref REF)"}]}]}`},
		{"bedrock",
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"other-call","name":"echo","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"other-call","content":[{"text":"ordinary echo REF"}]}}]}]}`,
			`{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"blocked (ref REF)"}]}}]}]}`},
		{"bedrock same tool other call",
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"other-call","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"other-call","content":[{"text":"ordinary echo REF"}]}}]}]}`,
			`{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"blocked (ref REF)"}]}}]}]}`},
		// Providers whose results carry no call id: the tool name decides.
		{"ollama other tool",
			`{"messages":[{"role":"tool","tool_name":"echo","content":"ordinary echo REF"}]}`,
			`{"messages":[{"role":"tool","tool_name":"exec","content":"DefenseClaw: blocked (ref REF)"}]}`},
		{"ollama no tool name",
			`{"messages":[{"role":"tool","content":"ordinary echo REF"}]}`,
			`{"messages":[{"role":"tool","tool_name":"exec","content":"DefenseClaw: blocked (ref REF)"}]}`},
		{"gemini other tool",
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"echo","response":{"text":"ordinary echo REF"}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"DefenseClaw: blocked (ref REF)"}}}]}]}`},
		{"gemini other call id",
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"other-call","name":"exec","response":{"text":"ordinary echo REF"}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"call_blk1","name":"exec","response":{"error":"DefenseClaw: blocked (ref REF)"}}}]}]}`},
		{"chat result without any id",
			`{"messages":[{"role":"tool","content":"ordinary echo REF"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"blocked (ref REF)"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			ref := rememberTestNotice("exec", []string{noticeTestRule}, "protected write")
			out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.ordinary, "REF", ref), ctype: noticeJSONType, respBody: noticeChatReply})
			if out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("another call's result claimed the block: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
			// A request that carries the other result and the blocked call's
			// own result: the blocked one takes the notice, once.
			out, _ = serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.own, "REF", ref), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("the blocked call's own result did not take the notice: %s", out)
			}
		})
	}
}

// The ids a provider adapter may send back for the blocked call that depend on
// the id alone still tie a result that only repeats the reference to it; the
// ids that do not are decided by the block text.
func TestGAP0644ProviderRewritesOfTheCallIDStillMatch(t *testing.T) {
	chat := func(id, ref string) string {
		return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"blocked (ref ` + ref + `)"}]}`
	}
	for _, tc := range []struct {
		recorded, sent string
		want           bool
	}{
		{"call_abc|fc_123", "call_abc", true},     // Responses "<call>|<item>"
		{"call.abc|fc_1", "call_abc", true},       // characters outside the set replaced
		{"call.abc", "callabc", true},             // letters and digits only
		{"toolu_01ABCDEFGHIJ", "toolu01A", false}, // not a form of the id
		{"abcdefghijklmnop", "abcdefghi", false},  // nine-character form: only the block text ties it (see the replay test)
		{"call_abc", "call_abd", false},           // a different call
		{"call_abc", "call_abc2", false},          // a longer look-alike
		{"", "call_abc", false},                   // no recorded id
		{"call_abc", "", false},                   // no result id and no tool name
	} {
		resetOpenClawBlockNotices(t)
		ref := rememberOpenClawBlockNotice("exec", tc.recorded, []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{reqBody: chat(tc.sent, ref), ctype: noticeJSONType, respBody: noticeChatReply})
		if noticeServed(out) != tc.want || openClawBlockNoticesPending() == tc.want {
			t.Errorf("recorded %q, result id %q: served=%v pending=%v, want served=%v", tc.recorded, tc.sent, noticeServed(out), openClawBlockNoticesPending(), tc.want)
		}
	}
}
