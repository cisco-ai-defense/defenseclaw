// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// GAP-0644: the result of another call never takes the notice, whatever it
// says: even a result that quotes the block text word for word is the result
// of its own call. The blocked tool is exec and its call id is noticeTestCallID.
func TestGAP0644OnlyTheBlockedCallResultTakesTheNotice(t *testing.T) {
	const quoted = "DefenseClaw: protected write"
	type tc struct{ name, other, own string }
	cases := []tc{
		{"chat",
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"other-call","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"other-call","content":"QUOTE"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"QUOTE"}]}`},
		{"responses",
			`{"input":[{"type":"function_call","call_id":"other-call","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"other-call","output":"QUOTE"}]}`,
			`{"input":[{"type":"function_call_output","call_id":"call_blk1","output":"QUOTE"}]}`},
		{"anthropic",
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"other-call","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"other-call","content":"QUOTE"}]}]}`,
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":"QUOTE"}]}]}`},
		{"bedrock",
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"other-call","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"other-call","content":[{"text":"QUOTE"}]}}]}]}`,
			`{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"QUOTE"}]}}]}]}`},
		{"gemini",
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"other-call","name":"exec","response":{"text":"QUOTE"}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"call_blk1","name":"exec","response":{"error":"QUOTE"}}}]}]}`},
		{"ollama with call ids",
			`{"messages":[{"role":"tool","tool_call_id":"other-call","tool_name":"exec","content":"QUOTE"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","tool_name":"exec","content":"QUOTE"}]}`},
		{"chat result without any id",
			`{"messages":[{"role":"tool","content":"QUOTE"}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"call_blk1","content":"QUOTE"}]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "protected write")
			out, _ := serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.other, "QUOTE", quoted), ctype: noticeJSONType, respBody: noticeChatReply})
			if out != noticeChatReply || !openClawBlockNoticesPending() {
				t.Fatalf("another call result claimed the block: served=%v pending=%v", noticeServed(out), openClawBlockNoticesPending())
			}
			// A request that carries the other result and the blocked call own
			// result: the blocked one takes the notice, once.
			out, _ = serveNoticeWith(t, noticeServe{reqBody: strings.ReplaceAll(c.own, "QUOTE", quoted), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("the blocked call own result did not take the notice: %s", out)
			}
		})
	}
}

// The id of a result must equal the recorded id or its replay form, the letters
// and digits OpenClaw keeps of it (at most 40): no case folding, no trimming,
// no other cap and no prefix. Chat Completions, Anthropic, Bedrock and Gemini
// send the id back as it was recorded or in that replay form.
func TestGAP0644ResultIDMustEqualTheRecordedID(t *testing.T) {
	chat := func(id string) string {
		return `{"messages":[{"role":"tool","tool_call_id":"` + id + `","content":"blocked"}]}`
	}
	for _, tc := range []struct {
		recorded, sent string
		want           bool
	}{
		{"call_abc", "call_abc", true},
		{"call_abc|fc_123", "call_abc|fc_123", true}, // the full id sent back
		{"call_abc|fc_123", "call_abc", false},       // the head of a Responses id is another call here
		{"call.abc|fc_1", "call_abc", false},         // punctuation replaced: not the same id
		{"call.abc", "callabc", true},                // the replay form: letters and digits only
		{"call.abc", "call-abc", false},              // punctuation replaced, not dropped: not the replay form
		{"call_abc", "callabc", true},                // the replay form of an id with an underscore
		{"call_abc", "Callabc", false},               // the replay form keeps case
		{"call_abc", " callabc", false},              // and takes no spaces
		{"toolu_01ABCDEFGHIJ", "toolu01A", false},    // not the id
		{"abcdefghijklmnop", "abcdefghi", false},     // nine-character prefix
		{"call_abc", "call_abd", false},              // a different call
		{"call_abc", "call_abc2", false},             // a longer look-alike
		{"call_abc", "Call_ABC", false},              // case differs
		{"call_abc", "call_abc ", false},             // trailing space differs
		{"call_abc|fc_1", "fc_1", false},             // the item part is not the call
		{"call_abc|fc_1", "call_abc|fc_2", false},    // another item of the call id family
		{"|fc_1", "", false},                         // no call part, no result id
		{"", "call_abc", false},                      // no recorded id: nothing recorded
		{"call_abc", "", false},                      // no result id
	} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", tc.recorded, noticeTestSession, []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{reqBody: chat(tc.sent), ctype: noticeJSONType, respBody: noticeChatReply})
		wantPending := tc.recorded != "" && !tc.want
		if noticeServed(out) != tc.want || openClawBlockNoticesPending() != wantPending {
			t.Errorf("recorded %q, result id %q: served=%v pending=%v, want served=%v pending=%v",
				tc.recorded, tc.sent, noticeServed(out), openClawBlockNoticesPending(), tc.want, wantPending)
		}
	}
}

// OpenClaw names a Responses call "<call id>|<item id>" and the Responses
// request sends back the call id alone. That equivalence holds for a
// function_call_output item only.
func TestGAP0644ResponsesResultIDIsTheCallPartOfTheRecordedID(t *testing.T) {
	// The request carries the function_call item of the call (item id, if any)
	// and a function_call_output whose call_id is sent.
	responses := func(id, item string) string {
		return responsesBody("function_call_output", id, [2]string{id, item})
	}
	for _, tc := range []struct {
		recorded, sent, item string
		want                 bool
	}{
		{"call_abc|fc_123", "call_abc", "fc_123", true},  // the call part, tied to the item of its own request
		{"call_abc|fc_123", "call_abc", "fc_999", false}, // a sibling item of the same call part
		{"call_abc|fc_123", "call_abc", "", true},        // the replayed call carries no item id: the call part is the call
		{"call_abc|fc_123", "call_abc|fc_123", "", true}, // the full id sent back
		{"call_abc", "call_abc", "fc_1", true},
		{"call_abc|fc_1", "call_abd", "fc_1", false},
		{"call_abc|fc_1", "fc_1", "fc_1", false},
		{"call_abc|fc_1", "call_ab", "fc_1", false},
		{"|fc_1", "", "", false},
	} {
		resetOpenClawBlockNotices(t)
		rememberOpenClawBlockNotice("exec", tc.recorded, noticeTestSession, []string{noticeTestRule}, "r")
		out, _ := serveNoticeWith(t, noticeServe{reqBody: responses(tc.sent, tc.item), ctype: noticeJSONType, respBody: noticeChatReply})
		if noticeServed(out) != tc.want || openClawBlockNoticesPending() == tc.want {
			t.Errorf("recorded %q, responses call_id %q item %q: served=%v pending=%v, want served=%v", tc.recorded, tc.sent, tc.item, noticeServed(out), openClawBlockNoticesPending(), tc.want)
		}
	}
}
