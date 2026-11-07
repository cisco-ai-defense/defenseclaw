// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// Review 4 (R4-1, R4-2): the reference is read from the result content field of
// each provider request after the body is decoded. For every adapter: the
// exact result takes the notice once, a JSON-escaped spelling of the same
// reference takes it too, and the same token as a result or call id, or as
// tool definition data shaped like a result, takes nothing.
func TestGAP0644ResultContentFieldPerAdapter(t *testing.T) {
	// escRef is the reference with its first letter written as a JSON escape.
	const escRef = `\u0064c-`
	adapters := []struct {
		name string
		// result carries REF in the result content; id carries REF only in
		// the ids of an ordinary result; schema carries REF in tool
		// definition data shaped like a result.
		result, id, schema string
	}{
		{"chat",
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"call_blk1","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"call_blk1","content":"blocked (ref REF)"}]}`,
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"REF","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"REF","content":"ordinary output"}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"x":{"type":"object","default":{"role":"tool","type":"tool_result","content":"REF"}}}}}}]}`},
		{"ollama",
			`{"messages":[{"role":"tool","tool_name":"exec","content":"blocked (ref REF)"}]}`,
			`{"messages":[{"role":"tool","tool_name":"REF","content":"ordinary output"}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"properties":{"x":{"default":{"role":"tool","content":"REF"}}}}}}]}`},
		{"responses",
			`{"input":[{"type":"function_call","call_id":"call_blk1","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"call_blk1","output":"blocked (ref REF)"}]}`,
			`{"input":[{"type":"function_call","call_id":"REF","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"REF","output":"ordinary output"}]}`,
			`{"input":"hi","tools":[{"type":"function","name":"f","parameters":{"properties":{"x":{"default":{"type":"function_call_output","output":"REF"}}}}}]}`},
		{"anthropic",
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"call_blk1","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_blk1","content":"blocked (ref REF)"}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"REF","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"REF","content":"ordinary output"}]}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"properties":{"x":{"default":{"type":"tool_result","content":"REF"}}}}}]}`},
		{"bedrock",
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"call_blk1","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"call_blk1","content":[{"text":"blocked (ref REF)"}]}}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"REF","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"REF","content":[{"text":"ordinary output"}]}}]}]}`,
			`{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":{"properties":{"x":{"default":{"toolResult":{"content":[{"text":"REF"}]}}}}}}}}]}}`},
		{"gemini",
			`{"contents":[{"role":"model","parts":[{"functionCall":{"name":"exec","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"name":"exec","response":{"error":"blocked (ref REF)"}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"REF","response":{"ok":true}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f","parameters":{"properties":{"x":{"default":{"functionResponse":{"response":"REF"}}}}}}]}]}`},
	}
	for _, a := range adapters {
		t.Run(a.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			ref := rememberTestNotice("exec", []string{noticeTestRule}, "r")
			spell := func(body, with string) string { return strings.ReplaceAll(body, "REF", with) }
			// Result ids and tool definition data never take the notice.
			for _, c := range []struct{ name, body string }{{"result id", a.id}, {"tool definition data", a.schema}} {
				out, _ := serveNoticeWith(t, noticeServe{reqBody: spell(c.body, ref), ctype: noticeJSONType, respBody: noticeChatReply})
				if out != noticeChatReply || !openClawBlockNoticesPending() {
					t.Fatalf("%s: %s took the notice: %s", a.name, c.name, out)
				}
			}
			// The escaped spelling of the reference in the result is the reference.
			escaped := strings.Replace(ref, "dc-", escRef, 1)
			out, _ := serveNoticeWith(t, noticeServe{reqBody: spell(a.result, escaped), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("%s: escaped reference in the blocked result lost the notice: %s", a.name, out)
			}
			// The exact result takes it, once.
			resetOpenClawBlockNotices(t)
			ref = rememberTestNotice("exec", []string{noticeTestRule}, "r")
			out, _ = serveNoticeWith(t, noticeServe{reqBody: spell(a.result, ref), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("%s: the blocked result did not show exactly one notice: %s", a.name, out)
			}
		})
	}
}
