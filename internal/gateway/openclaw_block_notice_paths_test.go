// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// The call id is read from the id field of the tool-result message of each
// provider request after the body is decoded. For every adapter: the exact
// result takes the notice once, a JSON-escaped spelling of the same id takes
// it too, and the same token as the id of the call itself, as tool definition
// data shaped like a result, or in the words of another call result takes
// nothing.
func TestGAP0644ResultIDFieldPerAdapter(t *testing.T) {
	// escID is the id with its underscore written as a JSON escape.
	const escID = `call\u005fblk1`
	adapters := []struct {
		name string
		// result carries the id on the tool-result message; call carries it
		// only on the call; schema carries it in tool definition data shaped
		// like a result; quoted is the result of another call that quotes
		// the block text and the id.
		result, call, schema, quoted string
	}{
		{"chat",
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"@ID@","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"@ID@","content":"DefenseClaw: blocked"}]}`,
			`{"messages":[{"role":"assistant","tool_calls":[{"id":"@ID@","type":"function","function":{"name":"exec","arguments":"{}"}}]},{"role":"tool","tool_call_id":"ok","content":"ordinary output"}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object","properties":{"x":{"type":"object","default":{"role":"tool","type":"tool_result","tool_call_id":"@ID@"}}}}}}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"other","content":"DefenseClaw: blocked @ID@"}]}`},
		{"ollama",
			`{"messages":[{"role":"tool","tool_call_id":"@ID@","tool_name":"exec","content":"DefenseClaw: blocked"}]}`,
			`{"messages":[{"role":"tool","tool_name":"@ID@","content":"ordinary output"}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"properties":{"x":{"default":{"role":"tool","tool_call_id":"@ID@"}}}}}}]}`,
			`{"messages":[{"role":"tool","tool_call_id":"other","tool_name":"exec","content":"DefenseClaw: blocked @ID@"}]}`},
		{"responses",
			`{"input":[{"type":"function_call","call_id":"@ID@","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"@ID@","output":"DefenseClaw: blocked"}]}`,
			`{"input":[{"type":"function_call","call_id":"@ID@","name":"exec","arguments":"{}"},{"type":"function_call_output","call_id":"ok","output":"ordinary output"}]}`,
			`{"input":"hi","tools":[{"type":"function","name":"f","parameters":{"properties":{"x":{"default":{"type":"function_call_output","call_id":"@ID@"}}}}}]}`,
			`{"input":[{"type":"function_call_output","call_id":"other","output":"DefenseClaw: blocked @ID@"}]}`},
		{"anthropic",
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"@ID@","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"@ID@","content":"DefenseClaw: blocked"}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"@ID@","name":"exec","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"ok","content":"ordinary output"}]}]}`,
			`{"messages":[{"role":"user","content":"hi"}],"tools":[{"name":"f","input_schema":{"properties":{"x":{"default":{"type":"tool_result","tool_use_id":"@ID@"}}}}}]}`,
			`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"other","content":"DefenseClaw: blocked @ID@"}]}]}`},
		{"bedrock",
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"@ID@","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"@ID@","content":[{"text":"DefenseClaw: blocked"}]}}]}]}`,
			`{"messages":[{"role":"assistant","content":[{"toolUse":{"toolUseId":"@ID@","name":"exec","input":{}}}]},{"role":"user","content":[{"toolResult":{"toolUseId":"ok","content":[{"text":"ordinary output"}]}}]}]}`,
			`{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"f","inputSchema":{"json":{"properties":{"x":{"default":{"toolResult":{"toolUseId":"@ID@"}}}}}}}}]}}`,
			`{"messages":[{"role":"user","content":[{"toolResult":{"toolUseId":"other","content":[{"text":"DefenseClaw: blocked @ID@"}]}}]}]}`},
		{"gemini",
			`{"contents":[{"role":"model","parts":[{"functionCall":{"id":"@ID@","name":"exec","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"id":"@ID@","name":"exec","response":{"error":"DefenseClaw: blocked"}}}]}]}`,
			`{"contents":[{"role":"model","parts":[{"functionCall":{"id":"@ID@","name":"exec","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"id":"ok","name":"exec","response":{"ok":true}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"f","parameters":{"properties":{"x":{"default":{"functionResponse":{"id":"@ID@"}}}}}}]}]}`,
			`{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"other","name":"exec","response":{"error":"DefenseClaw: blocked @ID@"}}}]}]}`},
	}
	for _, a := range adapters {
		t.Run(a.name, func(t *testing.T) {
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "r")
			spell := func(body, with string) string { return strings.ReplaceAll(body, "@ID@", with) }
			// The id on the call, in tool definition data, or in the words of
			// another result never takes the notice.
			for _, c := range []struct{ name, body string }{{"call id", a.call}, {"tool definition data", a.schema}, {"quoted by another result", a.quoted}} {
				out, _ := serveNoticeWith(t, noticeServe{reqBody: spell(c.body, noticeTestCallID), ctype: noticeJSONType, respBody: noticeChatReply})
				if out != noticeChatReply || !openClawBlockNoticesPending() {
					t.Fatalf("%s: %s took the notice: %s", a.name, c.name, out)
				}
			}
			// The escaped spelling of the id on the result is the id.
			out, _ := serveNoticeWith(t, noticeServe{reqBody: spell(a.result, escID), ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("%s: escaped id on the blocked result lost the notice: %s", a.name, out)
			}
			// The exact result takes it, once.
			resetOpenClawBlockNotices(t)
			rememberTestNotice("exec", []string{noticeTestRule}, "r")
			req := spell(a.result, noticeTestCallID)
			out, _ = serveNoticeWith(t, noticeServe{reqBody: req, ctype: noticeJSONType, respBody: noticeChatReply})
			if !noticeServed(out) || openClawBlockNoticesPending() {
				t.Fatalf("%s: the blocked result did not show exactly one notice: %s", a.name, out)
			}
			if again, _ := serveNoticeWith(t, noticeServe{reqBody: req, ctype: noticeJSONType, respBody: noticeChatReply}); again != noticeChatReply {
				t.Fatalf("%s: notice repeated: %s", a.name, again)
			}
		})
	}
}
