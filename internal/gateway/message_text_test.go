// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// parityCase is one row of testdata/message_text_parity.json. The OpenClaw
// plugin's extractMessage (message-text.test.ts) runs the same rows, so the
// plugin and the gateway read a message call's params the same way
// (GAP-0177, GAP-0290..0292).
type parityCase struct {
	Name    string          `json:"name"`
	Params  json.RawMessage `json:"params"`
	Gen     map[string]int  `json:"gen"`
	Text    *string         `json:"text"`
	TextLen *int            `json:"text_len"`
	OverCap bool            `json:"over_cap"`
	// Routing is asserted only for a row that lists it.
	Routing *map[string]interface{} `json:"routing"`
	Head    string                  `json:"head"`
	Tail    string                  `json:"tail"`
	// GoOnly rows are not run by the plugin, which never decodes an attachment.
	GoOnly bool `json:"go_only"`
	// ValidUTF8 asserts the text has no cut character.
	ValidUTF8 bool `json:"valid_utf8"`
}

func loadParityCases(t *testing.T) []parityCase {
	t.Helper()
	raw, err := os.ReadFile("testdata/message_text_parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []parityCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

// paramsOf builds the call's params: the row's own, or the large input its gen
// field names.
func (c parityCase) paramsOf(t *testing.T) json.RawMessage {
	t.Helper()
	var v interface{}
	switch {
	case c.Gen["strings"] > 0:
		items := make([]string, c.Gen["strings"])
		for i := range items {
			items[i] = "s"
		}
		v = map[string]interface{}{"blocks": items}
	case c.Gen["table"] > 0:
		rows := make([]interface{}, c.Gen["table"])
		for i := range rows {
			rows[i] = []interface{}{"a", "b"}
		}
		v = map[string]interface{}{"presentation": map[string]interface{}{"blocks": []interface{}{map[string]interface{}{"type": "table", "rows": rows}}}}
	case c.Gen["payload_buffer"] > 0:
		v = map[string]string{"message": "hi", "buffer": strings.Repeat("AAEC", c.Gen["payload_buffer"]/4)}
	case c.Gen["payload_dataurl"] > 0:
		v = map[string]string{"message": "hi", "media": "data:image/png;base64," + strings.Repeat("AAEC", c.Gen["payload_dataurl"]/4)}
	case c.Gen["payload_then_text"] > 0:
		v = map[string]string{"buffer": strings.Repeat("AAEC", c.Gen["payload_then_text"]/4) + " tail words"}
	case c.Gen["dataurl_message"] > 0:
		v = map[string]string{"message": "data:image/png;base64," + strings.Repeat("AAEC", c.Gen["dataurl_message"])}
	case c.Gen["nested_buffer"] > 0:
		v = map[string]any{"attachments": []any{map[string]string{"Buffer": strings.Repeat("AAEC", c.Gen["nested_buffer"])}}}
	case c.Gen["nodes_empty"] > 0:
		items := make([]interface{}, c.Gen["nodes_empty"])
		for i := range items {
			items[i] = map[string]interface{}{}
		}
		v = map[string]interface{}{"items": items}
	case c.Gen["payload_hidden"] > 0:
		raw := append(bytes.Repeat([]byte{0, 1, 2}, 3000), []byte("key words here and more text")...)
		v = map[string]string{"message": "hi", "buffer": base64.StdEncoding.EncodeToString(raw)}
	case c.Gen["payload_text"] > 0:
		v = map[string]string{"message": "hi", "buffer": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("abc ", c.Gen["payload_text"])))}
	case c.Gen["payload_text_dataurl"] > 0:
		v = map[string]string{"message": "hi", "media": "data:text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("abc ", c.Gen["payload_text_dataurl"])))}
	case c.Gen["plainbuf"] > 0:
		v = map[string]string{"buffer": strings.Repeat("word ", c.Gen["plainbuf"])}
	case c.Gen["routing_strings"] > 0:
		v = map[string]interface{}{"text": "x", "to": slices.Repeat([]string{"r"}, c.Gen["routing_strings"])}
	case c.Gen["depth"] > 0 || c.Gen["depth_empty"] > 0:
		v = interface{}("deep")
		n := c.Gen["depth"]
		if c.Gen["depth_empty"] > 0 {
			v, n = []interface{}{}, c.Gen["depth_empty"]
		}
		for i := 0; i < n; i++ {
			v = map[string]interface{}{"x": v}
		}
	case c.Gen["nodes"] > 0:
		items := make([]interface{}, c.Gen["nodes"], c.Gen["nodes"]+1)
		for i := range items {
			items[i] = map[string]interface{}{}
		}
		v = map[string]interface{}{"items": append(items, "late")}
	case c.Gen["multibyte"] > 0:
		v = map[string]string{"text": strings.Repeat("é", c.Gen["multibyte"])}
	case c.Gen["pad"] > 0:
		v = map[string]string{
			"body": strings.Repeat("a", c.Gen["pad"]),
			"text": strings.Repeat("z", c.Gen["pad"]),
		}
	default:
		return c.Params
	}
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtractMessageArgsParity(t *testing.T) {
	for _, tc := range loadParityCases(t) {
		t.Run(tc.Name, func(t *testing.T) {
			got := extractMessageArgs(tc.paramsOf(t))
			if tc.Text != nil && got.Text != *tc.Text {
				t.Errorf("text = %q, want %q", got.Text, *tc.Text)
			}
			if tc.TextLen != nil && len(got.Text) != *tc.TextLen {
				t.Errorf("text length = %d, want %d", len(got.Text), *tc.TextLen)
			}
			if tc.ValidUTF8 && !utf8.ValidString(got.Text) {
				t.Errorf("text holds a cut character")
			}
			if tc.Head != "" && !strings.HasPrefix(got.Text, tc.Head) {
				t.Errorf("text does not start with %q", tc.Head)
			}
			if tc.Tail != "" && !strings.HasSuffix(got.Text, tc.Tail) {
				t.Errorf("text does not end with %q", tc.Tail)
			}
			if got.Truncated.Any() != tc.OverCap {
				t.Errorf("over_cap = %v, want %v", got.Truncated.Any(), tc.OverCap)
			}
			if tc.Routing != nil {
				gotRouting := got.Routing
				if gotRouting == nil {
					gotRouting = map[string]interface{}{}
				}
				if !reflect.DeepEqual(gotRouting, *tc.Routing) {
					t.Errorf("routing = %v, want %v", gotRouting, *tc.Routing)
				}
			}
		})
	}
}

func TestExtractMessageArgsRejectsNonJSON(t *testing.T) {
	for _, raw := range []string{``, `not json`} {
		if got := extractMessageArgs(json.RawMessage(raw)); got.Text != "" || got.Truncated.Any() || got.Routing != nil {
			t.Errorf("extractMessageArgs(%q) = %+v, want nothing", raw, got)
		}
	}
}

// A secret in any text field of the params is blocked, not only in content
// or body (GAP-0177).
func TestInspectToolMessageSecretInEveryTextField(t *testing.T) {
	secret := "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"
	for _, args := range []string{
		`{"text":"key: ` + secret + `"}`,
		`{"message":"key: ` + secret + `"}`,
		`{"caption":"key: ` + secret + `","media":"m.png"}`,
		`{"to":"+1234","blocks":[{"type":"text","text":"key: ` + secret + `"}]}`,
		`{"attachments":[{"title":"t","description":"key: ` + secret + `"}]}`,
		`{"unlisted_field":"key: ` + secret + `"}`,
		`{"target":{"id":"u1","text":"key: ` + secret + `"}}`,
	} {
		api := testAPIServerWithConfig(t, "action")
		_, verdict := postInspect(t, api, `{"tool":"message","args":`+args+`,"direction":"outbound"}`)
		if verdict.Action != "block" {
			t.Errorf("args %s: action = %q, want block", args, verdict.Action)
		}
	}
}

// A message call with no text anywhere is not allowed unread: it takes the
// tool policy lane, which reads the args (GAP-0177).
func TestInspectToolMessageWithoutTextTakesToolPolicy(t *testing.T) {
	secret := "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"
	api := testAPIServerWithConfig(t, "observe")
	_, verdict := postInspect(t, api, `{"tool":"message","args":{"to":"`+secret+`"}}`)
	if !containsString(verdict.Findings, "SEC-ANTHROPIC:Anthropic API key") {
		t.Fatalf("a message call with no text was allowed unread; findings = %v", verdict.Findings)
	}

	_, verdict = postInspect(t, api, `{"tool":"message","args":{"to":"+1234","action":"send"}}`)
	if verdict.Action != "allow" {
		t.Fatalf("clean routing-only call: action = %q, want allow", verdict.Action)
	}
	for _, empty := range []string{`{"tool":"message"}`, `{"tool":"message","args":{}}`, `{"tool":"message","args":null}`} {
		if _, verdict = postInspect(t, api, empty); verdict.Action != "allow" || len(verdict.Findings) != 0 {
			t.Errorf("%s: action = %q findings = %v, want a plain allow", empty, verdict.Action, verdict.Findings)
		}
	}
}

// The routing values of a call that also has text are not skipped (GAP-0291):
// a credential in the recipient or target field is found, with the text clean.
// They are decided as the destination of any other send tool is: through the
// tool-policy lane, which records a credential in a tool's arguments as a
// finding and lets the profile decide the action.
func TestInspectToolMessageRoutingValuesAreInspected(t *testing.T) {
	secret := "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"
	for _, tc := range []struct{ withText, asSendTool string }{
		{`{"to":"` + secret + `","text":"hello"}`, `{"to":"` + secret + `"}`},
		{`{"target":{"id":"` + secret + `","text":"hello"}}`, `{"target.id":"` + secret + `"}`},
		{`{"channel":"` + secret + `","content":"hello"}`, `{"channel":"` + secret + `"}`},
		{`{"targets":["+1","` + secret + `"],"body":"hello"}`, `{"targets":"+1","targets#2":"` + secret + `"}`},
	} {
		for _, mode := range []string{"action", "observe"} {
			api := testAPIServerWithConfig(t, mode)
			_, want := postInspect(t, api, `{"tool":"send_email","args":`+tc.asSendTool+`}`)
			if !containsString(want.Findings, "SEC-ANTHROPIC:Anthropic API key") {
				t.Fatalf("%s: the send-tool call has no finding: %v", tc.asSendTool, want.Findings)
			}
			for _, content := range []string{``, `,"content":"hello"`} {
				_, got := postInspect(t, api, `{"tool":"message","args":`+tc.withText+content+`,"direction":"outbound"}`)
				if !containsString(got.Findings, "SEC-ANTHROPIC:Anthropic API key") {
					t.Errorf("%s (%s%s): the routing secret was not found: %v", tc.withText, mode, content, got.Findings)
				}
				if got.Action != want.Action || got.RawAction != want.RawAction {
					t.Errorf("%s (%s%s): action = %q/%q, want what a send tool's destination gets: %q/%q",
						tc.withText, mode, content, got.Action, got.RawAction, want.Action, want.RawAction)
				}
			}
		}
	}
	// Ordinary routing values with clean text change nothing.
	api := testAPIServerWithConfig(t, "action")
	_, verdict := postInspect(t, api, `{"tool":"message","args":{"to":"+15551230000","channel":"sms","action":"send","text":"hello"},"content":"hello","direction":"outbound"}`)
	if verdict.Action != "allow" || len(verdict.Findings) != 0 {
		t.Errorf("clean call: action = %q findings = %v, want a plain allow", verdict.Action, verdict.Findings)
	}
}

// Numbers in the args are text: a value sent as a JSON number is scanned as
// the same digits sent as a string.
func TestInspectToolMessageNumbersAreScanned(t *testing.T) {
	for _, pan := range []string{"4111111111111111", "4242424242424242"} {
		api := testAPIServerWithConfig(t, "action")
		_, asString := postInspect(t, api, `{"tool":"message","args":{"message":"credit card number","card":"`+pan+`"},"direction":"outbound"}`)
		_, asNumber := postInspect(t, api, `{"tool":"message","args":{"message":"credit card number","card":`+pan+`},"direction":"outbound"}`)
		if !reflect.DeepEqual(asNumber.Findings, asString.Findings) || asNumber.Action != asString.Action {
			t.Errorf("%s: as a number %q %v, as a string %q %v", pan, asNumber.Action, asNumber.Findings, asString.Action, asString.Findings)
		}
	}
}

// Text past the read limits is unknown (GAP-0290), judged by the bound rule:
// the call alerts in the default pack and blocks in strict, with or without
// the caller's own copy of the text; the gateway reads the args itself.
func TestInspectToolMessageOverCapIsUnknown(t *testing.T) {
	items := make([]string, messageTextMaxNodes+30)
	for i := range items {
		items[i] = `"ok"`
	}
	nodes := `{"blocks":[` + strings.Join(items, ",") + `]}`
	pad := strings.Repeat("a", 140*1024)
	size := `{"body":"` + pad + `","text":"` + pad + `"}`
	deep := `{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":"text"}}}}}}}}}}`
	hasLimit := func(findings []string, cap string) bool {
		return slices.ContainsFunc(findings, func(f string) bool {
			return strings.HasPrefix(f, evaluationLimitRuleID) && strings.Contains(f, "bounded_truncated cap="+cap)
		})
	}
	for name, tc := range map[string]struct{ args, cap string }{"nodes": {nodes, "nodes"}, "size": {size, "bytes"}, "depth": {deep, "depth"}} {
		for _, withContent := range []bool{false, true} {
			api := testAPIServerWithConfig(t, "action")
			body := `{"tool":"message","args":` + tc.args + `,"direction":"outbound"`
			if withContent {
				body += `,"content":"ok"`
			}
			_, verdict := postInspect(t, api, body+`}`)
			if verdict.Action != "alert" || !hasLimit(verdict.Findings, tc.cap) {
				t.Errorf("%s (content %v): action = %q findings = %v, want an alert naming cap %s", name, withContent, verdict.Action, verdict.Findings, tc.cap)
			}
			observe := testAPIServerWithConfig(t, "observe")
			_, verdict = postInspect(t, observe, body+`}`)
			if verdict.Action != "allow" || verdict.RawAction != "alert" {
				t.Errorf("%s (content %v) observe: action = %q raw = %q, want allow with raw alert", name, withContent, verdict.Action, verdict.RawAction)
			}
		}
	}
	// A secret in the part that was read still blocks; the floor never lowers it.
	api := testAPIServerWithConfig(t, "action")
	_, verdict := postInspect(t, api, `{"tool":"message","args":{"content":"`+messageTestSecret+`","blocks":[`+strings.Join(items, ",")+`]},"direction":"outbound"}`)
	if verdict.Action != "block" {
		t.Errorf("secret plus over-cap text: action = %q, want block", verdict.Action)
	}
	// Under the limits there is no alert.
	_, verdict = postInspect(t, api, `{"tool":"message","args":{"text":"hello"},"direction":"outbound"}`)
	if verdict.Action != "allow" || len(verdict.Findings) != 0 {
		t.Errorf("small clean call: action = %q findings = %v, want a plain allow", verdict.Action, verdict.Findings)
	}
}

// messageTestSecret is a synthetic Anthropic-shaped key the message tests use.
const messageTestSecret = "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"

// The message lane's caps under the bound rule's property test
// (TestBoundRuleEveryLaneCap): at the cap the call is not truncated, past it
// the action is at least the unknown tier of each of the five tiers and names
// the cap.
func init() {
	registerBoundedLane(
		boundedLaneCap{lane: "openclaw message depth", cap: bounded.Depth, limit: messageTextMaxDepth,
			decide: boundedDecideOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				var v any = "text"
				for range size + 1 {
					v = map[string]any{"x": v}
				}
				return v.(map[string]any)
			})},
		boundedLaneCap{lane: "openclaw message nodes", cap: bounded.Nodes, limit: messageTextMaxNodes,
			decide: boundedDecideOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				items := make([]any, size-3, size-2)
				for i := range items {
					items[i] = map[string]any{}
				}
				return map[string]any{"items": append(items, "late")}
			})},
		boundedLaneCap{lane: "openclaw message routing values", cap: bounded.Nodes, limit: messageTextMaxNodes,
			decide: boundedDecideOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				return map[string]any{"text": "x", "to": slices.Repeat([]any{"r"}, size-2)}
			})},
		boundedLaneCap{lane: "openclaw message bytes", cap: bounded.Bytes, limit: messageTextMaxBytes,
			decide: boundedDecideOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				return map[string]any{"text": strings.Repeat("a", size)}
			})},
	)
}

// boundedMessageCall is a message call of the params fill(size) builds, with
// the lane's seen element (a key in the message field, which blocks in every
// tier) before the capped part for the seen shape and after it (last in the
// walk) for seen-after. The nested and multi-cap shapes have no form here.
func boundedMessageCall(fill func(size int) map[string]any) func(int, boundedShape) (boundedLaneCall, bool) {
	return func(size int, shape boundedShape) (boundedLaneCall, bool) {
		if shape.nested || shape.multi {
			return boundedLaneCall{}, false
		}
		params := fill(size)
		switch {
		case shape.seen:
			params["message"] = "key: " + messageTestSecret
		case shape.seenAfter:
			params["zzz"] = "key: " + messageTestSecret
		}
		return boundedLaneCall{tool: "message", input: params}, true
	}
}

// boundedMessageSeen is the seen element alone: the message of a call.
func boundedMessageSeen() boundedLaneCall {
	return boundedLaneCall{tool: "message", input: map[string]any{"message": "key: " + messageTestSecret}}
}

// boundedDecideOpenClawMessage sends one message call to /inspect/tool as the
// OpenClaw plugin does, in the tier the api is set up for.
func boundedDecideOpenClawMessage(t *testing.T, api *APIServer, _ boundedEnv, call boundedLaneCall) (string, []string) {
	t.Helper()
	api.inspectToolScanTimeout = 30 * time.Second
	_, verdict := postInspectForConnector(t, api, "openclaw",
		string(mustJSON(t, map[string]any{"tool": call.tool, "args": call.input, "direction": "outbound"})))
	return verdict.Action, verdict.Findings
}

// The tool block list decides a message call before any of its text is read
// (GAP-0292): a call with text is blocked as a call without text is.
func TestInspectToolMessageStaticBlockRunsFirst(t *testing.T) {
	for name, args := range map[string]string{
		"with text":    `{"to":"+1","text":"hello there"}`,
		"routing only": `{"to":"+1","action":"send"}`,
		"over the cap": `{"blocks":[` + strings.Repeat(`"x",`, messageTextMaxNodes+5) + `"x"]}`,
	} {
		api := testAPIServerWithConfig(t, "action")
		api.scannerCfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "message"}}
		raw, _ := json.Marshal(map[string]interface{}{
			"tool": "message", "args": json.RawMessage(args),
			"content": extractMessageArgs(json.RawMessage(args)).Text, "direction": "outbound",
		})
		_, verdict := postInspect(t, api, string(raw))
		if verdict.Action != "block" || !containsString(verdict.Findings, "STATIC-BLOCK") {
			t.Errorf("%s: action = %q findings = %v, want STATIC-BLOCK", name, verdict.Action, verdict.Findings)
		}
	}
}

// No lane that reads a tool call's content decides it before the tool block
// list does (GAP-0292): the generic tool lane and the Cowork native deny read
// the list through toolBlockListVerdict, and the message lane runs it first.
func TestToolBlockListVerdict(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	api.scannerCfg.AssetPolicy.Tool.Denied = []config.AssetPolicyToolRule{{Name: "message"}, {Name: "send_email", Connector: "openclaw"}}
	for _, tc := range []struct {
		tool, connector string
		want            bool
	}{
		{"message", "openclaw", true},
		{"send_email", "openclaw", true},
		{"send_email", "codex", false},
		{"read_file", "openclaw", false},
	} {
		v := api.toolBlockListVerdict(t.Context(), &ToolInspectRequest{Tool: tc.tool, Connector: tc.connector}, nil)
		if (v != nil) != tc.want {
			t.Errorf("%s/%s: verdict = %+v, want a block = %v", tc.tool, tc.connector, v, tc.want)
		}
		if v != nil && (v.Action != "block" || !containsString(v.Findings, "STATIC-BLOCK")) {
			t.Errorf("%s/%s: verdict = %+v, want a STATIC-BLOCK block", tc.tool, tc.connector, v)
		}
	}
}

// The walk is linear in the call: 16000 recipients (80 KB) are read in well
// under a second, and over the node budget the call is truncated, not walked
// for seconds (GAP-0322).
func TestExtractMessageArgsRoutingCost(t *testing.T) {
	raw, err := json.Marshal(map[string]any{"text": "hi", "to": slices.Repeat([]string{"+1"}, 16000)})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	got := extractMessageArgs(raw)
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("reading 16000 recipients took %v", took)
	}
	if !got.Truncated.Has(bounded.Nodes) || got.Text != "hi" {
		t.Errorf("truncated nodes = %v, text = %q, want nodes hit and the text read", got.Truncated.Has(bounded.Nodes), got.Text)
	}
	if len(got.Routing) != messageTextMaxNodes-2 {
		t.Errorf("filed %d routing values, want the %d the budget allows", len(got.Routing), messageTextMaxNodes-2)
	}
}

// An attachment is read as a stream within a fixed budget of characters per
// call (GAP-0328, GAP-0338): inside it the content decides, past it the unread
// part is truncated, never skipped, and a 4 MB or 16 MB attachment costs no
// more than one at the budget.
func TestExtractMessageArgsAttachmentBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		chars     int
		truncated bool
	}{
		{"1 MiB", 1 << 20, false},
		{"at the budget", messagePayloadMaxChars, false},
		{"4 MB", 4 << 20, true},
		{"16 MB", 16 << 20, true},
	} {
		raw, err := json.Marshal(map[string]string{"message": "hi", "buffer": strings.Repeat("AAEC", tc.chars/4)})
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		got := extractMessageArgs(raw)
		if took := time.Since(start); took > 750*time.Millisecond {
			t.Errorf("%s: reading the call took %v", tc.name, took)
		}
		if got.Text != "hi" || got.Truncated.Has(bounded.Bytes) != tc.truncated {
			t.Errorf("%s: text %q, truncated bytes = %v, want hi and %v", tc.name, got.Text, got.Truncated.Has(bounded.Bytes), tc.truncated)
		}
	}
	// Text after the budget is unread and the call says so; text inside it is read.
	sentence := []byte("a sentence that is long enough to be a run of text")
	for len(sentence)%3 != 0 {
		sentence = append(sentence, ' ')
	}
	tail := base64.StdEncoding.EncodeToString(sentence)
	late, _ := json.Marshal(map[string]string{"buffer": strings.Repeat("AAEC", messagePayloadMaxChars/4) + tail})
	if got := extractMessageArgs(late); !got.Truncated.Has(bounded.Bytes) || got.Text != "" {
		t.Errorf("text past the budget: text %q truncated %v, want unread and truncated", got.Text, got.Truncated.Has(bounded.Bytes))
	}
	early, _ := json.Marshal(map[string]string{"buffer": tail + strings.Repeat("AAEC", 1<<20/4)})
	if got := extractMessageArgs(early); got.Truncated.Any() || !strings.Contains(got.Text, "a sentence that is long enough") {
		t.Errorf("text inside the budget: text %q truncated %v", got.Text, got.Truncated.Any())
	}
}

// A secret hidden behind a binary header in a buffer, or after a base64 prefix,
// is found (GAP-0328): the attachment is skipped only when none of it is text.
func TestInspectToolMessageAttachmentsHideNoText(t *testing.T) {
	hidden := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0, 1, 2}, 3000), []byte("key: "+messageTestSecret)...))
	afterPrefix := strings.Repeat("AAEC", 1024) + " key: " + messageTestSecret
	for name, args := range map[string]string{
		"buffer, binary header then text": `{"buffer":"` + hidden + `"}`,
		"buffer, base64 then words":       `{"buffer":"` + afterPrefix + `"}`,
		"caption is always text":          `{"caption":"` + afterPrefix + `"}`,
		"Buffer nested, any case":         `{"attachments":[{"Buffer":"` + hidden + `"}]}`,
		"data URL in message":             `{"message":"data:image/png;base64,` + afterPrefix + `"}`,
		"text data URL":                   `{"media":"data:text/plain;base64,` + hidden + `"}`,
	} {
		api := testAPIServerWithConfig(t, "action")
		_, verdict := postInspect(t, api, `{"tool":"message","args":`+args+`,"direction":"outbound"}`)
		if verdict.Action != "block" {
			t.Errorf("%s: action = %q findings = %v, want block", name, verdict.Action, verdict.Findings)
		}
	}
	// A binary attachment alone is no text, no cap hit and no finding.
	api := testAPIServerWithConfig(t, "action")
	photo := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0, 1, 2, 255, 254}, 80000))
	_, verdict := postInspect(t, api, `{"tool":"message","args":{"message":"here is the photo","buffer":"`+photo+`","filename":"a.png"},"direction":"outbound"}`)
	if verdict.Action != "allow" || len(verdict.Findings) != 0 {
		t.Errorf("300 KB binary attachment: action = %q findings = %v, want a plain allow", verdict.Action, verdict.Findings)
	}
}

// On a managed AI Defense-only install the routing values still reach AI
// Defense through the tool lane (the P3 of the GAP-0177 re-check): the message
// lane no longer leaves them out. The tool lane, not the text lane, decides
// them there, so the call's routing args are what that lane is asked about.
func TestMessageRoutingArgs(t *testing.T) {
	got := messageRoutingArgs(map[string]interface{}{"to": "+1", "target.id": "u1"})
	var round map[string]string
	if err := json.Unmarshal(got, &round); err != nil || round["to"] != "+1" || round["target.id"] != "u1" {
		t.Errorf("routing args = %s (%v)", got, err)
	}
	if messageRoutingArgs(nil) != nil {
		t.Error("no routing values must give no routing call")
	}
}
