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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// parityCase is one row of testdata/message_text_parity.json: what the
// gateway reads of a message call's params (GAP-0177, GAP-0290..0292,
// GAP-0436). The OpenClaw plugin reads nothing of them: it sends them.
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
	deep := `{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":"text"}}}}}}}}}}`
	hasLimit := func(findings []string, cap string) bool {
		return slices.ContainsFunc(findings, func(f string) bool {
			return strings.HasPrefix(f, evaluationLimitRuleID) && strings.Contains(f, "bounded_truncated cap="+cap)
		})
	}
	for name, tc := range map[string]struct{ args, cap string }{"nodes": {nodes, "nodes"}, "depth": {deep, "depth"}} {
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
			connector: "openclaw", decide: boundedDecideOpenClawMessage, judge: boundedJudgeOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				var v any = "text"
				for range size + 1 {
					v = map[string]any{"x": v}
				}
				return v.(map[string]any)
			})},
		boundedLaneCap{lane: "openclaw message nodes", cap: bounded.Nodes, limit: messageTextMaxNodes,
			connector: "openclaw", decide: boundedDecideOpenClawMessage, judge: boundedJudgeOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				items := make([]any, size-4, size-3)
				for i := range items {
					items[i] = map[string]any{}
				}
				return map[string]any{"items": append(items, "late")}
			})},
		boundedLaneCap{lane: "openclaw message routing values", cap: bounded.Nodes, limit: messageTextMaxNodes,
			connector: "openclaw", decide: boundedDecideOpenClawMessage, judge: boundedJudgeOpenClawMessage, seen: boundedMessageSeen, gen: boundedMessageCall(func(size int) map[string]any {
				return map[string]any{"text": "x", "to": slices.Repeat([]any{"r"}, size-3)}
			})},
		boundedLaneCap{lane: "openclaw message attachment bytes", cap: bounded.Bytes, limit: messagePayloadMaxChars,
			connector: "openclaw", decide: boundedDecideOpenClawMessage, judge: boundedJudgeOpenClawMessage, seen: boundedMessageSeen,
			gen: boundedMessageCall(func(size int) map[string]any {
				return map[string]any{"buffer": strings.Repeat("A", size)}
			})},
	)
}

// boundedMessageCaption is the text every lane input carries for the judge to
// be asked about: one node and its bytes plus a newline are taken off each
// cap's input so the input at the cap stays exactly at the cap.
const boundedMessageCaption = "a short note that the judge is asked about"

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
		// Text for the judge to be asked about whatever the cap dropped.
		params["caption"] = boundedMessageCaption
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

// boundedJudgeOpenClawMessage is the lane's judge row: the same call on the
// API with the regex_judge stub (enabled for the lane's connector): the
// message lane reaches the judge for a truncated call before the floor, as it
// does for any message.
func boundedJudgeOpenClawMessage(t *testing.T, api *APIServer, _ boundedEnv, call boundedLaneCall) (string, []string) {
	t.Helper()
	api.inspectToolScanTimeout = 30 * time.Second
	// The stub judges tool calls only; a message is judged by the PII judge of
	// the completion direction.
	api.scannerCfg.Guardrail.Judge.PII, api.scannerCfg.Guardrail.Judge.PIICompletion = true, true
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
		// The bound only catches a read that scales with the attachment (the
		// 200 ms path is 8 MiB of decode and rune scan away from a 504): the
		// request body limit keeps a real call under 1 MiB, and -race on a
		// loaded box is ten times slower than production.
		took := time.Since(start)
		t.Logf("%s: extractMessageArgs took %v", tc.name, took)
		if took > 4*time.Second {
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

// A caller that cut the call down to fit the request body limit says so
// (args_partial): the part not sent is unread, so the call is judged at the
// unknown tier of each pack, never blocked by the size limit and never clean
// (GAP-0356). The plugin's cut call (an attachment's size, type and hash) for
// 1, 4 and 16 MB attachments is a small request.
func TestInspectToolArgsPartialIsUnknown(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 5 * time.Second
		want := bounded.Unknown(tier.tier).String()
		for _, mb := range []int{1, 4, 16} {
			digest := strings.Repeat("ab", 32)
			body := fmt.Sprintf(`{"tool":"message","args":{"message":"here is the photo","buffer":"[attachment bytes not sent: %d characters, image/png, sha256 %s]"},"content":"here is the photo","direction":"outbound","args_partial":%%t}`,
				mb<<20, digest)
			if len(body) > 4096 {
				t.Fatalf("the cut call is %d bytes, want a small request", len(body))
			}
			_, whole := postInspectForConnector(t, api, "openclaw", fmt.Sprintf(body, false))
			if whole.Action != "allow" {
				t.Fatalf("%s %d MB: the call sent whole is %q, want allow", tier.name, mb, whole.Action)
			}
			_, cut := postInspectForConnector(t, api, "openclaw", fmt.Sprintf(body, true))
			if cut.Action != want || !slices.ContainsFunc(cut.Findings, func(f string) bool {
				return strings.HasPrefix(f, evaluationLimitRuleID) && strings.Contains(f, "bounded_truncated cap=bytes")
			}) {
				t.Errorf("%s %d MB: action = %q findings = %v, want %s naming cap bytes", tier.name, mb, cut.Action, cut.Findings, want)
			}
		}
	}
}

// The cut of a call to fit the body limit keeps the answer of its tool class:
// a message gets the unknown tier of the pack, any other tool is blocked in
// every pack as an oversize call is (GAP-0356).
func TestInspectToolArgsPartialKeepsTheToolClass(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 5 * time.Second
		for _, tc := range []struct {
			class, body, want string
		}{
			{"message", `{"tool":"message","args":{"message":"photo"},"direction":"outbound","args_partial":true}`, bounded.Unknown(tier.tier).String()},
			{"shell", `{"tool":"exec","args":{"command":"echo hi"},"args_partial":true}`, "block"},
			{"file write", `{"tool":"write_file","args":{"path":"/tmp/x","content":"hi"},"args_partial":true}`, "block"},
			{"other tool", `{"tool":"read_file","args":{"path":"/tmp/x"},"args_partial":true}`, "block"},
		} {
			_, got := postInspectForConnector(t, api, "openclaw", tc.body)
			if got.Action != tc.want {
				t.Errorf("%s %s: action = %q findings = %v, want %s", tier.name, tc.class, got.Action, got.Findings, tc.want)
			}
		}
	}
}

// A UTF-16 text file in an attachment is read as text, with or without a byte
// order mark, in either byte order; binary data stays binary (the review of
// GAP-0328).
func TestInspectToolMessageUTF16Attachment(t *testing.T) {
	text := "key: " + messageTestSecret + " and some more words around it"
	utf16le := func(bom bool) []byte {
		var b []byte
		if bom {
			b = append(b, 0xff, 0xfe)
		}
		for _, r := range text {
			b = append(b, byte(r), byte(r>>8))
		}
		return b
	}
	utf16be := func(bom bool) []byte {
		var b []byte
		if bom {
			b = append(b, 0xfe, 0xff)
		}
		for _, r := range text {
			b = append(b, byte(r>>8), byte(r))
		}
		return b
	}
	pad := func(b []byte) []byte { // long enough to be read as a payload
		for len(b) < 1200 {
			b = append(b, b[len(b)-2:]...)
		}
		return b[:len(b)&^1]
	}
	for name, raw := range map[string][]byte{
		"LE with BOM": pad(utf16le(true)), "LE no BOM": pad(utf16le(false)),
		"BE with BOM": pad(utf16be(true)), "BE no BOM": pad(utf16be(false)),
	} {
		args := `{"buffer":"` + base64.StdEncoding.EncodeToString(raw) + `"}`
		got := extractMessageArgs(json.RawMessage(args))
		if !strings.Contains(got.Text, messageTestSecret) {
			t.Errorf("%s: the text was not read: %.60q", name, got.Text)
		}
		api := testAPIServerWithConfig(t, "action")
		_, verdict := postInspect(t, api, `{"tool":"message","args":`+args+`,"direction":"outbound"}`)
		if verdict.Action != "block" {
			t.Errorf("%s: action = %q, want block", name, verdict.Action)
		}
	}
	// Binary with NULs in the same places is not UTF-16 text.
	binary := bytes.Repeat([]byte{0, 1, 2, 3, 0, 5}, 400)
	if got := extractMessageArgs(json.RawMessage(`{"buffer":"` + base64.StdEncoding.EncodeToString(binary) + `"}`)); got.Text != "" || got.Truncated.Any() {
		t.Errorf("binary read as text: %q %v", got.Text, got.Truncated.Any())
	}
}

// An attachment field whose value is not base64 all the way through is text,
// even past the budget: only a real payload spends the budget (the review of
// GAP-0338).
func TestExtractMessageArgsAttachmentTailIsChecked(t *testing.T) {
	raw, _ := json.Marshal(map[string]string{"buffer": strings.Repeat("AAEC", messagePayloadMaxChars/4+1000) + " key: " + messageTestSecret})
	got := extractMessageArgs(raw)
	if !strings.Contains(got.Text, messageTestSecret) {
		t.Errorf("a plain-text tail after 2 MiB of base64 was not read as text: %.60q (truncated %v)", got.Text, got.Truncated.Any())
	}
}

// The request body limit and the attachment fields have one source, the
// embedded limits file the plugin build copies too (GAP-0402): the gateway
// reads them from there.
func TestInspectToolRequestLimitsFile(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/inspect-tool-request-limits.json")
	if err != nil {
		t.Fatal(err)
	}
	var limits struct {
		BodyMax int64    `json:"body_max_bytes"`
		Keys    []string `json:"message_attachment_keys"`
	}
	if err := json.Unmarshal(raw, &limits); err != nil {
		t.Fatal(err)
	}
	if limits.BodyMax != apiRequestBodyMaxBytes {
		t.Errorf("limits file %+v, gateway limit %d: want the same body limit", limits, apiRequestBodyMaxBytes)
	}
	if len(limits.Keys) != len(messageAttachmentKeys) {
		t.Errorf("attachment fields %v, gateway %v", limits.Keys, messageAttachmentKeys)
	}
	for _, k := range limits.Keys {
		if !messageAttachmentField(k) || !messageAttachmentField(strings.ToUpper(k)) {
			t.Errorf("%q is not an attachment field of the gateway", k)
		}
	}
	for _, k := range []string{"message", "text", "caption", "content", "body", "subject", "files", "attachments"} {
		if messageAttachmentField(k) {
			t.Errorf("%q is a text field, not an attachment field", k)
		}
	}
}

// The descriptor the plugin sends for an attachment over the body limit (its
// size, type and hash, then the text the gateway would have read in it, flagged
// partial) blocks a key in that text in every pack; a photo's descriptor (its
// camera metadata) is at the unknown tier, not blocked for its size (GAP-0356).
func TestInspectToolArgsPartialDescriptorKeepsTheAttachmentText(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	body := func(text string) string {
		b, _ := json.Marshal(map[string]any{"tool": "message", "direction": "outbound", "args_partial": true,
			"args": map[string]any{"to": "+15550001111", "caption": "see the file",
				"buffer": "[attachment bytes not sent: 1398104 characters, image/jpeg, sha256 " + strings.Repeat("ab", 32) + "]\n" + text}})
		return string(b)
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 5 * time.Second
		_, withKey := postInspectForConnector(t, api, "openclaw", body("notes for the demo\nkey: "+messageTestSecret+"\n"))
		if withKey.Action != "block" || withKey.Severity != "CRITICAL" {
			t.Errorf("%s: a key in an attachment's text: action = %q severity = %q, want block CRITICAL", tier.name, withKey.Action, withKey.Severity)
		}
		_, photo := postInspectForConnector(t, api, "openclaw", body("Apple\niPhone 15 Pro Max\n<x:xmpmeta xmlns:x=\"adobe:ns:meta/\"></x:xmpmeta>"))
		if want := bounded.Unknown(tier.tier).String(); photo.Action != want {
			t.Errorf("%s: a photo's descriptor: action = %q findings = %v, want %s (the unknown tier), not a block for its size", tier.name, photo.Action, photo.Findings, want)
		}
	}
}

// An attachment is read the way a lenient decoder (Node's Buffer.from) reads
// it: either alphabet, white space skipped, a "=" ends a group and the rest is
// read again; a file that decoder would deliver is never a clean allow
// (review of 46e8a4cf5e).
func TestInspectToolMessageLenientBase64Attachment(t *testing.T) {
	text := []byte("note: " + messageTestSecret + " and more words around it, long enough")
	std := base64.StdEncoding.EncodeToString(text)
	url := strings.NewReplacer("+", "-", "/", "_").Replace(base64.RawStdEncoding.EncodeToString(text))
	pad := strings.Repeat("AAEC", 300) // binary filler: makes the value a payload
	for name, value := range map[string]string{
		"standard":        pad + std,
		"URL alphabet":    pad + url,
		"spaces":          pad + strings.ReplaceAll(std, "A", " A "),
		"equals split":    pad + "=" + std,
		"mixed alphabets": pad + url + std,
		"line breaks":     pad + strings.Join(strings.SplitAfter(std, "e"), "\r\n"),
	} {
		got := extractMessageArgs(json.RawMessage(`{"buffer":"` + value + `"}`))
		if !strings.Contains(got.Text, messageTestSecret) {
			t.Errorf("%s: the text was not read: %.60q", name, got.Text)
		}
	}
	// A byte that is not base64 at all makes the value text, read as it is.
	odd := extractMessageArgs(json.RawMessage(`{"buffer":"` + pad + "!" + std + `"}`))
	if !strings.Contains(odd.Text, "AAECAAEC") {
		t.Errorf("a value with a non-base64 byte was not read as text: %.40q", odd.Text)
	}
}

// A guess of UTF-16 never hides the 8-bit text of the same file (review of
// 46e8a4cf5e): a byte order mark in front of a plain text file, and 16-bit
// samples in front of plain bytes, both give up the key.
func TestInspectToolMessageUTF16GuessKeepsEightBitText(t *testing.T) {
	plain := []byte("key: " + messageTestSecret + " and more words around it, long enough to be read" + strings.Repeat(" padding words to make it a payload.", 40))
	bom := append([]byte{0xff, 0xfe}, plain...)
	sample := bytes.Repeat([]byte{0x41, 0x00, 0x42, 0x00}, 1100)
	for name, raw := range map[string][]byte{"bom then 8-bit": bom, "16-bit head then 8-bit": append(sample, plain...)} {
		got := extractMessageArgs(json.RawMessage(`{"buffer":"` + base64.StdEncoding.EncodeToString(raw) + `"}`))
		if !strings.Contains(got.Text, messageTestSecret) {
			t.Errorf("%s: the 8-bit text was not read: %.60q", name, got.Text)
		}
	}
}

// The 810 KB shape of the round-3 review (GAP-0402): a short message that holds
// a key, a recipient and a table of numbers. rel reads it whole and blocks the
// key; so does this head, sent whole by the plugin (it fits the body limit) and
// read by the message lane, which keeps the text that ranks first when the node
// budget runs out.
func TestInspectToolMessageLargeNumberTableStillBlocksTheKey(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	rows := make([]any, 56000)
	for i := range rows {
		rows[i] = []any{i, i * 7}
	}
	body, err := json.Marshal(map[string]any{"tool": "message", "direction": "outbound", "args": map[string]any{
		"to": "+15550001111", "message": "status " + messageTestSecret,
		"presentation": map[string]any{"blocks": []any{map[string]any{"type": "table", "rows": rows}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(body) < 700<<10 || int64(len(body)) > apiRequestBodyMaxBytes {
		t.Fatalf("the request is %d bytes, want one between 700 KiB and the body limit", len(body))
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 10 * time.Second
		_, got := postInspectForConnector(t, api, "openclaw", string(body))
		if got.Action != "block" || !slices.ContainsFunc(got.Findings, func(f string) bool { return strings.HasPrefix(f, "SEC-ANTHROPIC") }) {
			t.Errorf("%s: action = %q findings = %v, want a block naming the key", tier.name, got.Action, got.Findings)
		}
	}
}

// The rules read all of the text that arrived, not its first and last 128 KiB
// (GAP-0436): a key in the middle of a 300 KB message blocks in every pack, as
// it does on rel, and the judge is sent at most 256 KiB of it.
func TestInspectToolMessageLongTextIsReadWhole(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, kb := range []int{250, 300, 900} {
		half := strings.Repeat("filler words go here. ", kb*1024/2/22)
		body, _ := json.Marshal(map[string]any{"tool": "message", "direction": "outbound",
			"args": map[string]any{"message": half + " key: " + messageTestSecret + " " + half}})
		clean, _ := json.Marshal(map[string]any{"tool": "message", "direction": "outbound",
			"args": map[string]any{"message": half + half}})
		for _, tier := range boundedTestTiers {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			api.inspectToolScanTimeout = 10 * time.Second
			_, got := postInspectForConnector(t, api, "openclaw", string(body))
			if got.Action != "block" || len(got.Findings) == 0 {
				t.Errorf("%s %d KB: action = %q findings = %v, want a block on the key in the middle", tier.name, kb, got.Action, got.Findings)
			}
			_, none := postInspectForConnector(t, api, "openclaw", string(clean))
			if none.Action != "allow" || slices.ContainsFunc(none.Findings, func(f string) bool { return strings.HasPrefix(f, evaluationLimitRuleID) }) {
				t.Errorf("%s %d KB clean: action = %q findings = %v, want a plain allow (no size alert)", tier.name, kb, none.Action, none.Findings)
			}
		}
	}
	long := strings.Repeat("é", messageJudgeMaxBytes)
	if got := messageJudgeText(long); len(got) > messageJudgeMaxBytes+1 || !utf8.ValidString(got) {
		t.Errorf("the judge text is %d bytes, valid UTF-8 = %v", len(got), utf8.ValidString(got))
	}
	if short := "a short text"; messageJudgeText(short) != short {
		t.Error("a short text must go to the judge whole")
	}
}

// The margin band of the round-5 review (GAP-0436): calls whose body is a few
// bytes over the cut target and under the body limit are sent whole by the
// plugin and read whole by the gateway, behind the production body limit: the
// key blocks CRITICAL in every pack, as on rel. The five shapes are built to the
// same byte counts as the plugin test (inspect-body-limit.test.ts).
func TestInspectToolMessageMarginBandStillBlocksTheKey(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("POSIX home fixture requires an unprivileged Unix user")
	}
	prose := func(n int) string { return strings.Repeat("the quarterly plan is attached for review. ", n/43+1)[:n] }
	keyText := prose(7000) + " key: " + messageTestSecret + " " + prose(7000)
	rows := func(n int) []any {
		out := make([]any, n)
		for r := range out {
			row := make([]any, 10)
			for c := range row {
				row[c] = r*10 + c
			}
			out[r] = row
		}
		return out
	}
	wrap := func(params map[string]any) []byte {
		b, err := json.Marshal(map[string]any{"tool": "message", "args": params, "direction": "outbound", "approval_surface": "native"})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// exact grows coarse(n) to the largest that fits, then fills to target bytes with small numbers.
	exact := func(target int, coarse func(n int) map[string]any) []byte {
		sized := func(n, pad int) int {
			params := coarse(n)
			params["pad"] = make([]int, pad)
			return len(wrap(params))
		}
		lo, hi := 0, 200000
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if sized(mid, 0) <= target-4 {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		count, top := 0, target
		for count < top {
			mid := (count + top + 1) / 2
			if sized(lo, mid) <= target {
				count = mid
			} else {
				top = mid - 1
			}
		}
		pad := make([]int, count)
		params := coarse(lo)
		params["pad"] = pad
		for i := 0; i < target-len(wrap(params)); i++ {
			pad[i] = 10
		}
		body := wrap(params)
		if len(body) != target {
			t.Fatalf("built %d bytes, want %d", len(body), target)
		}
		return body
	}
	table := func(field string) func(int) map[string]any {
		return func(n int) map[string]any {
			return map[string]any{"action": "send", "to": "+15550001111", field: keyText,
				"presentation": map[string]any{"blocks": []any{map[string]any{"type": "table", "rows": rows(n)}}}}
		}
	}
	target := int(apiRequestBodyMaxBytes) - 1024
	shapes := map[string][]byte{
		"band-body-numtable-1b": exact(target+1, table("body")),
		"band-body-numtable":    exact(target+100, table("body")),
		"band-content-numtable": exact(target+100, table("content")),
		"band-body-short": exact(target+200, func(n int) map[string]any {
			notes := make([]string, n)
			for i := range notes {
				notes[i] = strings.Repeat("y", 100)
			}
			return map[string]any{"action": "send", "to": "+15550001111", "body": keyText, "notes": notes}
		}),
		"band-body-eqstrings": exact(target+150, func(n int) map[string]any {
			params := map[string]any{"action": "send", "to": "+15550001111", "body": keyText}
			for i := 0; i < n; i++ {
				params["f"+strconv.Itoa(i)] = strings.Repeat("y", len(keyText))
			}
			return params
		}),
	}
	env := boundedLaneEnv(t)
	t.Setenv("HOME", env.home)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		api.inspectToolScanTimeout = 20 * time.Second
		handler := apiBodyLimitMiddleware(http.HandlerFunc(api.handleInspectTool), apiRequestBodyMaxBytes, otlpRequestBodyMaxBytes)
		for name, body := range shapes {
			if len(body) <= target || int64(len(body)) > apiRequestBodyMaxBytes {
				t.Fatalf("%s: %d bytes is not in the band (%d, %d]", name, len(body), target, apiRequestBodyMaxBytes)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = req.WithContext(withAuthenticatedInspectConnector(req.Context(), "openclaw"))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			var got ToolInspectVerdict
			if err := json.NewDecoder(rec.Result().Body).Decode(&got); err != nil || rec.Code != http.StatusOK {
				t.Errorf("%s %s: status %d (%v), want the verdict", tier.name, name, rec.Code, err)
				continue
			}
			if got.Action != "block" || got.Severity != "CRITICAL" || !slices.ContainsFunc(got.Findings, func(f string) bool { return strings.HasPrefix(f, "SEC-ANTHROPIC") }) {
				t.Errorf("%s %s: action = %q severity = %q findings = %v, want block CRITICAL on the key", tier.name, name, got.Action, got.Severity, got.Findings)
			}
		}
	}
}
