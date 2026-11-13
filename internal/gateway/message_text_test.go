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
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// parityCase is one row of testdata/message_text_parity.json. The OpenClaw
// plugin's extractMessage (message-text.test.ts) runs the same rows, so the
// plugin and the gateway read a message call's params the same way
// (GAP-0177, GAP-0290..0292).
type parityCase struct {
	Name    string                 `json:"name"`
	Params  json.RawMessage        `json:"params"`
	Gen     map[string]int         `json:"gen"`
	Text    *string                `json:"text"`
	TextLen *int                   `json:"text_len"`
	OverCap bool                   `json:"over_cap"`
	Routing map[string]interface{} `json:"routing"`
	Head    string                 `json:"head"`
	Tail    string                 `json:"tail"`
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
	case c.Gen["leaves"] > 0:
		items := make([]string, c.Gen["leaves"])
		for i := range items {
			items[i] = "s"
		}
		v = map[string]interface{}{"blocks": items}
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
			if got.OverCap != tc.OverCap {
				t.Errorf("over_cap = %v, want %v", got.OverCap, tc.OverCap)
			}
			want := tc.Routing
			if want == nil {
				want = map[string]interface{}{}
			}
			gotRouting := got.Routing
			if gotRouting == nil {
				gotRouting = map[string]interface{}{}
			}
			if !reflect.DeepEqual(gotRouting, want) {
				t.Errorf("routing = %v, want %v", gotRouting, want)
			}
		})
	}
}

func TestExtractMessageArgsRejectsNonJSON(t *testing.T) {
	for _, raw := range []string{``, `not json`} {
		if got := extractMessageArgs(json.RawMessage(raw)); got.Text != "" || got.OverCap || got.Routing != nil {
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

// Text past the read limits is unknown, never clean (GAP-0290): the call
// alerts in action mode and is recorded (raw_action alert) in observe mode,
// with or without the caller's own copy of the text.
func TestInspectToolMessageOverCapAlerts(t *testing.T) {
	items := make([]string, messageTextMaxLeaves+30)
	for i := range items {
		items[i] = `"ok"`
	}
	leaves := `{"blocks":[` + strings.Join(items, ",") + `]}`
	pad := strings.Repeat("a", 140*1024)
	size := `{"body":"` + pad + `","text":"` + pad + `"}`
	deep := `{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":{"x":"text"}}}}}}}}}}`
	for name, args := range map[string]string{"leaves": leaves, "size": size, "depth": deep} {
		for _, withContent := range []bool{false, true} {
			api := testAPIServerWithConfig(t, "action")
			body := `{"tool":"message","args":` + args + `,"direction":"outbound"`
			if withContent {
				body += `,"content":"ok"`
			}
			_, verdict := postInspect(t, api, body+`}`)
			if verdict.Action != "alert" || !containsString(verdict.Findings, messageTextOverCapRuleID) {
				t.Errorf("%s (content %v): action = %q findings = %v, want an alert on %s", name, withContent, verdict.Action, verdict.Findings, messageTextOverCapRuleID)
			}
			observe := testAPIServerWithConfig(t, "observe")
			_, verdict = postInspect(t, observe, body+`}`)
			if verdict.Action != "allow" || verdict.RawAction != "alert" {
				t.Errorf("%s (content %v) observe: action = %q raw = %q, want allow with raw alert", name, withContent, verdict.Action, verdict.RawAction)
			}
		}
	}
	// A secret in the part that was read still blocks; the over-cap alert
	// never lowers it.
	secret := "sk-ant-api03-" + "A7b9C2d4E6f8G1h3J5k7L9m2"
	api := testAPIServerWithConfig(t, "action")
	_, verdict := postInspect(t, api, `{"tool":"message","args":{"content":"`+secret+`","blocks":[`+strings.Join(items, ",")+`]},"direction":"outbound"}`)
	if verdict.Action != "block" {
		t.Errorf("secret plus over-cap text: action = %q, want block", verdict.Action)
	}
	// Under the limits there is no alert.
	_, verdict = postInspect(t, api, `{"tool":"message","args":{"text":"hello"},"direction":"outbound"}`)
	if verdict.Action != "allow" {
		t.Errorf("small clean call: action = %q, want allow", verdict.Action)
	}
}

// The tool block list decides a message call before any of its text is read
// (GAP-0292): a call with text is blocked as a call without text is.
func TestInspectToolMessageStaticBlockRunsFirst(t *testing.T) {
	for name, args := range map[string]string{
		"with text":    `{"to":"+1","text":"hello there"}`,
		"routing only": `{"to":"+1","action":"send"}`,
		"over the cap": `{"blocks":[` + strings.Repeat(`"x",`, messageTextMaxLeaves+5) + `"x"]}`,
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
