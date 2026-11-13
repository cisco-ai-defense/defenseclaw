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
	"strings"
	"testing"
)

// The message tool's text can sit in any string field of its params
// (GAP-0177). messageTextFromArgs reads all of them.
func TestMessageTextFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args string
		want string
	}{
		{"content", `{"content":"one"}`, "one"},
		{"body", `{"body":"two"}`, "two"},
		{"text", `{"text":"three"}`, "three"},
		{"message", `{"message":"four"}`, "four"},
		{"caption", `{"media":"x","caption":"five"}`, "five\nx"},
		{"known keys first, then the rest sorted", `{"zz":"last","aa":"mid","content":"first"}`, "first\nmid\nlast"},
		{"nested blocks and attachments", `{"blocks":[{"type":"text","text":"b1"},{"type":"text","text":"b2"}],"attachments":[{"title":"a1"}]}`, "b1\nb2\na1"},
		{"routing keys are not text", `{"action":"send","channel":"sms","to":"+15551230000","accountId":"acct"}`, ""},
		{"routing keys inside blocks are not text", `{"blocks":[{"type":"text","id":"blk","text":"hello"}]}`, "hello"},
		{"blank strings are not text", `{"text":"   ","body":""}`, ""},
		{"non-string values are not text", `{"text":42,"flag":true,"n":null,"items":[1,2]}`, ""},
		{"empty args", ``, ""},
		{"not JSON", `not json`, ""},
		{"empty object", `{}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := messageTextFromArgs(json.RawMessage(tc.args)); got != tc.want {
				t.Fatalf("messageTextFromArgs(%s) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestMessageTextFromArgsBounds(t *testing.T) {
	t.Run("depth", func(t *testing.T) {
		deep := `"deep"`
		for i := 0; i < messageTextMaxDepth+4; i++ {
			deep = `{"x":` + deep + `}`
		}
		if got := messageTextFromArgs(json.RawMessage(deep)); got != "" {
			t.Fatalf("a string below the depth limit was read: %q", got)
		}
		shallow := `{"a":{"b":{"c":"seen"}}}`
		if got := messageTextFromArgs(json.RawMessage(shallow)); got != "seen" {
			t.Fatalf("got %q, want seen", got)
		}
	})
	t.Run("leaves", func(t *testing.T) {
		items := make([]string, messageTextMaxLeaves+50)
		for i := range items {
			items[i] = `"s"`
		}
		got := messageTextFromArgs(json.RawMessage(`{"blocks":[` + strings.Join(items, ",") + `]}`))
		if n := strings.Count(got, "s"); n != messageTextMaxLeaves {
			t.Fatalf("read %d leaves, want the cap %d", n, messageTextMaxLeaves)
		}
	})
	t.Run("size keeps head and tail", func(t *testing.T) {
		long := strings.Repeat("a", messageTextMaxBytes) + strings.Repeat("m", 1000) + strings.Repeat("z", messageTextMaxBytes)
		got := messageTextFromArgs(json.RawMessage(`{"text":"` + long + `","body":"` + long + `"}`))
		if len(got) > messageTextMaxBytes+1 {
			t.Fatalf("len = %d, want at most %d", len(got), messageTextMaxBytes+1)
		}
		if !strings.HasPrefix(got, "a") || !strings.HasSuffix(got, "z") {
			t.Fatalf("head or tail lost: %q ... %q", got[:3], got[len(got)-3:])
		}
	})
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
}
