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

package connector

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestOpenHandsProfileDecodeMapsSDKStdinEventTypes(t *testing.T) {
	for stdin, want := range map[string]string{
		"PreToolUse": "pre_tool_use",
		// Anything else keeps the generic resolution.
		"pre_tool_use": "",
	} {
		if got := openHandsProfileDecode(map[string]interface{}{"event_type": stdin}).HookEventName; got != want {
			t.Errorf("event_type %q decoded to %q, want %q", stdin, got, want)
		}
	}

	profile := NewOpenHandsConnector().HookProfile(SetupOpts{})
	if profile.Decode == nil {
		t.Fatal("OpenHands profile has no decoder for its stdin event type")
	}
	for stdin, name := range openHandsHookEvents {
		if !slices.Contains(profile.SupportedEvents, name) {
			t.Errorf("%s maps to %q, which the OpenHands contract does not register", stdin, name)
		}
	}
	if route := profile.ToolCallLifecycle.RouteForEvent(openHandsHookEvents["PreToolUse"]); route != ToolEventRouteStructuredAction {
		t.Errorf("PreToolUse routes to %v, want structured tool-call inspection", route)
	}
	if !slices.Contains(profile.Capabilities.BlockEvents, openHandsHookEvents["PreToolUse"]) {
		t.Errorf("PreToolUse is not a block event: %v", profile.Capabilities.BlockEvents)
	}
}

func TestOpenHandsTerminalActionProjectsOnlyForTheTrustedParser(t *testing.T) {
	// The exact tool input OpenHands CLI 1.16 sends for a terminal call.
	input := `{"command":"echo marker","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"}`
	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":`+input+`}`), &payload); err != nil {
		t.Fatal(err)
	}
	// The decoder leaves the recorded tool input alone; only the
	// trusted-action parser sees the projection.
	if got := openHandsProfileDecode(payload); got.ToolArgsAuthoritative || len(got.ToolArgs) != 0 {
		t.Errorf("decode replaced the tool input: authoritative=%v %s", got.ToolArgsAuthoritative, got.ToolArgs)
	}
	projected, ok := OpenHandsTrustedShellArgs("terminal", json.RawMessage(input))
	if !ok || string(projected) != `{"command":"echo marker"}` {
		t.Errorf("tool_input %s projected to ok=%v %s, want the command alone", input, ok, projected)
	}
	// Anything else keeps the generic, unproven arguments.
	for _, tc := range []struct{ tool, args string }{
		{"terminal", `{"command":"echo marker","env":{"A":"1"}}`},
		{"file_editor", `{"command":"view","path":"/tmp/x"}`},
	} {
		if got, ok := OpenHandsTrustedShellArgs(tc.tool, json.RawMessage(tc.args)); ok || string(got) != tc.args {
			t.Errorf("%s %s projected to ok=%v %s, want no projection", tc.tool, tc.args, ok, got)
		}
	}
}
