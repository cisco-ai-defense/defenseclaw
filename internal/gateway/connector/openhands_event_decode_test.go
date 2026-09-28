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
	for stdin, name := range openHandsStdinEventNames {
		if !slices.Contains(profile.SupportedEvents, name) {
			t.Errorf("%s maps to %q, which the OpenHands contract does not register", stdin, name)
		}
	}
	if route := profile.ToolCallLifecycle.RouteForEvent(openHandsStdinEventNames["PreToolUse"]); route != ToolEventRouteStructuredAction {
		t.Errorf("PreToolUse routes to %v, want structured tool-call inspection", route)
	}
	if !slices.Contains(profile.Capabilities.BlockEvents, openHandsStdinEventNames["PreToolUse"]) {
		t.Errorf("PreToolUse is not a block event: %v", profile.Capabilities.BlockEvents)
	}
}

func TestOpenHandsProfileDecodeProjectsTerminalAction(t *testing.T) {
	decode := func(body string) HookProfileRequest {
		t.Helper()
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatal(err)
		}
		return openHandsProfileDecode(payload)
	}
	// The exact tool input OpenHands CLI 1.16 sends for a terminal call.
	input := `{"command":"echo marker","is_input":false,"timeout":null,"reset":false,"kind":"TerminalAction"}`
	got := decode(`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":` + input + `}`)
	if !got.ToolArgsAuthoritative || string(got.ToolArgs) != `{"command":"echo marker"}` {
		t.Errorf("tool_input %s projected to authoritative=%v %s, want the command alone", input, got.ToolArgsAuthoritative, got.ToolArgs)
	}
	// Anything else keeps the generic, unproven projection.
	for _, body := range []string{
		`{"event_type":"PreToolUse","tool_name":"terminal","tool_input":{"command":"echo marker","env":{"A":"1"}}}`,
		`{"event_type":"PreToolUse","tool_name":"file_editor","tool_input":{"command":"view","path":"/tmp/x"}}`,
	} {
		if got := decode(body); got.ToolArgsAuthoritative || len(got.ToolArgs) != 0 {
			t.Errorf("%s projected to authoritative=%v %s, want no projection", body, got.ToolArgsAuthoritative, got.ToolArgs)
		}
	}
}
