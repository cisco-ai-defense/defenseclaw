// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "testing"

// GAP-0271: a hook-failure line names the agent's tool call id as call_id
// and tool_id, so the gateway can record a call the hook blocked under the
// tool id of its own decision row. A source event id or a bare call_id is
// no tool id.
func TestHookFailureCorrelationNamesTheToolCallID(t *testing.T) {
	for _, tc := range []struct {
		payload, session, call, tool string
	}{
		{`{"session_id":"s","tool_use_id":"toolu_1"}`, "s", "toolu_1", "toolu_1"},
		{`{"sessionID":"s","callID":"oc_1"}`, "s", "oc_1", "oc_1"},
		{`{"thread_id":"s","tool_call_id":"call_1","tool_use_id":"toolu_1"}`, "s", "call_1", "call_1"},
		{`{"session_id":"s","source_event_id":"ev_1","tool_use_id":"toolu_1"}`, "s", "ev_1", ""},
		{`{"session_id":"s","call_id":"c_1"}`, "s", "c_1", ""},
	} {
		session, call, tool := hookFailureCorrelation([]byte(tc.payload))
		if session != tc.session || call != tc.call || tool != tc.tool {
			t.Errorf("%s: session=%q call=%q tool=%q, want %q %q %q", tc.payload, session, call, tool, tc.session, tc.call, tc.tool)
		}
	}
	if _, call, tool := hookFailureCorrelation([]byte(`{"session_id":"s"}`)); call == "" || tool != "" {
		t.Errorf("no id in the payload: call=%q tool=%q, want a random call id and no tool id", call, tool)
	}
}
