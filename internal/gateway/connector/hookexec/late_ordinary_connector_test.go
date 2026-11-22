// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "testing"

// Only Claude Code and Codex calls that a gateway took and did not answer may
// follow the open outage tier; on Windows the link-hop scan does not run, so
// the connector check alone keeps a Kiro or Devin shell call closed
// (rel-1-0-10 GAP-0030, GAP-0518 contract).
func TestLateOrdinaryOpenIsLimitedToClaudeCodeAndCodex(t *testing.T) {
	payload := []byte(`{"hook_event_name":"PreToolUse","tool_name":"shell","tool_input":{"command":"echo ok"}}`)
	for _, connector := range []string{"kiro", "devin", "antigravity", "copilot", "cursor", "hermes"} {
		opts := Options{Connector: connector, Event: "PreToolUse", failurePayload: payload}
		if bothLateScansOrdinary(opts) {
			t.Fatalf("%s late call follows the open tier", connector)
		}
	}
	for _, connector := range []string{"claudecode", "codex", " Codex "} {
		if !lateOrdinaryConnector(connector) {
			t.Fatalf("%s lost the late ordinary path", connector)
		}
	}
}
