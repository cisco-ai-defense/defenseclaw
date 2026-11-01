// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// GAP-0655: the interpreter-write block reaches Claude Code and Codex as a
// readable sentence with its guidance, in the native answer each agent
// shows, never as redacted spans.
func TestGAP0655InterpreterWriteGuidanceReachesClaudeAndCodex(t *testing.T) {
	redaction.SetAgentReasonRedactionDisabled(false)
	t.Cleanup(func() { redaction.SetAgentReasonRedactionDisabled(false) })
	useAgentVerdictProfile(t, false, false)
	title := hookpaths.UnprovenWriteTitle("interpreter-path") + unprovenWriteGuidance
	source := "matched: persistence.ssh_authorized_keys_command:" + title
	for _, tc := range []struct {
		name    string
		profile connector.HookProfile
	}{
		{"claudecode", connector.NewClaudeCodeConnector().HookProfile(connector.SetupOpts{})},
		{"codex", connector.NewCodexConnector().HookProfile(connector.SetupOpts{})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := agentHookResponseForProfile(tc.profile,
				agentHookRequest{ConnectorName: tc.name, HookEventName: "PreToolUse", ToolName: "Bash"},
				"block", "block", "CRITICAL", source, nil, "action", true, tc.profile.Capabilities)
			wire, err := json.Marshal(renderAgentHookResponseForProfile(tc.profile, resp))
			if err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{resp.Reason, string(wire)} {
				if !strings.Contains(text, unprovenWriteGuidance) || strings.Contains(text, "<redacted") ||
					!strings.Contains(text, agentBlockNoRetry) {
					t.Fatalf("agent text %q lacks the readable guidance", text)
				}
			}
		})
	}
}
