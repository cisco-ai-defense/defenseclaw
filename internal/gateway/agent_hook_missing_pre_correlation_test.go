// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-1228: concurrent hooks of one session can leave one delivery of a call
// without its correlation (no connector instance). The audited PreToolUse
// still matches its PostToolUse: ordinary parallel Codex work raises no
// missing-pre-tool alert.
func TestPostToolMatchesAuditedPreAcrossCorrelationOutcome(t *testing.T) {
	for _, test := range []struct{ name, pre, post string }{
		{"pre without correlation", "", "caller-instance"},
		{"post without correlation", "caller-instance", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, logger := testStoreAndLogger(t)
			api := &APIServer{store: store, logger: logger}
			response := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "observe"}
			for _, step := range []struct{ event, instance string }{{"PreToolUse", test.pre}, {"PostToolUse", test.post}} {
				req := agentHookRequest{ConnectorName: "codex", ConnectorInstanceID: step.instance,
					HookEventName: step.event, SessionID: "session-1", ToolInvocationID: "call_1", ToolName: "Bash"}
				if !api.finalizeAgentHook(t.Context(), "codex", req, response, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
					t.Fatal("hook decision audit was not persisted")
				}
			}
			events, err := store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			for _, event := range events {
				if event.Action == string(audit.ActionAlert) && event.Actor == "hook-pre-tool-missing" {
					t.Fatalf("audited PreToolUse reported missing: %+v", event)
				}
			}
		})
	}
}
