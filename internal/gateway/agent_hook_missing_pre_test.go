// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// A stopped PreToolUse hook never contacts the gateway. A later post-tool
// event cannot undo the tool, but it must leave a prominent audit signal.
func TestPostToolWithoutMatchingPreDecisionRaisesHighAudit(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, test := range []struct {
			name, event, preSession, postSession, preTool, postTool string
			wantAlert, noInstance                                   bool
		}{
			{"missing success", "PostToolUse", "", "session-1", "", "tool-1", true, false},
			{"missing failure", "PostToolUseFailure", "", "session-1", "", "tool-1", true, false},
			{"matching pre", "PostToolUse", "session-1", "session-1", "tool-1", "tool-1", false, false},
			{"matching pre without instance", "PostToolUse", "session-1", "session-1", "tool-1", "tool-1", false, true},
			{"other session", "PostToolUse", "session-2", "session-1", "tool-1", "tool-1", true, false},
			{"other invocation", "PostToolUse", "session-1", "session-1", "tool-2", "tool-1", true, false},
		} {
			t.Run(connector+"/"+test.name, func(t *testing.T) {
				store, logger := testStoreAndLogger(t)
				api := &APIServer{store: store, logger: logger}
				response := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
				finish := func(event, session, tool string) {
					instance := "caller-instance"
					if test.noInstance {
						instance = ""
					}
					req := agentHookRequest{ConnectorName: connector, ConnectorInstanceID: instance,
						HookEventName: event, SessionID: session, ToolInvocationID: tool, ToolName: "Bash"}
					if !api.finalizeAgentHook(t.Context(), connector, req, response, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
						t.Fatal("hook decision audit was not persisted")
					}
				}
				if test.preSession != "" {
					finish("PreToolUse", test.preSession, test.preTool)
				}
				finish(test.event, test.postSession, test.postTool)
				events, err := store.ListEvents(100)
				if err != nil {
					t.Fatal(err)
				}
				alerts := 0
				for _, event := range events {
					if event.Action == string(audit.ActionAlert) && event.Actor == "hook-pre-tool-missing" {
						alerts++
						if event.Severity != "HIGH" || event.SessionID != test.postSession || event.Connector != connector ||
							!strings.Contains(event.Details, missingPreToolRuleID) || !strings.Contains(event.Details, test.postTool) {
							t.Fatalf("missing-pre alert lacks attribution: %+v", event)
						}
					}
				}
				if got := alerts == 1; got != test.wantAlert {
					t.Fatalf("alerts=%d, want alert=%v; events=%+v", alerts, test.wantAlert, events)
				}
			})
		}
	}
}
