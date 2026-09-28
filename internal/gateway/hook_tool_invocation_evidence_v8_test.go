// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// bindHookToolEvidenceRuntime binds the real v8 runtime with the default
// local event history (the audit database), optionally redacting the
// tool.activity bucket.
func bindHookToolEvidenceRuntime(t *testing.T, profile string) (*APIServer, string) {
	t.Helper()
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{}
	fixture.sidecar.setAPIServer(api)
	raw := fmt.Sprintf("config_version: 8\ndata_dir: %q\n", fixture.dataDir)
	if profile != "" {
		raw += fmt.Sprintf("observability:\n  buckets:\n    tool.activity:\n      redaction_profile: %s\n", profile)
	}
	bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, []byte(raw))
	if err != nil || !bound || api.observabilityV8RuntimeEmitter() == nil {
		t.Fatalf("bootstrap v8 runtime bound=%t error=%v", bound, err)
	}
	return api, filepath.Join(fixture.dataDir, config.DefaultAuditDBName)
}

// emitClaudeCanaryPreToolUse drives the gateway's Claude Code hook path with
// the PreToolUse payload Claude Code sends for the live-check canary, as the
// hook helper reports it for OS user uid.
func emitClaudeCanaryPreToolUse(t *testing.T, api *APIServer, toolCallID, command, uid string) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"session_id": "claude-canary-session", "hook_event_name": "PreToolUse", "cwd": "/home/alice",
		"tool_name": "Bash", "tool_use_id": toolCallID,
		"tool_input": map[string]any{"command": command, "description": "DefenseClaw live policy check"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	ctx := ContextWithAgentIdentity(t.Context(), AgentIdentity{UserID: uid, UserIDKind: "posix_uid", UserName: "alice"})
	api.emitClaudeCodeHookLLMEvent(ctx, decodeClaudeCodeRequestFromBytes(raw, payload), nil, raw)
}

func waitForHookToolInvocation(t *testing.T, dbPath string, query audit.HookToolInvocationQuery) audit.HookToolInvocationEvidence {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		evidence, err := audit.FindHookToolInvocation(context.Background(), dbPath, query)
		if err != nil {
			t.Fatal(err)
		}
		if evidence.Matched || time.Now().After(deadline) {
			return evidence
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The live Claude Code check proves hook contact from the record the real v8
// emitter leaves for a PreToolUse hook call. It matches the tool call id, an
// identifier every built-in redaction profile keeps, so redacted tool
// arguments do not matter; a record for another connector, user or tool
// call, or one older than the check, does not count.
func TestHookToolInvocationEvidenceMatchesTheV8EventHistory(t *testing.T) {
	for _, profile := range []string{"", "strict"} {
		t.Run("profile="+profile, func(t *testing.T) {
			api, dbPath := bindHookToolEvidenceRuntime(t, profile)
			started := time.Now()
			const toolCallID = "toolu_defenseclaw_canary_0123456789abcdef01234567"
			const marker = "defenseclaw-canary-0123456789abcdef01234567"
			emitClaudeCanaryPreToolUse(t, api, toolCallID, "echo "+marker, "1000")
			query := audit.HookToolInvocationQuery{Connector: "claudecode", ToolCallID: toolCallID, Since: started, UserID: "1000"}
			if evidence := waitForHookToolInvocation(t, dbPath, query); !evidence.Matched {
				t.Fatalf("the v8 record of the canary PreToolUse call must match: %+v", evidence)
			}
			if profile == "strict" {
				db, err := sql.Open("sqlite", dbPath)
				if err != nil {
					t.Fatal(err)
				}
				defer db.Close()
				var projected string
				if err := db.QueryRow(`SELECT projected_record_json FROM audit_events WHERE event_name = 'tool.invocation.requested'`).Scan(&projected); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(projected, marker) {
					t.Fatalf("test setup: strict must redact the tool arguments: %s", projected)
				}
			}
			for name, tc := range map[string]struct {
				query      audit.HookToolInvocationQuery
				mismatched bool
			}{
				"other connector": {audit.HookToolInvocationQuery{Connector: "codex", ToolCallID: toolCallID, Since: started, UserID: "1000"}, true},
				"other user":      {audit.HookToolInvocationQuery{Connector: "claudecode", ToolCallID: toolCallID, Since: started, UserID: "1001"}, true},
				"later check":     {audit.HookToolInvocationQuery{Connector: "claudecode", ToolCallID: toolCallID, Since: time.Now().Add(time.Hour), UserID: "1000"}, false},
				"other tool call": {audit.HookToolInvocationQuery{Connector: "claudecode", ToolCallID: "toolu_other", Since: started, UserID: "1000"}, false},
			} {
				evidence, err := audit.FindHookToolInvocation(context.Background(), dbPath, tc.query)
				if err != nil {
					t.Fatal(err)
				}
				if evidence.Matched || (len(evidence.Mismatches) > 0) != tc.mismatched {
					t.Fatalf("%s: %+v", name, evidence)
				}
			}
		})
	}
}
