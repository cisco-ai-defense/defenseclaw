// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestStructuredFileEmailChainRequiresExactSingleArtifactIdentity(t *testing.T) {
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainFileReadThenEmailSameArtifact,
	)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 {
		t.Fatalf("file-email chain definition=%+v", definition)
	}
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	project := func(tool, arguments string) guardrail.ToolChainProjection {
		t.Helper()
		facts := actionfacts.Analyze(actionfacts.Input{
			Tool: tool, Args: json.RawMessage(arguments),
		})
		projection := guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}
		projectStructuredFileEmailChainSteps(&projection, facts)
		return projection
	}

	read := project("get_file_by_id", `{"file_id":"19"}`)
	same := project("send_email", `{
		"recipients":["reviewer@example.test"],
		"subject":"review", "body":"attached", "cc":null, "bcc":null,
		"attachments":[{"file_id":"19","type":"file"}]
	}`)
	assertToolChainStep(t, read, definition.ID, 1, false)
	assertToolChainStep(t, same, definition.ID, 2, false)
	if read.EnforcementJoinDigests[index] == "" ||
		read.EnforcementJoinDigests[index] != same.EnforcementJoinDigests[index] {
		t.Fatal("same file identity did not produce an exact opaque join")
	}

	pending, synchronous := splitToolChainProjection(same)
	if pending.DetectionStepMask&definition.Step2Bit == 0 ||
		synchronous.DetectionStepMask&definition.Step2Bit != 0 {
		t.Fatalf("terminal-success split pending=%+v synchronous=%+v", pending, synchronous)
	}

	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	matches, err := guardrail.MatchToolChains([]guardrail.ToolChainWindowEvent{{
		SemanticEventID: "read", Sequence: 1, ReceivedAt: now, Projection: read,
	}}, guardrail.ToolChainWindowEvent{
		SemanticEventID: "email", Sequence: 2, ReceivedAt: now.Add(time.Second), Projection: same,
	})
	if err != nil || matches.DetectedMask != definition.ResultBit ||
		matches.EnforcementSafeMask != 0 {
		t.Fatalf("same-artifact match=%+v err=%v", matches, err)
	}

	for name, candidate := range map[string]guardrail.ToolChainProjection{
		"different file": project("send_email", `{
			"recipients":["reviewer@example.test"], "subject":"review",
			"body":"attached", "cc":null, "bcc":null,
			"attachments":[{"file_id":"20","type":"file"}]
		}`),
		"multiple files": project("send_email", `{
			"recipients":["reviewer@example.test"], "subject":"review",
			"body":"attached", "cc":null, "bcc":null,
			"attachments":[{"file_id":"19","type":"file"},{"file_id":"20","type":"file"}]
		}`),
		"extended schema": project("send_email", `{
			"recipients":["reviewer@example.test"], "subject":"review",
			"body":"attached", "cc":null, "bcc":null, "priority":"high",
			"attachments":[{"file_id":"19","type":"file"}]
		}`),
	} {
		t.Run(name, func(t *testing.T) {
			if name != "different file" &&
				candidate.DetectionStepMask&definition.Step2Bit != 0 {
				t.Fatalf("ambiguous schema projected terminal role: %+v", candidate)
			}
			got, matchErr := guardrail.MatchToolChains(
				[]guardrail.ToolChainWindowEvent{{
					SemanticEventID: "read", Sequence: 1, ReceivedAt: now, Projection: read,
				}},
				guardrail.ToolChainWindowEvent{
					SemanticEventID: "email", Sequence: 2,
					ReceivedAt: now.Add(time.Second), Projection: candidate,
				},
			)
			if matchErr != nil || got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("hard negative matched=%+v err=%v", got, matchErr)
			}
		})
	}
}

func TestAuthenticatedStructuredFileEmailChainRequiresBothSuccessfulOutcomes(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	handler := http.HandlerFunc(api.handleAgentHook("claudecode"))

	read := func(event, session, invocation, fileID string) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": event, "session_id": session,
			"tool_use_id": invocation, "tool_name": "get_file_by_id",
			"tool_input": map[string]interface{}{"file_id": fileID},
		}
	}
	email := func(event, session, invocation, fileID string) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": event, "session_id": session,
			"tool_use_id": invocation, "tool_name": "send_email",
			"tool_input": map[string]interface{}{
				"recipients": []interface{}{"reviewer@example.test"},
				"subject":    "review", "body": "attached",
				"cc": nil, "bcc": nil,
				"attachments": []interface{}{
					map[string]interface{}{"file_id": fileID, "type": "file"},
				},
			},
		}
	}
	result := func(event, session, invocation, tool, status string) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": event, "session_id": session,
			"tool_use_id": invocation, "tool_name": tool,
			"tool_response": map[string]interface{}{"status": status},
		}
	}

	callAgentHookForTest(t, handler, read("PreToolUse", "success", "read-success", "19"))
	callAgentHookForTest(t, handler, result("PostToolUse", "success", "read-success", "get_file_by_id", "success"))
	preEmail := callAgentHookForTest(t, handler, email("PreToolUse", "success", "email-success", "19"))
	if slices.Contains(preEmail.RuleIDs, guardrail.ToolChainFileReadThenEmailSameArtifact) {
		t.Fatalf("attempt-only transfer matched chain: %+v", preEmail)
	}
	postEmail := callAgentHookForTest(t, handler, result("PostToolUse", "success", "email-success", "send_email", "success"))
	if !slices.Contains(postEmail.RuleIDs, guardrail.ToolChainFileReadThenEmailSameArtifact) ||
		postEmail.Action == guardrailActionBlock || postEmail.WouldBlock {
		t.Fatalf("successful exact lineage did not alert without blocking: %+v", postEmail)
	}

	callAgentHookForTest(t, handler, read("PreToolUse", "failed", "read-failed", "19"))
	callAgentHookForTest(t, handler, result("PostToolUseFailure", "failed", "read-failed", "get_file_by_id", "error"))
	callAgentHookForTest(t, handler, email("PreToolUse", "failed", "email-failed", "19"))
	failed := callAgentHookForTest(t, handler, result("PostToolUse", "failed", "email-failed", "send_email", "success"))
	if slices.Contains(failed.RuleIDs, guardrail.ToolChainFileReadThenEmailSameArtifact) {
		t.Fatalf("failed source armed chain: %+v", failed)
	}

	callAgentHookForTest(t, handler, read("PreToolUse", "mismatch", "read-mismatch", "19"))
	callAgentHookForTest(t, handler, result("PostToolUse", "mismatch", "read-mismatch", "get_file_by_id", "success"))
	callAgentHookForTest(t, handler, email("PreToolUse", "mismatch", "email-mismatch", "20"))
	mismatch := callAgentHookForTest(t, handler, result("PostToolUse", "mismatch", "email-mismatch", "send_email", "success"))
	if slices.Contains(mismatch.RuleIDs, guardrail.ToolChainFileReadThenEmailSameArtifact) {
		t.Fatalf("mismatched file identity completed chain: %+v", mismatch)
	}
}
