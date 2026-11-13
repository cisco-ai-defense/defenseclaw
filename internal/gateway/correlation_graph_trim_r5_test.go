// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// correlateClaudeHookForTest runs one Claude Code hook payload through the
// hook correlation of server.
func correlateClaudeHookForTest(t *testing.T, server *APIServer, payload map[string]any) agentHookRequest {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	profile := server.hookProfileForConnector("claudecode")
	request := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
	_, request, err = server.correlateHookOccurrence(t.Context(), profile, request, body)
	if err != nil {
		t.Fatalf("%v: %v", payload["hook_event_name"], err)
	}
	return request
}

func countCorrelationRowsForTest(t *testing.T, path, query string, args ...any) int {
	t.Helper()
	var count int
	if err := openCorrelationDB(t, path).QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return count
}

// TestMembershipIdentifierMatchesAreDroppedSoTheyAreNotStored proves the
// premise of S8 R5's identifier trim from the matcher: a turn or agent
// identifier another event shares matches it only as
// scoped-native-membership, a belongs_to that merges nothing and that
// putCorrelationMatchRelationship does not store. Such rows (a 1.0.9 store
// keeps them) never gave a reader anything.
func TestMembershipIdentifierMatchesAreDroppedSoTheyAreNotStored(t *testing.T) {
	installCorrelationHMACForTest()
	_, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	instance, err := repo.ResolveConnectorInstance(ctx, "claudecode", "claudecode-correlation-test", audit.ConnectorCustodyHookOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []audit.CorrelationIdentifierKind{
		audit.CorrelationIdentifierTurn, audit.CorrelationIdentifierPrompt, audit.CorrelationIdentifierAgent,
	} {
		if correlationIdentifierStored(kind) {
			t.Fatalf("%s identifiers are still stored", kind)
		}
		semantic, err := audit.NewSemanticEventID()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		tx, _, err := repo.BeginOccurrence(ctx, audit.CorrelationOccurrenceInput{Event: audit.CorrelationEvent{
			SemanticEventID: semantic, Connector: "claudecode", ConnectorInstanceID: instance.ConnectorInstanceID,
			Rail: audit.CorrelationRailHook, EventName: "tool_start", ReceivedTime: now,
			ProfileVersion: "claudecode-correlation-test", Completeness: audit.CorrelationPartial,
		}})
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(kind))
		identifier := audit.CorrelationMatchIdentifier{
			Namespace: "claudecode/" + string(kind), Kind: kind, ValueDigest: hex.EncodeToString(digest[:]),
		}
		if _, err := tx.PutIdentifier(ctx, audit.CorrelationIdentifier{
			SemanticEventID: semantic, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: identifier.Namespace, Kind: kind, ValueDigest: identifier.ValueDigest,
			NormalizedValue: "value-" + string(kind), SourceField: string(kind) + "_id",
			Origin: audit.CorrelationOriginReported, ProfileVersion: "claudecode-correlation-test", ObservedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		match, err := repo.MatchOccurrence(ctx, audit.CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID,
			Identifiers:         []audit.CorrelationMatchIdentifier{identifier},
		})
		if err != nil {
			t.Fatal(err)
		}
		if match.MatchedSemanticEventID != semantic || match.RuleID != "scoped-native-membership" ||
			match.RelationshipType != audit.CorrelationBelongsTo || match.MergeAllowed || match.LogicalEventID != "" {
			t.Fatalf("%s identifier match = %+v, want a non-merging scoped-native-membership", kind, match)
		}
		other, err := audit.NewSemanticEventID()
		if err != nil {
			t.Fatal(err)
		}
		relationship, err := putCorrelationMatchRelationship(ctx, nil, other,
			audit.CorrelationOccurrenceResult{Status: audit.CorrelationOccurrenceNew}, match, now)
		if err != nil || relationship != nil {
			t.Fatalf("%s membership match stored %+v, %v", kind, relationship, err)
		}
	}
}

// TestHookOccurrenceKeepsTurnAndAgentNodesWithoutTheirIdentifiers: a Claude
// Code session stores no turn, prompt or agent identifier, keeps its session
// identifier (the tool chain's partition key), and its graph still has the
// turn and agent nodes, from the occurrence's own edges (S8 R5).
func TestHookOccurrenceKeepsTurnAndAgentNodesWithoutTheirIdentifiers(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	server.scannerCfg = config.DefaultConfig()
	cwd := t.TempDir()
	correlateClaudeHookForTest(t, server, map[string]any{
		"hook_event_name": "SessionStart", "session_id": "session-r5", "cwd": cwd, "source": "startup",
	})
	prompt := correlateClaudeHookForTest(t, server, map[string]any{
		"hook_event_name": "UserPromptSubmit", "session_id": "session-r5", "cwd": cwd, "prompt": "status",
	})
	tool := correlateClaudeHookForTest(t, server, map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "session-r5", "cwd": cwd, "tool_name": "Bash",
		"tool_use_id": "toolu_r5_1", "tool_input": map[string]any{"command": "git status"},
	})
	if prompt.TurnID == "" || tool.TurnID != prompt.TurnID || tool.AgentID == "" {
		t.Fatalf("the session has no turn or agent: prompt %+v tool %+v", prompt, tool)
	}
	if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind IN ('turn','prompt','agent')`); got != 0 {
		t.Fatalf("%d turn, prompt or agent identifiers stored", got)
	}
	if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_identifiers
		WHERE identifier_kind='session' AND semantic_event_id=?`, tool.SemanticEventID); got != 1 {
		t.Fatalf("the tool call has %d session identifiers, want 1", got)
	}
	for _, edge := range []struct{ fromKind, fromID, toKind, toID string }{
		{"semantic_event", tool.SemanticEventID, "turn", tool.TurnID},
		{"semantic_event", tool.SemanticEventID, "agent", tool.AgentID},
		{"semantic_event", tool.SemanticEventID, "session", "session-r5"},
		{"agent", tool.AgentID, "session", "session-r5"},
	} {
		if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_relationships
			WHERE from_kind=? AND from_id=? AND to_kind=? AND to_id=? AND status='active'`,
			edge.fromKind, edge.fromID, edge.toKind, edge.toID); got != 1 {
			t.Fatalf("edge %+v: %d rows, want 1", edge, got)
		}
	}
}

// TestNativeCustodyClaudeHooksKeepClaimsAndToolIdentifier: a per-user
// Claude Code hook has no native counterpart, so it stores no cross-rail
// identity claim and no tool identifier; a managed or sandboxed hook keeps
// both, and a managed hook and the native span of the same tool call are
// still one logical event with a same_as edge (S8 R5).
func TestNativeCustodyClaudeHooksKeepClaimsAndToolIdentifier(t *testing.T) {
	for _, mode := range []string{"per-user", "sandboxed", "managed"} {
		t.Run(mode, func(t *testing.T) {
			installCorrelationHMACForTest()
			fixture := newCodexNativeOTLPFixture(t)
			api := &APIServer{store: fixture.store}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			ctx := t.Context()
			switch mode {
			case "per-user":
				api.scannerCfg = config.DefaultConfig()
			case "sandboxed":
				api.scannerCfg = config.DefaultConfig()
				ctx = sandboxauth.WithRequest(ctx, sandboxauth.Binding{
					ID: "sb_0000000000000000000000000000000a", Connector: "claudecode",
				}, nil)
				ctx = withAuthenticatedHookConnector(ctx, "claudecode")
			case "managed":
				api.scannerCfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise,
					Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
			}
			payload, raw := loadClaudeHookCorrelationSourceFixture(t)
			profile := api.hookProfileForRequest(ctx, "claudecode")
			hook := normalizeAgentHookRequestWithProfile("claudecode", payload, profile)
			_, hook, err := api.correlateHookOccurrence(ctx, profile, hook, raw)
			if err != nil {
				t.Fatal(err)
			}
			claims := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_identity_claims
				WHERE semantic_event_id=?`, hook.SemanticEventID)
			tools := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_identifiers
				WHERE semantic_event_id=? AND identifier_kind='tool_invocation'`, hook.SemanticEventID)
			sessions := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_identifiers
				WHERE semantic_event_id=? AND identifier_kind='session'`, hook.SemanticEventID)
			if mode == "per-user" {
				if claims != 0 || tools != 0 || sessions != 1 {
					t.Fatalf("per-user hook claims=%d tool identifiers=%d session identifiers=%d, want 0, 0, 1",
						claims, tools, sessions)
				}
				return
			}
			if claims == 0 || tools != 1 || sessions != 1 {
				t.Fatalf("%s hook claims=%d tool identifiers=%d session identifiers=%d, want claims, 1, 1",
					mode, claims, tools, sessions)
			}
			if mode != "managed" {
				return
			}
			accounting, err := api.importDecodedOTLPRequestV8(
				t.Context(), loadClaudeNativeCorrelationSourceFixture(t), otelSignalTraces,
				"claudecode", time.Now().UTC(),
			)
			if err != nil || !accounting.valid() || accounting.importedAndDerived != 1 {
				t.Fatalf("Claude native import accounting=%+v err=%v", accounting, err)
			}
			events := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_events
				WHERE logical_group_id=?`, hook.LogicalEventID)
			sameAs := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_relationships
				WHERE relationship_type='same_as' AND status='active'
				AND ((from_kind='semantic_event' AND from_id=?) OR (to_kind='semantic_event' AND to_id=?))`,
				hook.SemanticEventID, hook.SemanticEventID)
			if events != 2 || sameAs == 0 {
				t.Fatalf("managed hook and native span: %d events in the hook group, %d same_as edges", events, sameAs)
			}
		})
	}
}

// TestSettledToolCallLeavesNoPendingOperation: a PostToolUse resolves its
// PreToolUse's pending operation by deleting it, and the same PostToolUse
// delivered again finds nothing to resolve and is recorded without error
// (S8 R5).
func TestSettledToolCallLeavesNoPendingOperation(t *testing.T) {
	installCorrelationHMACForTest()
	path := filepath.Join(t.TempDir(), "audit.db")
	server, store := newHookCorrelationServer(t, path)
	defer store.Close() //nolint:errcheck
	server.scannerCfg = config.DefaultConfig()
	cwd := t.TempDir()
	start := correlateClaudeHookForTest(t, server, map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "session-r5-pending", "cwd": cwd, "tool_name": "Bash",
		"tool_use_id": "toolu_r5_pending", "tool_input": map[string]any{"command": "git status"},
	})
	if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_pending_operations
		WHERE status='active' AND start_semantic_event_id=?`, start.SemanticEventID); got != 1 {
		t.Fatalf("PreToolUse left %d active operations, want 1", got)
	}
	post := map[string]any{
		"hook_event_name": "PostToolUse", "session_id": "session-r5-pending", "cwd": cwd, "tool_name": "Bash",
		"tool_use_id": "toolu_r5_pending", "tool_input": map[string]any{"command": "git status"},
		"tool_response": map[string]any{"stdout": "On branch main", "stderr": "", "interrupted": false},
	}
	end := correlateClaudeHookForTest(t, server, post)
	if end.ToolInvocationID != start.ToolInvocationID || end.TurnID != start.TurnID || end.AgentID != start.AgentID {
		t.Fatalf("PostToolUse did not continue its start: start %+v end %+v", start, end)
	}
	if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_pending_operations`); got != 0 {
		t.Fatalf("a settled tool call left %d pending operations, want 0", got)
	}
	replay := correlateClaudeHookForTest(t, server, post)
	if replay.ToolInvocationID != start.ToolInvocationID {
		t.Fatalf("replayed PostToolUse lost its tool call: %+v", replay)
	}
	if got := countCorrelationRowsForTest(t, path, `SELECT COUNT(*) FROM correlation_pending_operations`); got != 0 {
		t.Fatalf("a replayed PostToolUse left %d pending operations, want 0", got)
	}
}

// sendClaudeToolHookForTest sends one Claude Code PreToolUse or PostToolUse
// of "git status" through the full hook handler of fixture.
func sendClaudeToolHookForTest(t *testing.T, fixture auditFailureHookFixture, cwd, event, toolUseID string) {
	t.Helper()
	payload := map[string]any{
		"hook_event_name": event, "session_id": "session-r5-settle", "cwd": cwd,
		"tool_name": "Bash", "tool_use_id": toolUseID, "tool_input": map[string]any{"command": "git status"},
	}
	if event == "PostToolUse" {
		payload["tool_response"] = map[string]any{"stdout": "On branch main", "stderr": "", "interrupted": false}
	}
	recorder := httptest.NewRecorder()
	fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(mustBenchJSON(t, payload))))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: status %d body %.200s", event, recorder.Code, recorder.Body.String())
	}
}

// waitForCorrelationRowsForTest waits up to 5 s for query to count want.
func waitForCorrelationRowsForTest(t *testing.T, path string, want int, query string, args ...any) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := countCorrelationRowsForTest(t, path, query, args...)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d rows, want %d", query, got, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSettledClaudeToolCallReleasesItsReplayReceipt: a PreToolUse sent
// again before its PostToolUse is still suppressed as a replay; the
// PostToolUse deletes the start's accepted receipt; a PreToolUse sent again
// after it is evaluated and recorded again, never dropped (S8 R5).
func TestSettledClaudeToolCallReleasesItsReplayReceipt(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	const accepted = `SELECT COUNT(*) FROM correlation_receipts WHERE accepted_time_unix_nano IS NOT NULL`
	sendClaudeToolHookForTest(t, fixture, cwd, "PreToolUse", "toolu_r5_settle")
	waitForCorrelationRowsForTest(t, fixture.path, 1, accepted)
	events := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_events`)

	sendClaudeToolHookForTest(t, fixture, cwd, "PreToolUse", "toolu_r5_settle")
	if got := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_events`); got != events {
		t.Fatalf("a replay before the PostToolUse added %d occurrences", got-events)
	}
	if got := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_receipts
		WHERE delivery_count=2`); got != 1 {
		t.Fatalf("the replay before the PostToolUse was not counted on its receipt (%d)", got)
	}

	sendClaudeToolHookForTest(t, fixture, cwd, "PostToolUse", "toolu_r5_settle")
	if got := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_receipts`); got != 0 {
		t.Fatalf("the settled call kept %d receipts, want 0", got)
	}
	events = countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_events`)

	sendClaudeToolHookForTest(t, fixture, cwd, "PreToolUse", "toolu_r5_settle")
	if got := countCorrelationRowsForTest(t, fixture.path, `SELECT COUNT(*) FROM correlation_events`); got != events+1 {
		t.Fatalf("a replay after the PostToolUse recorded %d occurrences, want 1", got-events)
	}
	waitForCorrelationRowsForTest(t, fixture.path, 1, accepted)
}

// TestSettledClaudeToolCallLeavesNoChainPendingAction: the tool chain's
// pending action of a PreToolUse is gone once its PostToolUse came, so a
// settled call leaves none of its 1 KB (S8 R5).
func TestSettledClaudeToolCallLeavesNoChainPendingAction(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "open")
	cwd := t.TempDir()
	const actions = `SELECT COUNT(*) FROM guardrail_chain_pending_actions`
	sendClaudeToolHookForTest(t, fixture, cwd, "PreToolUse", "toolu_r5_chain")
	if got := countCorrelationRowsForTest(t, fixture.path, actions); got != 1 {
		t.Fatalf("PreToolUse left %d chain pending actions, want 1", got)
	}
	sendClaudeToolHookForTest(t, fixture, cwd, "PostToolUse", "toolu_r5_chain")
	if got := countCorrelationRowsForTest(t, fixture.path, actions); got != 0 {
		t.Fatalf("a settled call left %d chain pending actions, want 0", got)
	}
}
