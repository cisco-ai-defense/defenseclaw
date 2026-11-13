// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
