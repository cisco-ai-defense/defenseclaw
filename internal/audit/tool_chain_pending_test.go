// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestToolChainPendingMigrationIsAppendOnlyContentFreeAndReady(t *testing.T) {
	const migrationIndex = 30
	if len(migrations) <= migrationIndex ||
		migrations[migrationIndex].description !=
			"guardrails: add pending tool-call predecessor lifecycle" {
		t.Fatal("pending tool-chain state is not append-only migration 31")
	}
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.ToolChainRepository(); err == nil {
		t.Fatal("unready store exposed pending tool-chain repository")
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ToolChainRepository(); err != nil {
		t.Fatalf("ready repository: %v", err)
	}
	if version, err := store.SchemaVersion(); err != nil || version != len(migrations) {
		t.Fatalf("schema version=%d want=%d err=%v", version, len(migrations), err)
	}
	if err := migrateToolChainPendingState(store.db); err != nil {
		t.Fatalf("idempotent migration: %v", err)
	}

	for _, table := range []string{
		"guardrail_chain_pending_actions", "guardrail_chain_pending_boundaries",
		"guardrail_chain_terminal_resets", "guardrail_chain_cutoff_barriers",
	} {
		rows, err := store.db.Query(`PRAGMA table_info(` + table + `)`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var (
				cid, notNull, primaryKey int
				name, columnType         string
				defaultValue             sql.NullString
			)
			if err := rows.Scan(
				&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey,
			); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			for _, forbidden := range []string{
				"command", "argv", "payload", "content", "raw", "normalized_value",
				"path", "endpoint", "url", "tool_name",
			} {
				if strings.Contains(name, forbidden) {
					_ = rows.Close()
					t.Fatalf("%s contains content-bearing column %s", table, name)
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestToolChainPendingTableIsMandatoryForStoreReadiness(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "missing-pending.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.db.Exec(`CREATE TABLE schema_version (
		version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for index, migration := range migrations {
		if err := store.applyMigration(index+1, migration); err != nil {
			t.Fatalf("migration %d: %v", index+1, err)
		}
	}
	if _, err := store.db.Exec(`DROP TABLE guardrail_chain_pending_actions`); err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err == nil || !strings.Contains(
		err.Error(),
		"mandatory SQLite table guardrail_chain_pending_actions is missing",
	) {
		t.Fatalf("missing pending table readiness error=%v", err)
	}
	if store.Ready() {
		t.Fatal("missing pending table published store readiness")
	}
}

func TestToolChainPendingSuccessCommitsTerminalPredecessorAndReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	fixture := newToolChainFixture(t, path)
	chainID := guardrail.ToolChainSecretReadThenEgress
	pre := fixture.seed(t, "pending-success", correlationDigest("pending-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  pre.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("invocation-success"),
		PreSemanticEventID:   pre.SemanticEventID,
		PreInputFingerprint:  pre.InputFingerprint,
		RulesetFingerprint:   pre.RulesetFingerprint,
		Projection:           toolChainProjection(t, []string{chainID}, 1, true),
	}
	if result, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
		result.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%#v err=%v", result, err)
	}
	if result, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
		result.Status != ToolChainPendingReplay {
		t.Fatalf("prepare replay=%#v err=%v", result, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	fixture = newToolChainFixture(t, path)
	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "pending-success", correlationDigest("pending-terminal"))
	resolve := ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     prepare.ToolInvocationDigest,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       prepare.RulesetFingerprint,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	}
	resolved, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || resolved.Status != ToolChainPendingResolved ||
		resolved.Observation.Status != ToolChainObserveFresh {
		t.Fatalf("resolve=%#v err=%v", resolved, err)
	}
	var pending, preEvents, terminalEvents int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events
		WHERE semantic_event_id=?`, string(pre.SemanticEventID)).Scan(&preEvents); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_events
		WHERE semantic_event_id=?`, string(terminal.SemanticEventID)).Scan(&terminalEvents); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || preEvents != 0 || terminalEvents != 1 {
		t.Fatalf("pending/pre/terminal rows=%d/%d/%d want 0/0/1",
			pending, preEvents, terminalEvents)
	}
	if replay, err := fixture.chain.ResolvePending(t.Context(), resolve); err != nil ||
		replay.Status != ToolChainPendingMissing {
		t.Fatalf("resolve replay=%#v err=%v", replay, err)
	}

	fixture.now = fixture.now.Add(time.Second)
	final := fixture.seed(t, "pending-success", correlationDigest("pending-final"))
	final.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	final.DenyEligible = true
	matched, err := fixture.chain.Observe(t.Context(), final)
	if err != nil || matched.DeniedMask == 0 {
		t.Fatalf("terminal predecessor match=%#v err=%v", matched, err)
	}
}

func TestToolChainPendingConflictInvalidatesBothProposals(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretReadThenEgress
	invocation := correlationDigest("collision-invocation")

	preA := fixture.seed(t, "collision-session", correlationDigest("collision-pre-a"))
	prepareA := ToolChainPreparePendingInput{
		ConnectorInstanceID:  preA.ConnectorInstanceID,
		ToolInvocationDigest: invocation,
		PreSemanticEventID:   preA.SemanticEventID,
		PreInputFingerprint:  preA.InputFingerprint,
		RulesetFingerprint:   preA.RulesetFingerprint,
		Projection:           toolChainProjection(t, []string{chainID}, 1, true),
	}
	if result, err := fixture.chain.PreparePending(t.Context(), prepareA); err != nil ||
		result.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare A=%#v err=%v", result, err)
	}

	preB := fixture.seed(t, "collision-session", correlationDigest("collision-pre-b"))
	prepareB := prepareA
	prepareB.PreSemanticEventID = preB.SemanticEventID
	prepareB.PreInputFingerprint = preB.InputFingerprint
	prepareB.Projection = toolChainProjection(t, []string{chainID}, 1, false)
	if result, err := fixture.chain.PreparePending(t.Context(), prepareB); !errors.Is(err, ErrToolChainPendingConflict) || result.Status != "" {
		t.Fatalf("prepare B conflict=%#v err=%v", result, err)
	}

	var pending int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending after collision=%d err=%v", pending, err)
	}

	terminalB := fixture.seed(
		t,
		"collision-session",
		correlationDigest("collision-terminal-b"),
	)
	resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminalB.ConnectorInstanceID,
		ToolInvocationDigest:     invocation,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       prepareB.RulesetFingerprint,
		TerminalSemanticEventID:  terminalB.SemanticEventID,
		TerminalInputFingerprint: terminalB.InputFingerprint,
	})
	if err != nil || resolved.Status != ToolChainPendingMissing ||
		resolved.Observation.Status != "" {
		t.Fatalf("resolve B=%#v err=%v", resolved, err)
	}

	var predecessors int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_events`).Scan(&predecessors); err != nil || predecessors != 0 {
		t.Fatalf("committed predecessors=%d err=%v", predecessors, err)
	}
}

func TestToolChainPendingNonSuccessNeverCommits(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainGuardrailsOffThenEgress
	for index, outcome := range []ToolChainPendingOutcome{
		ToolChainPendingOutcomeFailure,
		ToolChainPendingOutcomeDenied,
		ToolChainPendingOutcomeCancelled,
		ToolChainPendingOutcomeUnknown,
	} {
		pre := fixture.seed(t, "pending-failure", correlationDigest("failed-pre-"+string(rune('a'+index))))
		prepare := ToolChainPreparePendingInput{
			ConnectorInstanceID:  pre.ConnectorInstanceID,
			ToolInvocationDigest: correlationDigest("failed-invocation-" + string(outcome)),
			PreSemanticEventID:   pre.SemanticEventID,
			PreInputFingerprint:  pre.InputFingerprint,
			RulesetFingerprint:   pre.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, true),
		}
		if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
			t.Fatal(err)
		}
		terminal := fixture.seed(
			t,
			"pending-failure",
			correlationDigest("failed-terminal-"+string(outcome)),
		)
		result, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      pre.ConnectorInstanceID,
			ToolInvocationDigest:     prepare.ToolInvocationDigest,
			Outcome:                  outcome,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		})
		if err != nil || result.Status != ToolChainPendingResolved ||
			result.Observation.Status != "" {
			t.Fatalf("outcome %s result=%#v err=%v", outcome, result, err)
		}
	}
	var pending, events int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || events != 0 {
		t.Fatalf("non-success pending/events=%d/%d want 0/0", pending, events)
	}
}

func TestToolChainPendingAcceptsMarkerAndRejectsTerminalProjection(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainPrivilegeDiscoveryThenElevation
	pre := fixture.seed(t, "pending-session-a", correlationDigest("identity-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  pre.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("identity-invocation"),
		PreSemanticEventID:   pre.SemanticEventID,
		PreInputFingerprint:  pre.InputFingerprint,
		RulesetFingerprint:   pre.RulesetFingerprint,
		Projection: guardrail.ToolChainProjection{
			ParseStatus: actionfacts.StatusNotApplicable,
		},
	}
	if result, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil ||
		result.Status != ToolChainPendingPrepared {
		t.Fatalf("marker prepare=%#v err=%v", result, err)
	}
	markerTerminal := fixture.seed(
		t,
		"pending-session-a",
		correlationDigest("identity-marker-terminal"),
	)
	markerResult, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      markerTerminal.ConnectorInstanceID,
		ToolInvocationDigest:     prepare.ToolInvocationDigest,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       prepare.RulesetFingerprint,
		TerminalSemanticEventID:  markerTerminal.SemanticEventID,
		TerminalInputFingerprint: markerTerminal.InputFingerprint,
	})
	if err != nil || markerResult.Status != ToolChainPendingResolved ||
		markerResult.Observation.Status != "" {
		t.Fatalf("marker resolve=%#v err=%v", markerResult, err)
	}
	prepare.ToolInvocationDigest = correlationDigest("identity-terminal")
	prepare.Projection = toolChainProjection(t, []string{chainID}, 2, true)
	if _, err := fixture.chain.PreparePending(t.Context(), prepare); err == nil {
		t.Fatal("terminal projection was accepted as pending predecessor")
	}
	prepare.ToolInvocationDigest = correlationDigest("identity-invocation")
	prepare.Projection = toolChainProjection(t, []string{chainID}, 1, true)
	if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
		t.Fatal(err)
	}

	fixture.now = fixture.now.Add(time.Second)
	wrongSession := fixture.seed(t, "pending-session-b", correlationDigest("wrong-session"))
	resolve := ToolChainResolvePendingInput{
		ConnectorInstanceID:      pre.ConnectorInstanceID,
		ToolInvocationDigest:     prepare.ToolInvocationDigest,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       prepare.RulesetFingerprint,
		TerminalSemanticEventID:  wrongSession.SemanticEventID,
		TerminalInputFingerprint: wrongSession.InputFingerprint,
	}
	if result, err := fixture.chain.ResolvePending(t.Context(), resolve); err != nil ||
		result.Status != ToolChainPendingMissing {
		t.Fatalf("session mismatch result=%#v error=%v", result, err)
	}
	var pending int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("session conflict pending=%d err=%v", pending, err)
	}

	sameSession := fixture.seed(t, "pending-session-a", correlationDigest("same-session"))
	resolve.TerminalSemanticEventID = sameSession.SemanticEventID
	resolve.TerminalInputFingerprint = sameSession.InputFingerprint
	resolve.RulesetFingerprint = correlationDigest("new-ruleset")
	stale, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || stale.Status != ToolChainPendingExpired {
		t.Fatalf("ruleset drift=%#v err=%v", stale, err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("stale ruleset pending=%d err=%v", pending, err)
	}
}

func TestToolChainPendingTTLAndCapacityAreBounded(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	fixture.chain.maxPending = 2
	fixture.chain.pendingTTL = time.Minute
	chainID := guardrail.ToolChainSecretManagerReadThenEgress
	var inputs []ToolChainPreparePendingInput
	for index := 0; index < 3; index++ {
		pre := fixture.seed(t, "pending-bounds", correlationDigest("bound-pre-"+string(rune('a'+index))))
		input := ToolChainPreparePendingInput{
			ConnectorInstanceID:  pre.ConnectorInstanceID,
			ToolInvocationDigest: correlationDigest("bound-invocation-" + string(rune('a'+index))),
			PreSemanticEventID:   pre.SemanticEventID,
			PreInputFingerprint:  pre.InputFingerprint,
			RulesetFingerprint:   pre.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, true),
		}
		if _, err := fixture.chain.PreparePending(t.Context(), input); err != nil {
			t.Fatal(err)
		}
		inputs = append(inputs, input)
		fixture.now = fixture.now.Add(time.Second)
	}
	var count, oldest int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions
		WHERE tool_invocation_digest=?`, inputs[0].ToolInvocationDigest).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if count != 2 || oldest != 0 {
		t.Fatalf("bounded pending count/oldest=%d/%d want 2/0", count, oldest)
	}

	fixture.now = fixture.now.Add(time.Minute)
	terminal := fixture.seed(t, "pending-bounds", correlationDigest("bound-terminal"))
	expired, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      inputs[1].ConnectorInstanceID,
		ToolInvocationDigest:     inputs[1].ToolInvocationDigest,
		Outcome:                  ToolChainPendingOutcomeFailure,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	})
	if err != nil || expired.Status != ToolChainPendingExpired {
		t.Fatalf("expired result=%#v err=%v", expired, err)
	}
}

func TestToolChainPendingInvocationIdentityIsScopedToExactSession(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	invocation := correlationDigest("shared-invocation")
	chainID := guardrail.ToolChainPrivilegeDiscoveryThenElevation
	for _, session := range []string{"pending-session-a", "pending-session-b"} {
		pre := fixture.seed(t, session, correlationDigest("pre-"+session))
		input := ToolChainPreparePendingInput{
			ConnectorInstanceID:  pre.ConnectorInstanceID,
			ToolInvocationDigest: invocation,
			PreSemanticEventID:   pre.SemanticEventID,
			PreInputFingerprint:  pre.InputFingerprint,
			RulesetFingerprint:   pre.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, true),
		}
		if result, err := fixture.chain.PreparePending(t.Context(), input); err != nil ||
			result.Status != ToolChainPendingPrepared {
			t.Fatalf("prepare %s=%#v err=%v", session, result, err)
		}
	}

	terminal := fixture.seed(t, "pending-session-b", correlationDigest("terminal-b"))
	resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     invocation,
		Outcome:                  ToolChainPendingOutcomeFailure,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	})
	if err != nil || resolved.Status != ToolChainPendingResolved {
		t.Fatalf("resolve session b=%#v err=%v", resolved, err)
	}
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pending after session-b resolve=%d err=%v", count, err)
	}
	var remainingSession string
	if err := fixture.store.db.QueryRow(`SELECT session_value_digest
		FROM guardrail_chain_pending_actions`).Scan(&remainingSession); err != nil {
		t.Fatal(err)
	}
	if remainingSession != correlationDigest("pending-session-a") {
		t.Fatalf("remaining session=%q want session a", remainingSession)
	}
}

func TestToolChainDiscardPendingForEventSessionIsExactAndBounded(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretReadThenEgress
	var replayInput ToolChainPreparePendingInput
	for index, session := range []string{"discard-a", "discard-a", "discard-b"} {
		pre := fixture.seed(t, session, correlationDigest("discard-pre-"+string(rune('a'+index))))
		input := ToolChainPreparePendingInput{
			ConnectorInstanceID:  pre.ConnectorInstanceID,
			ToolInvocationDigest: correlationDigest("discard-invocation-" + string(rune('a'+index))),
			PreSemanticEventID:   pre.SemanticEventID,
			PreInputFingerprint:  pre.InputFingerprint,
			RulesetFingerprint:   pre.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, false),
		}
		if index == 0 {
			replayInput = input
		}
		_, err := fixture.chain.PreparePending(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
	}

	terminal := fixture.seed(t, "discard-a", correlationDigest("discard-terminal"))
	fixture.now = fixture.now.Add(time.Millisecond)
	postBoundary := fixture.seed(
		t, "discard-a", correlationDigest("discard-post-boundary-pre"),
	)
	postBoundaryInvocation := correlationDigest("discard-post-boundary-invocation")
	if prepared, err := fixture.chain.PreparePending(
		t.Context(), ToolChainPreparePendingInput{
			ConnectorInstanceID:  postBoundary.ConnectorInstanceID,
			ToolInvocationDigest: postBoundaryInvocation,
			PreSemanticEventID:   postBoundary.SemanticEventID,
			PreInputFingerprint:  postBoundary.InputFingerprint,
			RulesetFingerprint:   postBoundary.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, false),
		},
	); err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("post-boundary prepare=%#v err=%v", prepared, err)
	}
	discarded, err := fixture.chain.DiscardPendingForEventSession(
		t.Context(),
		ToolChainDiscardPendingForEventSessionInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		},
	)
	if err != nil || discarded.Status != ToolChainPendingResolved || discarded.Count != 2 {
		t.Fatalf("discard=%#v err=%v", discarded, err)
	}
	var count int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("pending after discard=%d err=%v", count, err)
	}
	var postBoundaryCount int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions
		WHERE connector_instance_id=? AND session_value_digest=?
		AND tool_invocation_digest=?`, string(terminal.ConnectorInstanceID),
		correlationDigest("discard-a"), postBoundaryInvocation,
	).Scan(&postBoundaryCount); err != nil || postBoundaryCount != 1 {
		t.Fatalf("post-boundary pending=%d err=%v", postBoundaryCount, err)
	}
	replayedPrepare, err := fixture.chain.PreparePending(t.Context(), replayInput)
	if err != nil || replayedPrepare.Status != ToolChainPendingExpired {
		t.Fatalf("replayed pre-boundary prepare=%#v err=%v", replayedPrepare, err)
	}
	lateSuccess, err := fixture.chain.ResolvePending(
		t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      replayInput.ConnectorInstanceID,
			ToolInvocationDigest:     replayInput.ToolInvocationDigest,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       replayInput.RulesetFingerprint,
			TerminalSemanticEventID:  postBoundary.SemanticEventID,
			TerminalInputFingerprint: postBoundary.InputFingerprint,
		},
	)
	if err != nil || lateSuccess.Status != ToolChainPendingMissing {
		t.Fatalf("late success=%#v err=%v", lateSuccess, err)
	}
	again, err := fixture.chain.DiscardPendingForEventSession(
		t.Context(),
		ToolChainDiscardPendingForEventSessionInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		},
	)
	if err != nil || again.Status != ToolChainPendingReplay || again.Count != 0 {
		t.Fatalf("discard replay=%#v err=%v", again, err)
	}

	// Exercise the production saturation path at a one-row bound. The oldest
	// exact-session cutoff is summarized by the global barrier before discard-b
	// is recorded, without deleting unrelated pending work.
	fixture.chain.maxPartitions = 1
	fixture.now = fixture.now.Add(time.Millisecond)
	terminalB := fixture.seed(t, "discard-b", correlationDigest("discard-b-terminal"))
	bounded, err := fixture.chain.DiscardPendingForEventSession(
		t.Context(), ToolChainDiscardPendingForEventSessionInput{
			ConnectorInstanceID:      terminalB.ConnectorInstanceID,
			TerminalSemanticEventID:  terminalB.SemanticEventID,
			TerminalInputFingerprint: terminalB.InputFingerprint,
		},
	)
	if err != nil || bounded.Status != ToolChainPendingResolved || bounded.Count != 1 {
		t.Fatalf("bounded discard=%#v err=%v", bounded, err)
	}
	var boundaryCount, barrierCount, pendingBCount int
	var boundarySession string
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*), session_value_digest
		FROM guardrail_chain_pending_boundaries`).Scan(
		&boundaryCount, &boundarySession,
	); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_cutoff_barriers
		WHERE barrier_kind='pending_boundary'`).Scan(&barrierCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions WHERE session_value_digest=?`,
		correlationDigest("discard-b"),
	).Scan(&pendingBCount); err != nil {
		t.Fatal(err)
	}
	if boundaryCount != 1 || boundarySession != correlationDigest("discard-b") ||
		barrierCount != 1 || pendingBCount != 0 {
		t.Fatalf("bounded boundary/session/barrier/pending=%d/%q/%d/%d",
			boundaryCount, boundarySession, barrierCount, pendingBCount)
	}
	if replayed, err := fixture.chain.PreparePending(
		t.Context(), replayInput,
	); err != nil || replayed.Status != ToolChainPendingExpired {
		t.Fatalf("evicted-session stale prepare=%#v err=%v", replayed, err)
	}
	if replayed, err := fixture.chain.DiscardPendingForEventSession(
		t.Context(), ToolChainDiscardPendingForEventSessionInput{
			ConnectorInstanceID:      terminal.ConnectorInstanceID,
			TerminalSemanticEventID:  terminal.SemanticEventID,
			TerminalInputFingerprint: terminal.InputFingerprint,
		},
	); err != nil || replayed.Status != ToolChainPendingReplay {
		t.Fatalf("evicted boundary replay=%#v err=%v", replayed, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	survivorTerminal := fixture.seed(
		t, "discard-a", correlationDigest("discard-survivor-terminal"),
	)
	survived, err := fixture.chain.ResolvePending(
		t.Context(), ToolChainResolvePendingInput{
			ConnectorInstanceID:      postBoundary.ConnectorInstanceID,
			ToolInvocationDigest:     postBoundaryInvocation,
			Outcome:                  ToolChainPendingOutcomeSuccess,
			RulesetFingerprint:       postBoundary.RulesetFingerprint,
			TerminalSemanticEventID:  survivorTerminal.SemanticEventID,
			TerminalInputFingerprint: survivorTerminal.InputFingerprint,
		},
	)
	if err != nil || survived.Status != ToolChainPendingResolved ||
		survived.Observation.Status != ToolChainObserveFresh {
		t.Fatalf("unrelated pending after saturation=%#v err=%v", survived, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	fresh := fixture.seed(t, "discard-a", correlationDigest("discard-fresh-pre"))
	freshResult, err := fixture.chain.PreparePending(
		t.Context(), ToolChainPreparePendingInput{
			ConnectorInstanceID:  fresh.ConnectorInstanceID,
			ToolInvocationDigest: correlationDigest("discard-fresh-invocation"),
			PreSemanticEventID:   fresh.SemanticEventID,
			PreInputFingerprint:  fresh.InputFingerprint,
			RulesetFingerprint:   fresh.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, false),
		},
	)
	if err != nil || freshResult.Status != ToolChainPendingPrepared {
		t.Fatalf("post-barrier prepare=%#v err=%v", freshResult, err)
	}
}

func TestToolChainTerminalResetIsExactAndSuppressesStaleReplay(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainPrivilegeDiscoveryThenElevation
	seedObserved := func(session, name string, step int, deny bool) ToolChainObserveInput {
		t.Helper()
		input := fixture.seed(t, session, correlationDigest(name))
		input.Projection = toolChainProjection(t, []string{chainID}, step, true)
		input.DenyEligible = deny
		return input
	}
	pendingInput := func(session, name string) ToolChainPreparePendingInput {
		t.Helper()
		pre := fixture.seed(t, session, correlationDigest(name+"-pre"))
		return ToolChainPreparePendingInput{
			ConnectorInstanceID:  pre.ConnectorInstanceID,
			ToolInvocationDigest: correlationDigest(name + "-invocation"),
			PreSemanticEventID:   pre.SemanticEventID,
			PreInputFingerprint:  pre.InputFingerprint,
			RulesetFingerprint:   pre.RulesetFingerprint,
			Projection:           toolChainProjection(t, []string{chainID}, 1, true),
		}
	}
	prepare := func(session, name string) (ToolChainPreparePendingInput, ToolChainPreparePendingResult) {
		t.Helper()
		input := pendingInput(session, name)
		result, err := fixture.chain.PreparePending(t.Context(), input)
		if err != nil {
			t.Fatal(err)
		}
		return input, result
	}

	firstA := seedObserved("reset-a", "reset-a-first", 1, false)
	if result, err := fixture.chain.Observe(t.Context(), firstA); err != nil ||
		result.Status != ToolChainObserveFresh {
		t.Fatalf("first a=%#v err=%v", result, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	finalA := seedObserved("reset-a", "reset-a-final", 2, true)
	denied, err := fixture.chain.Observe(t.Context(), finalA)
	if err != nil || denied.Status != ToolChainObserveFresh || denied.DeniedMask == 0 ||
		len(denied.ReceiptIDs) != 1 {
		t.Fatalf("final a=%#v err=%v", denied, err)
	}
	pendingA, preparedA := prepare("reset-a", "reset-a-pending")
	if preparedA.Status != ToolChainPendingPrepared {
		t.Fatalf("pending a=%#v", preparedA)
	}
	latePendingA := pendingInput("reset-a", "reset-a-late-pending")

	firstB := seedObserved("reset-b", "reset-b-first", 1, false)
	if _, err := fixture.chain.Observe(t.Context(), firstB); err != nil {
		t.Fatal(err)
	}
	_, preparedB := prepare("reset-b", "reset-b-pending")
	if preparedB.Status != ToolChainPendingPrepared {
		t.Fatalf("pending b=%#v", preparedB)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	terminal := fixture.seed(t, "reset-a", correlationDigest("reset-a-terminal"))
	fixture.now = fixture.now.Add(time.Millisecond)
	if late, err := fixture.chain.PreparePending(t.Context(), latePendingA); err != nil ||
		late.Status != ToolChainPendingPrepared {
		t.Fatalf("late prepared predecessor=%#v err=%v", late, err)
	}
	postPendingA, preparedPostA := prepare("reset-a", "reset-a-post-pending")
	if preparedPostA.Status != ToolChainPendingPrepared {
		t.Fatalf("post-terminal pending=%#v", preparedPostA)
	}
	resetInput := ToolChainResetForTerminalEventSessionInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	}
	mismatch := resetInput
	mismatch.TerminalInputFingerprint = correlationDigest("mismatched-terminal")
	if result, err := fixture.chain.ResetForTerminalEventSession(
		t.Context(), mismatch,
	); !errors.Is(err, ErrToolChainIntegrity) ||
		result != (ToolChainResetForTerminalEventSessionResult{}) {
		t.Fatalf("mismatched reset=%#v err=%v", result, err)
	}

	reset, err := fixture.chain.ResetForTerminalEventSession(t.Context(), resetInput)
	if err != nil || reset.Status != ToolChainSessionResetApplied ||
		reset.PendingCount != 2 || reset.EventCount != 2 {
		t.Fatalf("reset=%#v err=%v", reset, err)
	}
	var pendingACount, pendingBCount, eventsBCount, receipts int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions
		WHERE session_value_digest=? AND tool_invocation_digest=?`,
		correlationDigest("reset-a"), postPendingA.ToolInvocationDigest,
	).Scan(&pendingACount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_pending_actions WHERE session_value_digest=?`,
		correlationDigest("reset-b")).Scan(&pendingBCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_events WHERE session_value_digest=?`,
		correlationDigest("reset-b")).Scan(&eventsBCount); err != nil {
		t.Fatal(err)
	}
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_deny_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if pendingACount != 1 || pendingBCount != 1 || eventsBCount != 1 || receipts != 1 {
		t.Fatalf("newer pending/other session/receipts=%d/%d/%d/%d",
			pendingACount, pendingBCount, eventsBCount, receipts)
	}

	stale, err := fixture.chain.Observe(t.Context(), firstA)
	if err != nil || stale.Status != ToolChainObserveReplay ||
		!stale.SuppressTelemetry || stale.DetectedMask != 0 || stale.DeniedMask != 0 {
		t.Fatalf("stale direct replay=%#v err=%v", stale, err)
	}
	stalePending, err := fixture.chain.PreparePending(t.Context(), pendingA)
	if err != nil || stalePending.Status != ToolChainPendingExpired {
		t.Fatalf("stale pending replay=%#v err=%v", stalePending, err)
	}
	deniedReplay, err := fixture.chain.Observe(t.Context(), finalA)
	if err != nil || deniedReplay.Status != ToolChainObserveReplay ||
		deniedReplay.DeniedMask != denied.DeniedMask ||
		len(deniedReplay.ReceiptIDs) != 1 {
		t.Fatalf("deny receipt replay=%#v err=%v", deniedReplay, err)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	newFirst := seedObserved("reset-a", "reset-a-new-first", 1, false)
	if result, err := fixture.chain.Observe(t.Context(), newFirst); err != nil ||
		result.Status != ToolChainObserveFresh {
		t.Fatalf("new first=%#v err=%v", result, err)
	}
	replayedReset, err := fixture.chain.ResetForTerminalEventSession(t.Context(), resetInput)
	if err != nil || replayedReset.Status != ToolChainSessionResetReplay ||
		replayedReset.PendingCount != 0 || replayedReset.EventCount != 0 {
		t.Fatalf("reset replay=%#v err=%v", replayedReset, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	newFinal := seedObserved("reset-a", "reset-a-new-final", 2, true)
	matched, err := fixture.chain.Observe(t.Context(), newFinal)
	if err != nil || matched.Status != ToolChainObserveFresh || matched.DeniedMask == 0 {
		t.Fatalf("post-reset chain=%#v err=%v", matched, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	newTerminalA := fixture.seed(t, "reset-a", correlationDigest("reset-a-new-terminal"))
	newResetInput := ToolChainResetForTerminalEventSessionInput{
		ConnectorInstanceID:      newTerminalA.ConnectorInstanceID,
		TerminalSemanticEventID:  newTerminalA.SemanticEventID,
		TerminalInputFingerprint: newTerminalA.InputFingerprint,
	}
	if newer, err := fixture.chain.ResetForTerminalEventSession(
		t.Context(), newResetInput,
	); err != nil || newer.Status != ToolChainSessionResetApplied {
		t.Fatalf("newer reset=%#v err=%v", newer, err)
	}
	if older, err := fixture.chain.ResetForTerminalEventSession(
		t.Context(), resetInput,
	); err != nil || older.Status != ToolChainSessionResetReplay {
		t.Fatalf("older reset replay=%#v err=%v", older, err)
	}
	var retainedTerminal string
	if err := fixture.store.db.QueryRow(`SELECT terminal_semantic_event_id
		FROM guardrail_chain_terminal_resets
		WHERE connector_instance_id=? AND session_value_digest=?`,
		string(newTerminalA.ConnectorInstanceID), correlationDigest("reset-a"),
	).Scan(&retainedTerminal); err != nil {
		t.Fatal(err)
	}
	if retainedTerminal != string(newTerminalA.SemanticEventID) {
		t.Fatalf("older reset moved cutoff to %q", retainedTerminal)
	}

	fixture.now = fixture.now.Add(time.Millisecond)
	survivorFirst := seedObserved(
		"reset-survivor", "reset-survivor-first", 1, false,
	)
	if result, err := fixture.chain.Observe(
		t.Context(), survivorFirst,
	); err != nil || result.Status != ToolChainObserveFresh {
		t.Fatalf("survivor predecessor=%#v err=%v", result, err)
	}

	fixture.chain.maxPartitions = 1
	fixture.now = fixture.now.Add(time.Millisecond)
	terminalB := fixture.seed(t, "reset-b", correlationDigest("reset-b-terminal"))
	bounded, err := fixture.chain.ResetForTerminalEventSession(
		t.Context(), ToolChainResetForTerminalEventSessionInput{
			ConnectorInstanceID:      terminalB.ConnectorInstanceID,
			TerminalSemanticEventID:  terminalB.SemanticEventID,
			TerminalInputFingerprint: terminalB.InputFingerprint,
		},
	)
	if err != nil || bounded.Status != ToolChainSessionResetApplied {
		t.Fatalf("bounded reset=%#v err=%v", bounded, err)
	}
	var resetCount int
	var resetSession string
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*), session_value_digest
		FROM guardrail_chain_terminal_resets`).Scan(&resetCount, &resetSession); err != nil {
		t.Fatal(err)
	}
	if resetCount != 1 || resetSession != correlationDigest("reset-b") {
		t.Fatalf("bounded resets=%d/%q", resetCount, resetSession)
	}
	var barrierCount int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*)
		FROM guardrail_chain_cutoff_barriers
		WHERE barrier_kind='terminal_reset'`).Scan(&barrierCount); err != nil {
		t.Fatal(err)
	}
	if barrierCount != 1 {
		t.Fatalf("terminal reset barrier count=%d want 1", barrierCount)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	survivorFinal := seedObserved(
		"reset-survivor", "reset-survivor-final", 2, true,
	)
	if survived, err := fixture.chain.Observe(
		t.Context(), survivorFinal,
	); err != nil || survived.Status != ToolChainObserveFresh ||
		survived.DeniedMask == 0 {
		t.Fatalf("unrelated committed predecessor after saturation=%#v err=%v",
			survived, err)
	}
	if stale, err := fixture.chain.Observe(t.Context(), firstA); err != nil ||
		stale.Status != ToolChainObserveReplay || !stale.SuppressTelemetry {
		t.Fatalf("evicted-session stale observe=%#v err=%v", stale, err)
	}
	if stale, err := fixture.chain.PreparePending(
		t.Context(), pendingA,
	); err != nil || stale.Status != ToolChainPendingExpired {
		t.Fatalf("evicted-session stale prepare=%#v err=%v", stale, err)
	}
	fixture.now = fixture.now.Add(time.Millisecond)
	freshObserved := seedObserved("reset-a", "reset-a-after-barrier", 1, false)
	if fresh, err := fixture.chain.Observe(
		t.Context(), freshObserved,
	); err != nil || fresh.Status != ToolChainObserveFresh {
		t.Fatalf("post-barrier observe=%#v err=%v", fresh, err)
	}
	_, freshPrepared := prepare("reset-a", "reset-a-pending-after-barrier")
	if freshPrepared.Status != ToolChainPendingPrepared {
		t.Fatalf("post-barrier prepare=%#v", freshPrepared)
	}
}
