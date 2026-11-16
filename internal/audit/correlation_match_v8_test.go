// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

func TestMatchOccurrenceUsesExactFirstOrderWithoutCollapsingLifecycleEvents(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	receipt := &CorrelationReceiptClaim{
		SourceKeyDigest: correlationDigest("source-receipt"), FingerprintSHA256: correlationDigest("payload"),
		ReceivedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	sourceDigest := correlationDigest("native-source-occurrence")
	turnDigest := correlationDigest("native-turn")
	compositeDigest := correlationDigest("profile-composite")
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		rail: CorrelationRailHook, eventName: "tool.started", receivedAt: now, receipt: receipt,
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			for _, identifier := range []CorrelationIdentifier{
				{SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace: "codex.hook", Kind: CorrelationIdentifierSourceEvent,
					ValueDigest: sourceDigest, NormalizedValue: "source-occurrence", SourceField: "event_id",
					Origin: CorrelationOriginReported, ProfileVersion: instance.ProfileVersion, ObservedAt: now},
				{SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace: "codex", Kind: CorrelationIdentifierTurn,
					ValueDigest: turnDigest, NormalizedValue: "turn", SourceField: "turn_id",
					Origin: CorrelationOriginReported, ProfileVersion: instance.ProfileVersion, ObservedAt: now},
				{SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace: "codex.composite.tool", Kind: CorrelationIdentifierSourceSequence,
					ValueDigest: compositeDigest, NormalizedValue: "composite", SourceField: "composite",
					Origin: CorrelationOriginDerived, ProfileVersion: instance.ProfileVersion, ObservedAt: now},
			} {
				if _, err := tx.PutIdentifier(t.Context(), identifier); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.PutObservation(t.Context(), CorrelationObservation{
				RecordID: "hook-observation", SemanticEventID: event.SemanticEventID,
				Signal: CorrelationSignalLogs, Bucket: "agent", EventName: event.EventName, ObservedAt: now,
				TraceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpanID: "bbbbbbbbbbbbbbbb",
				SessionID: "session", TurnID: "turn", AgentID: "agent",
				Status: CorrelationObservationExportEligible,
			}); err != nil {
				t.Fatal(err)
			}
			if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
				ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
				OperationID: "tool-call", Type: CorrelationOperationTool,
				ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
				Name: "shell", SessionID: "session", TurnID: "turn",
				AgentID: "agent", StartSemanticEventID: event.SemanticEventID,
				StartedAt: now, Status: CorrelationOperationActive,
			}); err != nil {
				t.Fatal(err)
			}
		},
	})
	traceOnly := CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		TraceID:             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SpanID:              "bbbbbbbbbbbbbbbb",
	}
	result, err := repo.MatchOccurrence(t.Context(), traceOnly)
	if err != nil || result.Rank != CorrelationMatchNone || result.MergeAllowed {
		t.Fatalf("hook trace context became same-as authority: result=%+v err=%v", result, err)
	}
	nativeEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		rail: CorrelationRailNativeOTLP, eventName: "tool.started", receivedAt: now.Add(time.Nanosecond),
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if err := tx.PutObservation(t.Context(), CorrelationObservation{
				RecordID: "native-trace-observation", SemanticEventID: event.SemanticEventID,
				Signal: CorrelationSignalTraces, Bucket: "agent", EventName: event.EventName,
				ObservedAt: now.Add(time.Nanosecond), TraceID: traceOnly.TraceID, SpanID: traceOnly.SpanID,
				Status: CorrelationObservationExportEligible,
			}); err != nil {
				t.Fatal(err)
			}
		},
	})

	base := CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Receipt:             &CorrelationReceiptLookup{SourceKeyDigest: receipt.SourceKeyDigest, FingerprintSHA256: receipt.FingerprintSHA256},
		Identifiers:         []CorrelationMatchIdentifier{{Namespace: "codex.hook", Kind: CorrelationIdentifierSourceEvent, ValueDigest: sourceDigest}},
		TraceID:             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SpanID: "bbbbbbbbbbbbbbbb",
		Composite: &CorrelationCompositeMatch{Namespace: "codex.composite.tool", Kind: CorrelationIdentifierSourceSequence,
			ValueDigest: compositeDigest, RuleID: "codex-tool-composite", RuleVersion: "v1"},
		Pending: &CorrelationPendingMatch{Namespace: "codex", Kind: CorrelationIdentifierTool,
			Type: CorrelationOperationTool, ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
			Name: "shell", SessionID: "session", TurnID: "turn", AgentID: "agent"},
		Similarity: &CorrelationSimilarityHint{SessionID: "session", AgentID: "agent", EventName: "tool.started", Around: now, Window: time.Second},
	}
	base.SemanticEventID = event.SemanticEventID
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchSemanticEvent || !result.MergeAllowed || result.LogicalEventID != event.LogicalEventID {
		t.Fatalf("semantic result=%+v err=%v", result, err)
	}
	base.SemanticEventID = ""
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchReceipt || !result.MergeAllowed {
		t.Fatalf("receipt result=%+v err=%v", result, err)
	}
	base.Receipt = &CorrelationReceiptLookup{
		SourceKeyDigest:   receipt.SourceKeyDigest,
		FingerprintSHA256: correlationDigest("conflicting-payload"),
	}
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchReceipt || !result.Conflict ||
		result.ConflictsWith != event.SemanticEventID || result.MergeAllowed ||
		result.MatchedSemanticEventID != "" || result.LogicalEventID != "" {
		t.Fatalf("receipt conflict must stop weaker matching result=%+v err=%v", result, err)
	}
	base.Receipt = nil
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchNativeIdentifier || !result.MergeAllowed {
		t.Fatalf("source occurrence result=%+v err=%v", result, err)
	}
	base.Identifiers = []CorrelationMatchIdentifier{{Namespace: "codex", Kind: CorrelationIdentifierTurn, ValueDigest: turnDigest}}
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchTraceSpan || !result.MergeAllowed ||
		result.LogicalEventID != nativeEvent.LogicalEventID {
		t.Fatalf("trace must outrank non-merge membership result=%+v err=%v", result, err)
	}
	base.Identifiers = nil
	base.TraceID, base.SpanID = "", ""
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchProfileComposite || result.MergeAllowed ||
		result.RelationshipType != CorrelationCorrelatesWith || result.LogicalEventID != "" {
		t.Fatalf("composite result=%+v err=%v", result, err)
	}
	base.Composite = nil
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchUniquePending || result.MergeAllowed ||
		result.RelationshipType != CorrelationBelongsTo {
		t.Fatalf("pending result=%+v err=%v", result, err)
	}
	base.Pending = nil
	result, err = repo.MatchOccurrence(t.Context(), base)
	if err != nil || result.Rank != CorrelationMatchSimilarityCandidate || result.MergeAllowed ||
		!result.CandidateOnly || result.RelationshipType != CorrelationCorrelatesWith {
		t.Fatalf("similarity result=%+v err=%v", result, err)
	}
}

func TestMatchOccurrenceScopesKindsNamespacesAndRequiresPhaseCompatibleCrossRailMirror(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	now := time.Now().UTC()
	digest := correlationDigest("same-raw-value")
	toolDigest := correlationDigest("same-tool-call")
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		rail: CorrelationRailHook, eventName: "tool.started", receivedAt: now,
		mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			for _, identifier := range []CorrelationIdentifier{
				{SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace: "codex", Kind: CorrelationIdentifierTurn, ValueDigest: digest,
					NormalizedValue: "native-value", SourceField: "turn_id", Origin: CorrelationOriginReported,
					ProfileVersion: instance.ProfileVersion, ObservedAt: now},
				{SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
					Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: toolDigest,
					NormalizedValue: "tool-call", SourceField: "tool_use_id", Origin: CorrelationOriginReported,
					ProfileVersion: instance.ProfileVersion, ObservedAt: now},
			} {
				if _, err := tx.PutIdentifier(t.Context(), identifier); err != nil {
					t.Fatal(err)
				}
			}
		},
	})

	for _, identifier := range []CorrelationMatchIdentifier{
		{Namespace: "codex", Kind: CorrelationIdentifierThread, ValueDigest: digest},
		{Namespace: "codex", Kind: CorrelationIdentifierAction, ValueDigest: digest},
		{Namespace: "codex.app-server", Kind: CorrelationIdentifierTurn, ValueDigest: digest},
	} {
		result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID, Identifiers: []CorrelationMatchIdentifier{identifier},
		})
		if err != nil || result.Rank != CorrelationMatchNone {
			t.Fatalf("kind/namespace leak identifier=%+v result=%+v err=%v", identifier, result, err)
		}
	}
	grouping := []CorrelationMatchIdentifier{{Namespace: "codex", Kind: CorrelationIdentifierTurn, ValueDigest: digest}}
	result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID, Identifiers: grouping,
	})
	if err != nil || result.MergeAllowed || result.RelationshipType != CorrelationBelongsTo || result.LogicalEventID != "" {
		t.Fatalf("turn grouping result=%+v err=%v", result, err)
	}
	result, err = repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID, Identifiers: grouping,
		MirrorCompatibility: &CorrelationMirrorCompatibility{
			Rail: CorrelationRailNativeOTLP, EventName: "tool.completed",
			RuleID: "codex-tool-phase", RuleVersion: "v1",
			EquivalentIdentifierKinds: []CorrelationIdentifierKind{CorrelationIdentifierTool},
		},
	})
	if err != nil || result.MergeAllowed || result.RelationshipType != CorrelationBelongsTo {
		t.Fatalf("different phase result=%+v err=%v", result, err)
	}
	mirrorGrouping := []CorrelationMatchIdentifier{{Namespace: "codex", Kind: CorrelationIdentifierTool, ValueDigest: toolDigest}}
	result, err = repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID, Identifiers: mirrorGrouping,
		MirrorCompatibility: &CorrelationMirrorCompatibility{
			Rail: CorrelationRailNativeOTLP, EventName: "tool.started",
			RuleID: "codex-tool-phase", RuleVersion: "v1",
			EquivalentIdentifierKinds: []CorrelationIdentifierKind{CorrelationIdentifierTool},
		},
	})
	if err != nil || !result.MergeAllowed || result.RelationshipType != CorrelationSameAs ||
		result.LogicalEventID != event.LogicalEventID {
		t.Fatalf("phase-compatible mirror result=%+v err=%v", result, err)
	}
	// Same-rail evidence cannot claim a mirror, even with the same event name.
	result, err = repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID, Identifiers: mirrorGrouping,
		MirrorCompatibility: &CorrelationMirrorCompatibility{
			Rail: CorrelationRailHook, EventName: "tool.started",
			RuleID: "codex-tool-phase", RuleVersion: "v1",
			EquivalentIdentifierKinds: []CorrelationIdentifierKind{CorrelationIdentifierTool},
		},
	})
	if err != nil || result.MergeAllowed {
		t.Fatalf("same-rail mirror result=%+v err=%v", result, err)
	}
}

func TestMatchOccurrenceNeverChoosesAmbiguousPendingOrNativeGroups(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "cursor", ConnectorCustodyHookOnly)
	now := time.Now().UTC()
	digest := correlationDigest("shared-turn")
	for index := 0; index < 2; index++ {
		operationID := "tool-a"
		if index == 1 {
			operationID = "tool-b"
		}
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(time.Duration(index) * time.Nanosecond), mutate: func(tx *CorrelationTx, event CorrelationEvent) {
			if _, err := tx.PutIdentifier(t.Context(), CorrelationIdentifier{
				SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
				Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest,
				NormalizedValue: "shared-turn", SourceField: "generation_id", Origin: CorrelationOriginReported,
				ProfileVersion: instance.ProfileVersion, ObservedAt: now,
			}); err != nil {
				t.Fatal(err)
			}
			if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
				ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "cursor", Kind: CorrelationIdentifierTool,
				OperationID: operationID, Type: CorrelationOperationTool,
				ScopeKind: CorrelationOperationScopeSession, ScopeID: "session",
				Name: "shell", SessionID: "session",
				StartSemanticEventID: event.SemanticEventID, StartedAt: now,
				Status: CorrelationOperationActive,
			}); err != nil {
				t.Fatal(err)
			}
		}})
	}
	result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Identifiers:         []CorrelationMatchIdentifier{{Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest}},
	})
	if err != nil || !result.Ambiguous || result.MatchedSemanticEventID != "" || result.LogicalEventID != "" {
		t.Fatalf("ambiguous identifier result=%+v err=%v", result, err)
	}
	result, err = repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Pending: &CorrelationPendingMatch{Namespace: "cursor", Kind: CorrelationIdentifierTool,
			Type: CorrelationOperationTool, ScopeKind: CorrelationOperationScopeSession,
			ScopeID: "session", Name: "shell", SessionID: "session"},
	})
	if err != nil || !result.Ambiguous || result.MatchedSemanticEventID != "" || result.LogicalEventID != "" {
		t.Fatalf("ambiguous pending result=%+v err=%v", result, err)
	}
}

// The identifier match reads only the earliest match and one match from
// another logical group (GAP-0186). A shared identifier stays an unambiguous
// candidate while every match is in one logical group, and becomes ambiguous
// when any later match is in another group, not only the second one.
func TestMatchOccurrenceGroupingIsAmbiguousWhenAnyMatchHasAnotherLogicalGroup(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "cursor", ConnectorCustodyHookOnly)
	now := time.Now().UTC()
	digest := correlationDigest("shared-session-turn")
	identify := func(tx *CorrelationTx, event CorrelationEvent) {
		if _, err := tx.PutIdentifier(t.Context(), CorrelationIdentifier{
			SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest,
			NormalizedValue: "shared-session-turn", SourceField: "generation_id", Origin: CorrelationOriginReported,
			ProfileVersion: instance.ProfileVersion, ObservedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	match := func() CorrelationMatchResult {
		t.Helper()
		result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
			ConnectorInstanceID: instance.ConnectorInstanceID,
			Identifiers:         []CorrelationMatchIdentifier{{Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	first, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now, mutate: identify})
	for index := 1; index <= 3; index++ {
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
			receivedAt: now.Add(time.Duration(index) * time.Nanosecond), logical: first.LogicalEventID, mutate: identify,
		})
	}
	if result := match(); result.Ambiguous || result.MatchedSemanticEventID != first.SemanticEventID ||
		result.MergeAllowed || result.LogicalEventID != "" {
		t.Fatalf("one logical group result=%+v, want the earliest event as a candidate", result)
	}
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(10 * time.Nanosecond), mutate: identify})
	if result := match(); !result.Ambiguous || result.MatchedSemanticEventID != "" || result.LogicalEventID != "" {
		t.Fatalf("a later match in another logical group result=%+v, want ambiguous", result)
	}
}
