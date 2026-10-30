// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

// rel-1-0-3 GAP-0247: the identifier match no longer reads its matches in
// time order first. The earliest match is still the result when every match
// is in one logical group, also when that earliest event was stored last.
func TestMatchOccurrenceSharedIdentifierPicksTheEarliestEventStoredLast(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "cursor", ConnectorCustodyHookOnly)
	now := time.Now().UTC()
	digest := correlationDigest("shared-session-turn-late-earliest")
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
	group, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: now.Add(10 * time.Second), mutate: identify})
	for index := 1; index <= 5; index++ {
		seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
			receivedAt: now.Add(time.Duration(10+index) * time.Second), logical: group.LogicalEventID, mutate: identify,
		})
	}
	earliest, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		receivedAt: now, logical: group.LogicalEventID, mutate: identify,
	})
	result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		Identifiers:         []CorrelationMatchIdentifier{{Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Ambiguous || result.MatchedSemanticEventID != earliest.SemanticEventID {
		t.Fatalf("result=%+v, want the earliest event %s", result, earliest.SemanticEventID)
	}
}

// A long session whose events share an identifier but are each their own
// occurrence (one logical group per tool call, the hook flood shape) is
// ambiguous, and the match reads at most two rows to say so: its time does not
// grow with the number of matching events.
func TestMatchOccurrenceSharedIdentifierOfALongSessionStaysFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("seeds a long session")
	}
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "cursor", ConnectorCustodyHookOnly)
	now := time.Now().UTC()
	digest := correlationDigest("long-session")
	identify := func(tx *CorrelationTx, event CorrelationEvent) {
		if _, err := tx.PutIdentifier(t.Context(), CorrelationIdentifier{
			SemanticEventID: event.SemanticEventID, ConnectorInstanceID: instance.ConnectorInstanceID,
			Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest,
			NormalizedValue: "long-session", SourceField: "generation_id", Origin: CorrelationOriginReported,
			ProfileVersion: instance.ProfileVersion, ObservedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Windows advances the monotonic clock once per timer tick (about 0.5 to
	// 2 ms), so one call timed alone reads 0 or a whole tick: a flat match
	// once read 0s with 50 events and 2.02ms with 3,000. Time batches of at
	// least 15 calls and 25ms instead, and compare the best mean call.
	match := func() time.Duration {
		t.Helper()
		const (
			batches   = 3
			minCalls  = 15
			minLength = 25 * time.Millisecond
		)
		var best time.Duration
		for range batches {
			calls := 0
			var elapsed time.Duration
			start := time.Now()
			for calls < minCalls || elapsed < minLength {
				result, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
					ConnectorInstanceID: instance.ConnectorInstanceID,
					Identifiers:         []CorrelationMatchIdentifier{{Namespace: "cursor", Kind: CorrelationIdentifierTurn, ValueDigest: digest}},
				})
				calls++
				elapsed = time.Since(start)
				if err != nil {
					t.Fatal(err)
				}
				if !result.Ambiguous {
					t.Fatalf("result=%+v, want ambiguous", result)
				}
			}
			if perCall := elapsed / time.Duration(calls); best == 0 || perCall < best {
				best = perCall
			}
		}
		return best
	}
	seed := func(from, to int) {
		for index := from; index < to; index++ {
			seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
				receivedAt: now.Add(time.Duration(index) * time.Millisecond), mutate: identify,
			})
		}
	}
	seed(0, 50)
	if _, err := repo.store.RefreshPlannerStatistics(t.Context()); err != nil {
		t.Fatal(err)
	}
	short := match()
	seed(50, 3000)
	if _, err := repo.store.RefreshPlannerStatistics(t.Context()); err != nil {
		t.Fatal(err)
	}
	long := match()
	// The old earliest-first read sorted every match: 60 times the matches
	// took about 40 times as long. Allow wide noise around flat.
	if long > 8*short+200*time.Microsecond {
		t.Fatalf("a match with 3,000 matching events took %v a call, with 50 took %v; want flat", long, short)
	}
}
