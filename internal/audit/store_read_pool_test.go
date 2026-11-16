// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"
	"time"
)

func TestR109PerfWALMatchReadsWhileWriterConnectionIsBusy(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{})
	writer, err := store.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	matched, err := repo.MatchOccurrence(ctx, CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		SemanticEventID:     event.SemanticEventID,
	})
	if err != nil {
		t.Fatalf("correlation read waited for the write connection: %v", err)
	}
	if matched.Rank != CorrelationMatchSemanticEvent || matched.MatchedSemanticEventID != event.SemanticEventID {
		t.Fatalf("correlation match = %+v", matched)
	}
}

func TestR109PerfWALUnmatchedCorrelationRemainsAllowed(t *testing.T) {
	_, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	unknown, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	matched, err := repo.MatchOccurrence(t.Context(), CorrelationMatchInput{
		ConnectorInstanceID: instance.ConnectorInstanceID,
		SemanticEventID:     unknown,
	})
	if err != nil || matched.Rank != CorrelationMatchNone {
		t.Fatalf("unmatched correlation = %+v, %v", matched, err)
	}
}
