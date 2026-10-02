// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// cancelWhileSigningSigner cancels the caller's context mid-write, as an OTLP
// exporter does when its request times out behind a slow write.
type cancelWhileSigningSigner struct {
	testProjectionSigner
	cancel context.CancelFunc
}

func (signer *cancelWhileSigningSigner) HMACSHA256(ctx context.Context, message []byte) ([]byte, error) {
	signer.cancel()
	return signer.testProjectionSigner.HMACSHA256(ctx, message)
}

// GAP-1790: a write whose caller gave up reports class deadline (which start
// waits out), not class other (which failed start on a large audit.db).
func TestEventHistoryWriteWhoseCallerGaveUpIsDeadlineClass(t *testing.T) {
	store := newV8HistoryStore(t)
	health := &testEventHistoryHealthReporter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer := &cancelWhileSigningSigner{
		testProjectionSigner: testProjectionSigner{keyID: "integrity-key-v1"},
		cancel:               cancel,
	}
	writer, err := NewEventHistoryWriter(store, signer, health,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-caller-gave-up", "private")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.AppendContext(ctx, record, projection); err == nil {
		t.Fatal("a write whose caller gave up succeeded")
	}
	if len(health.transitions) == 0 {
		t.Fatal("the failed write reported no health transition")
	}
	for _, transition := range health.transitions {
		if transition.Code == EventHistoryHealthWriteFailed && transition.SQLiteClass != EventHistorySQLiteDeadline {
			t.Fatalf("health class = %s, want %s", transition.SQLiteClass, EventHistorySQLiteDeadline)
		}
	}
}
