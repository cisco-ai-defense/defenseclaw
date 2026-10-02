// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// cancellingProjectionSigner cancels the caller's context while signing, the
// way an OTLP exporter gives up on a request stalled behind a slow write.
type cancellingProjectionSigner struct {
	testProjectionSigner
	cancel context.CancelFunc
}

func (signer *cancellingProjectionSigner) HMACSHA256(ctx context.Context, message []byte) ([]byte, error) {
	signer.cancel()
	return signer.testProjectionSigner.HMACSHA256(ctx, message)
}

// GAP-1790: a write whose caller gave up is a timed-out write (class
// deadline, which start waits out), not class other (which failed start).
func TestEventHistoryWriteCancelledByCallerIsDeadlineClass(t *testing.T) {
	store := newV8HistoryStore(t)
	health := &testEventHistoryHealthReporter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signer := &cancellingProjectionSigner{
		testProjectionSigner: testProjectionSigner{keyID: "integrity-key-v1"},
		cancel:               cancel,
	}
	writer, err := NewEventHistoryWriter(store, signer, health,
		testLocalProfileResolver{profile: observabilityredaction.ProfileNone})
	if err != nil {
		t.Fatal(err)
	}
	record := newV8HistoryRecord(t, "history-caller-cancelled", "private")
	projection := projectV8HistoryRecord(t, record, observabilityredaction.ProfileNone)
	if err := writer.AppendContext(ctx, record, projection); err == nil {
		t.Fatal("write with a cancelled caller context succeeded")
	}
	if len(health.transitions) == 0 {
		t.Fatal("the failed write reported no health transition")
	}
	last := health.transitions[len(health.transitions)-1]
	if last.Code != EventHistoryHealthWriteFailed || last.SQLiteClass != EventHistorySQLiteDeadline {
		t.Fatalf("health = %s/%s, want %s/%s", last.Code, last.SQLiteClass,
			EventHistoryHealthWriteFailed, EventHistorySQLiteDeadline)
	}
}
