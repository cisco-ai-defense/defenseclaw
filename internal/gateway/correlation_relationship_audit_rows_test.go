// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// relationshipContextCapture records whether each emission writes a local row.
type relationshipContextCapture struct {
	skipLocal []bool
	batches   int
}

func (capture *relationshipContextCapture) Emit(
	ctx context.Context, _ router.Metadata, _ observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	capture.skipLocal = append(capture.skipLocal, observability.SkipLocalWrite(ctx))
	return pipeline.LocalLogOutcome{}, nil
}

func (capture *relationshipContextCapture) EmitAtomicBatch(
	_ context.Context, items []observabilityruntime.LogBatchItem,
) ([]pipeline.LocalLogOutcome, error) {
	capture.batches++
	return make([]pipeline.LocalLogOutcome, len(items)), nil
}

// #1384: a standalone gateway exports a relationship change without writing
// it to audit_events again; Secure Client keeps its rows (#1092).
func TestStandaloneCorrelationRelationshipsWriteNoAuditRow(t *testing.T) {
	prior := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(false)
	t.Cleanup(func() { SetManagedEnterpriseActive(prior) })
	semantic := audit.SemanticEventID("019b2b7b-9f8c-7ea0-8757-3e064bcd9991")
	relationship := func(id, session string) audit.CorrelationRelationship {
		return audit.CorrelationRelationship{RelationshipID: id, FromKind: audit.CorrelationNodeSemanticEvent,
			FromID: string(semantic), ToKind: audit.CorrelationNodeSession, ToID: session,
			Type: audit.CorrelationBelongsTo, Method: audit.CorrelationMethodReported, Confidence: 95,
			RuleID: "session-membership", RuleVersion: "codex-correlation-v1",
			EvidenceCount: 1, Status: audit.CorrelationRelationshipActive}
	}
	capture := &relationshipContextCapture{}
	if err := emitCorrelationRelationshipsV8WithEmitter(t.Context(), capture,
		observability.SourceConnector, "codex", semantic, audit.LogicalEventID(semantic),
		audit.ConnectorInstanceID("019b2b7b-9f8c-7ea0-8757-3e064bcd9993"),
		[]audit.CorrelationRelationship{relationship("rel-one", "session-1"), relationship("rel-two", "session-2")},
	); err != nil {
		t.Fatal(err)
	}
	if capture.batches != 0 || len(capture.skipLocal) != 2 || !capture.skipLocal[0] || !capture.skipLocal[1] {
		t.Fatalf("emission = batches %d, singles %v; want two singles that skip the local write",
			capture.batches, capture.skipLocal)
	}
}

// flakyRemote fails its first deliveries (a destination outage), then
// keeps every record it gets.
type flakyRemote struct {
	mu       sync.Mutex
	failures int
	attempts int
	records  []string
}

func (*flakyRemote) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (r *flakyRemote) Deliver(_ context.Context, batch delivery.Batch) delivery.DeliveryResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts++
	if r.attempts <= r.failures {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
	}
	for _, item := range batch.Items() {
		r.records = append(r.records, string(item.Bytes()))
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (r *flakyRemote) relationships(session string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	count := 0
	for _, record := range r.records {
		if strings.Contains(record, observability.TelemetryEventCorrelationRelationshipChanged) &&
			strings.Contains(record, session) {
			count++
		}
	}
	return count
}

// #1384: the relationship family of a hook call reaches the destinations
// after an outage, as before, while audit_events and correlation_observations
// keep no second copy of it; correlation_relationships still holds it.
func TestHookRelationshipChangesExportAfterOutageWithoutAuditRows(t *testing.T) {
	remote := &flakyRemote{failures: 2}
	f := newManagedHookAuditFixtureExportingTo(t, nil, remote)
	const session = "relationships-outage"
	for range 3 {
		ackedHookCall(t, f.api, session, &recordFullDuplexStatusWriter{ResponseRecorder: httptest.NewRecorder()})
	}
	database := openCorrelationDB(t, f.path)
	var auditRows, observationRows, relationships int
	if err := database.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_name=?`,
		observability.TelemetryEventCorrelationRelationshipChanged).Scan(&auditRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_observations WHERE event_name=?`,
		observability.TelemetryEventCorrelationRelationshipChanged).Scan(&observationRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_relationships`).Scan(&relationships); err != nil {
		t.Fatal(err)
	}
	if auditRows != 0 || observationRows != 0 || relationships == 0 {
		t.Fatalf("audit rows %d, observations %d, relationships %d; want 0, 0 and the relationships",
			auditRows, observationRows, relationships)
	}
	deadline := time.Now().Add(20 * time.Second)
	for remote.relationships(session) == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := remote.relationships(session); got == 0 {
		remote.mu.Lock()
		attempts := remote.attempts
		remote.mu.Unlock()
		t.Fatalf("destination got no relationship record of %s after the outage (%d attempts)", session, attempts)
	}
}
