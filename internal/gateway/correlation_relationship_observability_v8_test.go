// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

type correlationRelationshipRecordCapture struct {
	records []observability.Record
}

func (capture *correlationRelationshipRecordCapture) Emit(
	_ context.Context,
	_ router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	capture.records = append(capture.records, record)
	return pipeline.LocalLogOutcome{}, nil
}

func TestCommittedCorrelationRelationshipBuildsExplainableExportLog(t *testing.T) {
	capture := &correlationRelationshipRecordCapture{}
	semantic := audit.SemanticEventID("019b2b7b-9f8c-7ea0-8757-3e064bcd9991")
	logical := audit.LogicalEventID("019b2b7b-9f8c-7ea0-8757-3e064bcd9992")
	instance := audit.ConnectorInstanceID("019b2b7b-9f8c-7ea0-8757-3e064bcd9993")
	err := emitCorrelationRelationshipsV8WithEmitter(
		t.Context(), capture, observability.SourceConnector, "codex", semantic, logical, instance,
		[]audit.CorrelationRelationship{{
			RelationshipID: "rel-0123456789abcdef", FromKind: audit.CorrelationNodeSemanticEvent,
			FromID: string(semantic), ToKind: audit.CorrelationNodeSemanticEvent,
			ToID: "019b2b7b-9f8c-7ea0-8757-3e064bcd9994", Type: audit.CorrelationCorrelatesWith,
			Method: audit.CorrelationMethodInferred, Confidence: 50,
			RuleID: "bounded-similarity", RuleVersion: "codex-correlation-v1",
			EvidenceCount: 3,
			Status:        audit.CorrelationRelationshipCandidate, CreatedAt: time.Now().UTC(),
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(capture.records) != 1 {
		t.Fatalf("records=%d want 1", len(capture.records))
	}
	record := capture.records[0]
	if record.Bucket() != observability.BucketTelemetryIngest ||
		record.EventName() != observability.EventName(observability.TelemetryEventCorrelationRelationshipChanged) {
		t.Fatalf("identity=%+v", record.Identity())
	}
	correlation := record.Correlation()
	if correlation.SemanticEventID != string(semantic) || correlation.LogicalEventID != string(logical) ||
		correlation.ConnectorInstanceID != string(instance) {
		t.Fatalf("correlation=%+v", correlation)
	}
	body, ok := record.Body()
	if !ok {
		t.Fatal("relationship log has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"defenseclaw.correlation.relationship.id":           "rel-0123456789abcdef",
		"defenseclaw.correlation.relationship.type":         "correlates_with",
		"defenseclaw.correlation.relationship.source_kind":  "semantic_event",
		"defenseclaw.correlation.relationship.target_kind":  "semantic_event",
		"defenseclaw.correlation.relationship.method":       "inferred",
		"defenseclaw.correlation.relationship.status":       "unresolved",
		"defenseclaw.correlation.relationship.rule_id":      "bounded-similarity",
		"defenseclaw.correlation.relationship.rule_version": "codex-correlation-v1",
	} {
		if got := object[key]; got != want {
			t.Errorf("%s=%v want %v", key, got, want)
		}
	}
	for key, want := range map[string]string{
		"defenseclaw.correlation.relationship.confidence":     "0.5",
		"defenseclaw.correlation.relationship.evidence_count": "3",
	} {
		got, ok := object[key].(json.Number)
		if !ok || got.String() != want {
			t.Errorf("%s=%v want numeric %s", key, object[key], want)
		}
	}
}
