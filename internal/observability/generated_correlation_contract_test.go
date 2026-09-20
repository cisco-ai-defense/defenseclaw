// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import "testing"

func TestGeneratedCorrelationRelationshipChangeIsLogsOnlyAndExplainable(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	record, err := builder.BuildLogCorrelationRelationshipChanged(LogCorrelationRelationshipChangedInput{
		Envelope:                                           testFamilyEnvelope(),
		Outcome:                                            OutcomeApplied,
		DefenseClawSemanticEventID:                         Present("semantic-1"),
		DefenseClawLogicalEventID:                          Present("logical-1"),
		DefenseClawConnectorInstanceID:                     Present("connector-instance-1"),
		DefenseClawCorrelationRelationshipID:               "relationship-1",
		DefenseClawCorrelationRelationshipType:             "same_as",
		DefenseClawCorrelationRelationshipSourceKind:       "semantic_event",
		DefenseClawCorrelationRelationshipSourceID:         "native-event-1",
		DefenseClawCorrelationRelationshipTargetKind:       "semantic_event",
		DefenseClawCorrelationRelationshipTargetID:         "hook-event-1",
		DefenseClawCorrelationRelationshipMethod:           "trace_exact",
		DefenseClawCorrelationRelationshipStatus:           "active",
		DefenseClawCorrelationRelationshipRuleID:           "codex-native",
		DefenseClawCorrelationRelationshipRuleVersion:      "codex-native-v1",
		DefenseClawCorrelationRelationshipConfidence:       1,
		DefenseClawCorrelationRelationshipEvidenceCount:    2,
		DefenseClawCorrelationRelationshipEvidenceRecordID: Present("record-1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Signal() != SignalLogs || record.Bucket() != BucketTelemetryIngest ||
		record.EventName() != EventName(TelemetryEventCorrelationRelationshipChanged) {
		t.Fatalf("relationship identity = %#v", record.Identity())
	}
	body := generatedContractBody(t, record)
	for key, want := range map[string]any{
		"defenseclaw.semantic_event.id":                           "semantic-1",
		"defenseclaw.logical_event.id":                            "logical-1",
		"defenseclaw.connector.instance.id":                       "connector-instance-1",
		"defenseclaw.correlation.relationship.id":                 "relationship-1",
		"defenseclaw.correlation.relationship.type":               "same_as",
		"defenseclaw.correlation.relationship.source_kind":        "semantic_event",
		"defenseclaw.correlation.relationship.target_kind":        "semantic_event",
		"defenseclaw.correlation.relationship.method":             "trace_exact",
		"defenseclaw.correlation.relationship.status":             "active",
		"defenseclaw.correlation.relationship.rule_id":            "codex-native",
		"defenseclaw.correlation.relationship.rule_version":       "codex-native-v1",
		"defenseclaw.correlation.relationship.evidence_record_id": "record-1",
	} {
		if got := body[key]; got != want {
			t.Errorf("%s=%v, want %v", key, got, want)
		}
	}
}

func TestGeneratedCorrelationRelationshipRejectsUnknownVocabulary(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	input := LogCorrelationRelationshipChangedInput{
		Envelope: testFamilyEnvelope(), Outcome: OutcomeApplied,
		DefenseClawCorrelationRelationshipID:            "relationship-1",
		DefenseClawCorrelationRelationshipType:          "same_as",
		DefenseClawCorrelationRelationshipSourceKind:    "semantic_event",
		DefenseClawCorrelationRelationshipSourceID:      "source-1",
		DefenseClawCorrelationRelationshipTargetKind:    "semantic_event",
		DefenseClawCorrelationRelationshipTargetID:      "target-1",
		DefenseClawCorrelationRelationshipMethod:        "reported",
		DefenseClawCorrelationRelationshipStatus:        "active",
		DefenseClawCorrelationRelationshipRuleID:        "reported-exact-id",
		DefenseClawCorrelationRelationshipRuleVersion:   "rule-v1",
		DefenseClawCorrelationRelationshipConfidence:    1,
		DefenseClawCorrelationRelationshipEvidenceCount: 1,
	}
	input.DefenseClawCorrelationRelationshipMethod = "timestamp_guess"
	if _, err := builder.BuildLogCorrelationRelationshipChanged(input); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("unknown method error = %v", err)
	}
}

func TestOccurrenceCorrelationNeverEntersMetricFieldsOrLabels(t *testing.T) {
	for familyID, contract := range generatedFamilyBaseContracts {
		if contract.identity.Signal != SignalMetrics {
			continue
		}
		for _, field := range contract.fields {
			switch field.key {
			case "defenseclaw.semantic_event.id", "defenseclaw.logical_event.id",
				"defenseclaw.connector.instance.id", "defenseclaw.turn.id",
				"defenseclaw.request.id", "defenseclaw.model.request.id",
				"defenseclaw.tool.invocation.id", "gen_ai.tool.call.id":
				t.Fatalf("metric family %s exposes high-cardinality occurrence field %s", familyID, field.key)
			}
		}
	}
}
