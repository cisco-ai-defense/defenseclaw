// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validRecordInput() RecordInput {
	severity := SeverityInfo
	observedAt := time.Date(2026, 7, 3, 5, 4, 3, 2, time.FixedZone("offset", 3600))
	return RecordInput{
		Timestamp:  time.Date(2026, 7, 3, 4, 3, 2, 1, time.FixedZone("offset", -5*3600)),
		ObservedAt: &observedAt,
		RecordID:   "occurrence-1",
		Identity: EventIdentity{
			Bucket: BucketDiagnostic,
			Signal: SignalLogs,
			Name:   EventName("diagnostic.message"),
		},
		Severity:  &severity,
		LogLevel:  LogLevelInfo,
		Source:    SourceGateway,
		Connector: "codex",
		Action:    "diagnostic.emit",
		Phase:     "completed",
		Outcome:   OutcomeCompleted,
		Correlation: Correlation{
			SemanticEventID:     "semantic-event-1",
			LogicalEventID:      "logical-event-1",
			ConnectorInstanceID: "connector-instance-1",
			RunID:               "run-1",
			RequestID:           "request-1",
			SessionID:           "session-1",
			TurnID:              "turn-1",
			TraceID:             "trace-1",
			SpanID:              "span-1",
			AgentID:             "agent-1",
			AgentInstanceID:     "agent-instance-1",
			PolicyID:            "policy-1",
			PolicyVersion:       "policy-version-1",
			EvaluationID:        "evaluation-1",
			ScanID:              "scan-1",
			FindingOccurrenceID: "finding-1",
			EnforcementActionID: "enforcement-1",
			ModelRequestID:      "model-request-1",
			ModelResponseID:     "model-response-1",
			ToolInvocationID:    "tool-1",
			DestinationID:       "destination-1",
			ConnectorID:         "connector-1",
			SidecarInstanceID:   "sidecar-1",
		},
		Provenance: Provenance{
			Producer:              "gateway.audit",
			BinaryVersion:         "v1.2.3+build",
			RegistrySchemaVersion: 7,
			ConfigGeneration:      3,
			BuildCommit:           "abcdef0123456789",
			ConfigDigest:          "0123456789abcdef",
		},
		Body: map[string]any{
			"message": "hello",
			"count":   2,
		},
		FieldClasses: map[string]FieldClass{
			"/message": FieldClassContent,
			"/count":   FieldClassMetadata,
		},
	}
}

func validMetricRecordInput() RecordInput {
	input := validRecordInput()
	input.Identity = EventIdentity{
		Bucket: BucketComplianceActivity,
		Signal: SignalMetrics,
		Name:   "defenseclaw.activity.total",
	}
	input.Severity = nil
	input.LogLevel = ""
	input.Outcome = ""
	input.Body = nil
	input.InstrumentData = map[string]any{
		"value": 2,
		"attributes": map[string]any{
			"kind": "diagnostic",
		},
	}
	input.FieldClasses = map[string]FieldClass{
		"/value":           FieldClassMetadata,
		"/attributes/kind": FieldClassMetadata,
	}
	return input
}

type testSchemaDerivedLogFamilyContract struct {
	identity  EventIdentity
	mandatory bool
}

func (contract *testSchemaDerivedLogFamilyContract) schemaDerivedLogIdentity() EventIdentity {
	return contract.identity
}

func (contract *testSchemaDerivedLogFamilyContract) schemaDerivedLogMandatory() bool {
	return contract.mandatory
}

func TestRecordEnvelopeAndDeterministicJSON(t *testing.T) {
	record, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	if record.SchemaVersion() != 1 || record.BucketCatalogVersion() != 1 {
		t.Fatalf("versions = %d/%d", record.SchemaVersion(), record.BucketCatalogVersion())
	}
	if record.Signal() != SignalLogs || record.Bucket() != BucketDiagnostic ||
		record.EventName() != "diagnostic.message" {
		t.Fatalf("identity = %#v", record.Identity())
	}
	if record.Timestamp().Location() != time.UTC {
		t.Fatalf("timestamp was not normalized to UTC: %v", record.Timestamp())
	}
	observedAt, present := record.ObservedAt()
	if !present || observedAt.Location() != time.UTC {
		t.Fatalf("observed_at = %v/%t", observedAt, present)
	}

	first, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("record encoding is not deterministic")
	}
	var wire map[string]any
	if err := json.Unmarshal(first, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["schema_version"] != float64(1) || wire["bucket_catalog_version"] != float64(1) {
		t.Fatalf("wire versions = %#v", wire)
	}
	if mandatory, exists := wire["mandatory"]; !exists || mandatory != false {
		t.Fatalf("false mandatory must remain explicit: %#v", wire)
	}
	if _, exists := wire["body"]; !exists {
		t.Fatalf("log body missing: %#v", wire)
	}
	if _, exists := wire["instrument_data"]; exists {
		t.Fatalf("log contains metric payload arm: %#v", wire)
	}
	correlation := wire["correlation"].(map[string]any)
	if len(correlation) != 23 {
		t.Fatalf("correlation fields = %d, want 23: %#v", len(correlation), correlation)
	}
	if !strings.Contains(string(first), `"field_classes":{"/count":"metadata","/message":"content"}`) {
		t.Fatalf("field classes not deterministic: %s", first)
	}
}

func TestRecordWithCorrelationDefaultsFillsOnlyMissingFields(t *testing.T) {
	input := validRecordInput()
	input.Correlation.SemanticEventID = ""
	input.Correlation.LogicalEventID = ""
	input.Correlation.ConnectorInstanceID = ""
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}

	defaults := Correlation{
		SemanticEventID:     "semantic-default",
		LogicalEventID:      "logical-default",
		ConnectorInstanceID: "connector-instance-default",
		RequestID:           input.Correlation.RequestID,
	}
	merged, err := record.WithCorrelationDefaults(defaults)
	if err != nil {
		t.Fatal(err)
	}
	got := merged.Correlation()
	if got.SemanticEventID != defaults.SemanticEventID ||
		got.LogicalEventID != defaults.LogicalEventID ||
		got.ConnectorInstanceID != defaults.ConnectorInstanceID ||
		got.RequestID != input.Correlation.RequestID {
		t.Fatalf("merged correlation = %#v", got)
	}
	original := record.Correlation()
	if original.SemanticEventID != "" || original.LogicalEventID != "" || original.ConnectorInstanceID != "" {
		t.Fatalf("WithCorrelationDefaults mutated receiver: %#v", original)
	}
	defaults.SemanticEventID = "mutated-after-call"
	if merged.Correlation().SemanticEventID != "semantic-default" {
		t.Fatal("merged record retained caller-owned default storage")
	}
}

func TestRecordWithCorrelationDefaultsKeepsRecordOwnedBusinessIdentity(t *testing.T) {
	record, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	merged, err := record.WithCorrelationDefaults(Correlation{
		TurnID:           "different-secret-turn",
		ToolInvocationID: "different-secret-tool",
	})
	if err != nil {
		t.Fatal(err)
	}
	correlation := merged.Correlation()
	if correlation.TurnID != "turn-1" || correlation.ToolInvocationID != "tool-1" {
		t.Fatalf("record-owned business identity was replaced: %#v", correlation)
	}
}

func TestRecordWithCorrelationDefaultsRejectsOccurrenceConflictWithoutLeakingValues(t *testing.T) {
	record, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	_, err = record.WithCorrelationDefaults(Correlation{SemanticEventID: "different-secret-event"})
	if err == nil {
		t.Fatal("expected occurrence identity conflict")
	}
	if strings.Contains(err.Error(), "different-secret-event") || strings.Contains(err.Error(), "semantic-event-1") {
		t.Fatalf("conflict error leaked correlation values: %v", err)
	}
	if !strings.Contains(err.Error(), "semantic_event_id") {
		t.Fatalf("conflict error did not identify the field: %v", err)
	}
}

func TestRecordWithCorrelationDefaultsRejectsInvalidDefault(t *testing.T) {
	record, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	_, err = record.WithCorrelationDefaults(Correlation{SemanticEventID: strings.Repeat("x", MaxCorrelationIDBytes+1)})
	if err == nil || !strings.Contains(err.Error(), "invalid correlation defaults") {
		t.Fatalf("invalid default error = %v", err)
	}
}

func TestRecordFullEnvelopeLexicalGolden(t *testing.T) {
	input := RecordInput{
		Timestamp: time.Date(2026, 7, 3, 1, 2, 3, 4, time.UTC),
		RecordID:  "occurrence",
		Identity: EventIdentity{
			Bucket: BucketDiagnostic,
			Signal: SignalLogs,
			Name:   "diagnostic.message",
		},
		Source: SourceGateway,
		Provenance: Provenance{
			Producer:              "gateway",
			BinaryVersion:         "v8",
			RegistrySchemaVersion: 1,
			ConfigGeneration:      0,
		},
		Body:         map[string]any{"message": "<>&\u2028\u2029"},
		FieldClasses: map[string]FieldClass{"/message": FieldClassContent},
	}
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"body":{"message":"<>&\u2028\u2029"},"bucket":"diagnostic","bucket_catalog_version":1,"correlation":{},"event_name":"diagnostic.message","field_classes":{"/message":"content"},"mandatory":false,"provenance":{"binary_version":"v8","config_generation":0,"producer":"gateway","registry_schema_version":1},"record_id":"occurrence","schema_version":1,"signal":"logs","source":"gateway","timestamp":"2026-07-03T01:02:03.000000004Z"}`
	want = strings.ReplaceAll(want, `\u2028`, "\u2028")
	want = strings.ReplaceAll(want, `\u2029`, "\u2029")
	if got := string(encoded); got != want {
		t.Fatalf("lexical record mismatch\n got: %s\nwant: %s", got, want)
	}
	encoded[0] = '['
	again, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != want {
		t.Fatal("record Bytes exposed internal state")
	}
	if record.IsFloorOnly() {
		t.Fatal("ordinary record marked floor-only")
	}
}

func TestRecordLiteralLineSeparatorEscapesRoundTripInEnvelopeStrings(t *testing.T) {
	inputs := []RecordInput{
		func() RecordInput {
			input := validRecordInput()
			input.Correlation.RequestID = `\u2028\u2029`
			return input
		}(),
		func() RecordInput {
			input := validRecordInput()
			input.Identity = EventIdentity{
				Bucket: BucketAgentLifecycle,
				Signal: SignalTraces,
				Name:   "span.workflow.run",
			}
			input.SpanName = `workflow \u2028 \u2029`
			return input
		}(),
	}
	for _, input := range inputs {
		record, err := NewRecord(input)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := record.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(encoded) {
			t.Fatalf("record encoding is invalid JSON: %q", encoded)
		}
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		if input.Identity.Signal == SignalLogs {
			correlation := wire["correlation"].(map[string]any)
			if got := correlation["request_id"]; got != input.Correlation.RequestID {
				t.Fatalf("request_id round trip = %q", got)
			}
		} else if got := wire["span_name"]; got != input.SpanName {
			t.Fatalf("span_name round trip = %q", got)
		}
	}
}

func TestRecordPayloadArmsBySignal(t *testing.T) {
	tests := []struct {
		name               string
		mutate             func(*RecordInput)
		wantBody           bool
		wantInstrumentData bool
	}{
		{
			name:     "log",
			mutate:   func(*RecordInput) {},
			wantBody: true,
		},
		{
			name: "trace",
			mutate: func(input *RecordInput) {
				input.Identity = EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalTraces, Name: "span.workflow.run"}
				input.SpanName = "workflow nightly"
			},
			wantBody: true,
		},
		{
			name: "metric",
			mutate: func(input *RecordInput) {
				input.Identity = EventIdentity{Bucket: BucketComplianceActivity, Signal: SignalMetrics, Name: "defenseclaw.activity.total"}
				input.InstrumentData = input.Body
				input.Body = nil
				input.Severity = nil
				input.LogLevel = ""
				input.Outcome = ""
			},
			wantInstrumentData: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRecordInput()
			test.mutate(&input)
			record, err := NewRecord(input)
			if err != nil {
				t.Fatal(err)
			}
			_, hasBody := record.Body()
			_, hasInstrumentData := record.InstrumentData()
			if hasBody != test.wantBody || hasInstrumentData != test.wantInstrumentData {
				t.Fatalf("payload arms body=%t metric=%t", hasBody, hasInstrumentData)
			}
			encoded, err := record.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if test.name != "log" && strings.Contains(string(encoded), `"mandatory"`) {
				t.Fatalf("non-log mandatory serialized: %s", encoded)
			}
		})
	}
}

func TestRecordRejectsInvalidPayloadArmCombinations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecordInput)
	}{
		{name: "log missing body", mutate: func(input *RecordInput) { input.Body = nil }},
		{name: "log has both arms", mutate: func(input *RecordInput) { input.InstrumentData = map[string]any{} }},
		{name: "log span name", mutate: func(input *RecordInput) { input.SpanName = "wrong" }},
		{name: "metric missing instrument", mutate: func(input *RecordInput) {
			input.Identity = EventIdentity{Bucket: BucketComplianceActivity, Signal: SignalMetrics, Name: "defenseclaw.activity.total"}
			input.Body = nil
		}},
		{name: "trace missing span name", mutate: func(input *RecordInput) {
			input.Identity = EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalTraces, Name: "span.workflow.run"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRecordInput()
			test.mutate(&input)
			if _, err := NewRecord(input); err == nil {
				t.Fatal("invalid payload arms accepted")
			}
		})
	}
}

func TestRecordInputHasNoCallerControlledMandatorySurface(t *testing.T) {
	typeOfInput := reflect.TypeOf(RecordInput{})
	if _, exists := typeOfInput.FieldByName("Mandatory"); exists {
		t.Fatal("generic record input exposes caller-controlled mandatory state")
	}

	input := validMetricRecordInput()
	if _, err := newRecord(input, false, true); err == nil ||
		!strings.Contains(err.Error(), "mandatory is defined only for log records") {
		t.Fatalf("mandatory metric error = %v", err)
	}
}

func TestMetricRecordRejectsLogOnlyEnvelopeState(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*RecordInput)
		message string
	}{
		{
			name: "severity",
			mutate: func(input *RecordInput) {
				severity := SeverityHigh
				input.Severity = &severity
			},
			message: "metric record must not have severity",
		},
		{
			name:    "log level",
			mutate:  func(input *RecordInput) { input.LogLevel = LogLevelWarn },
			message: "metric record must not have a log level",
		},
		{
			name:    "outcome",
			mutate:  func(input *RecordInput) { input.Outcome = OutcomeCompleted },
			message: "metric record must not have an outcome",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validMetricRecordInput()
			test.mutate(&input)
			if _, err := NewRecord(input); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("metric forbidden-field error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestMetricRecordAllowsConnectorActionAndPhase(t *testing.T) {
	input := validMetricRecordInput()
	input.Connector = "codex"
	input.Action = "diagnostic.emit"
	input.Phase = "completed"
	record, err := NewRecord(input)
	if err != nil {
		t.Fatalf("valid metric metadata rejected: %v", err)
	}
	if record.Connector() != input.Connector || record.Action() != input.Action || record.Phase() != input.Phase {
		t.Fatalf("metric metadata = %q/%q/%q", record.Connector(), record.Action(), record.Phase())
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"connector": input.Connector,
		"action":    input.Action,
		"phase":     input.Phase,
	} {
		if got := wire[key]; got != want {
			t.Fatalf("wire %s = %#v, want %q", key, got, want)
		}
	}
	for _, forbidden := range []string{"severity", "log_level", "outcome", "mandatory", "body"} {
		if _, exists := wire[forbidden]; exists {
			t.Fatalf("metric wire contains forbidden %s: %#v", forbidden, wire)
		}
	}
	if got := wire["field_classes"]; !reflect.DeepEqual(got, map[string]any{
		"/attributes/kind": "metadata",
		"/value":           "metadata",
	}) {
		t.Fatalf("metric field classes = %#v", got)
	}
}

func TestRecordSnapshotsEveryMutableInputAndOutput(t *testing.T) {
	input := validRecordInput()
	body := input.Body.(map[string]any)
	classes := input.FieldClasses
	observedPointer := input.ObservedAt
	record, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	body["message"] = "mutated"
	classes["/message"] = FieldClassCredential
	*observedPointer = time.Time{}

	storedBody, _ := record.Body()
	object, _ := storedBody.Object()
	if object["message"] != "hello" {
		t.Fatalf("body input aliased: %#v", object)
	}
	returnedClasses := record.FieldClasses()
	if returnedClasses["/message"] != FieldClassContent {
		t.Fatalf("field-class input aliased: %#v", returnedClasses)
	}
	returnedClasses["/message"] = FieldClassError
	if record.FieldClasses()["/message"] != FieldClassContent {
		t.Fatal("field-class output aliased")
	}
	observed, present := record.ObservedAt()
	if !present || observed.IsZero() {
		t.Fatalf("observed_at input aliased: %v", observed)
	}

	clone := record.Clone()
	cloneClasses := clone.FieldClasses()
	cloneClasses["/message"] = FieldClassPath
	if record.FieldClasses()["/message"] != FieldClassContent {
		t.Fatal("clone aliased original")
	}
}

func TestRecordFieldClassPointerResolutionAndCompleteness(t *testing.T) {
	input := validRecordInput()
	input.Body = map[string]any{
		"a/b":   map[string]any{"~x": []any{nil, "value"}},
		"empty": map[string]any{},
	}
	input.FieldClasses = map[string]FieldClass{
		"/a~1b/~0x/0": FieldClassContent,
		"/a~1b/~0x/1": FieldClassContent,
		"/empty":      FieldClassMetadata,
	}
	if _, err := NewRecord(input); err != nil {
		t.Fatalf("escaped and array pointers rejected: %v", err)
	}

	input.FieldClasses = map[string]FieldClass{"/a~1b/~0x": FieldClassContent, "/empty": FieldClassMetadata}
	if _, err := NewRecord(input); err == nil || !strings.Contains(err.Error(), "cover every payload leaf") {
		t.Fatalf("parent pointer incorrectly covered descendants: %v", err)
	}

	input.FieldClasses = map[string]FieldClass{"/a~1b/~0x/0": FieldClassContent, "/empty": FieldClassMetadata}
	if _, err := NewRecord(input); err == nil || !strings.Contains(err.Error(), "cover every payload leaf") {
		t.Fatalf("missing leaf error = %v", err)
	}

	input.FieldClasses = map[string]FieldClass{"/missing": FieldClassContent, "": FieldClassContent}
	if _, err := NewRecord(input); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Fatalf("unresolved pointer error = %v", err)
	}

	input.FieldClasses = map[string]FieldClass{"": FieldClassContent}
	if _, err := NewRecord(input); err == nil || !strings.Contains(err.Error(), "cover every payload leaf") {
		t.Fatalf("root pointer incorrectly covered descendants: %v", err)
	}

	input.Body = map[string]any{}
	if _, err := NewRecord(input); err != nil {
		t.Fatalf("RFC 6901 root pointer rejected for empty-root leaf: %v", err)
	}

	longKey := strings.Repeat("k", 2048)
	input.Body = map[string]any{longKey: true}
	input.FieldClasses = map[string]FieldClass{"/" + longKey: FieldClassMetadata}
	if _, err := NewRecord(input); err != nil {
		t.Fatalf("valid long JSON Pointer rejected: %v", err)
	}
}

func TestRecordSchemaDerivedFieldClassTrustBoundary(t *testing.T) {
	input := validRecordInput()
	input.FieldClasses = nil
	if _, err := NewRecord(input); err == nil {
		t.Fatal("empty untrusted field classes accepted")
	}
	record, err := newSchemaDerivedRecord(input)
	if err != nil {
		t.Fatalf("schema-derived assertion rejected: %v", err)
	}
	if !record.SchemaDerivedFieldClasses() || len(record.FieldClasses()) != 0 {
		t.Fatalf("schema-derived state not preserved")
	}
}

func TestRecordSchemaDerivedLogMandatoryBoundary(t *testing.T) {
	input := validRecordInput()
	input.Identity = EventIdentity{
		Bucket: BucketComplianceActivity,
		Signal: SignalLogs,
		Name:   "approval.resolved",
	}
	input.Outcome = OutcomeApproved
	input.FieldClasses = nil
	contract := &testSchemaDerivedLogFamilyContract{identity: input.Identity, mandatory: true}
	record, err := newSchemaDerivedLogRecord(input, contract)
	if err != nil {
		t.Fatalf("schema-derived mandatory log rejected: %v", err)
	}
	if !record.Mandatory() || !record.SchemaDerivedFieldClasses() || record.IsFloorOnly() {
		t.Fatalf(
			"schema-derived log flags mandatory=%t derived=%t floor_only=%t",
			record.Mandatory(),
			record.SchemaDerivedFieldClasses(),
			record.IsFloorOnly(),
		)
	}
	if len(record.FieldClasses()) != 0 {
		t.Fatalf("schema-derived field classes = %#v", record.FieldClasses())
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["mandatory"] != true {
		t.Fatalf("mandatory wire state = %#v", wire["mandatory"])
	}
	if got := wire["field_classes"]; !reflect.DeepEqual(got, map[string]any{}) {
		t.Fatalf("schema-derived wire field classes = %#v", got)
	}
	if _, exists := wire["body"]; !exists {
		t.Fatalf("schema-derived log body missing: %#v", wire)
	}
	contract.mandatory = false
	nonMandatory, err := newSchemaDerivedLogRecord(input, contract)
	if err != nil {
		t.Fatalf("schema-derived non-mandatory log rejected: %v", err)
	}
	if nonMandatory.Mandatory() || !nonMandatory.SchemaDerivedFieldClasses() || nonMandatory.IsFloorOnly() {
		t.Fatalf("schema-derived non-mandatory flags changed: %#v", nonMandatory.data)
	}
}

func TestRecordSchemaDerivedLogRejectsInvalidFamilyContracts(t *testing.T) {
	logInput := validRecordInput()
	logInput.Identity = EventIdentity{
		Bucket: BucketComplianceActivity,
		Signal: SignalLogs,
		Name:   "approval.resolved",
	}
	unregisteredInput := logInput
	unregisteredInput.Identity.Name = "plausible.but.unregistered"
	tests := []struct {
		name     string
		input    RecordInput
		contract schemaDerivedLogFamilyContract
		message  string
	}{
		{
			name:  "trace contract",
			input: logInput,
			contract: &testSchemaDerivedLogFamilyContract{
				identity: EventIdentity{
					Bucket: BucketAgentLifecycle,
					Signal: SignalTraces,
					Name:   "span.workflow.run",
				},
			},
			message: "requires the logs signal",
		},
		{
			name:     "nil contract",
			input:    logInput,
			contract: nil,
			message:  "requires a family contract",
		},
		{
			name:     "typed nil contract",
			input:    logInput,
			contract: (*testSchemaDerivedLogFamilyContract)(nil),
			message:  "requires a family contract",
		},
		{
			name:  "identity mismatch",
			input: logInput,
			contract: &testSchemaDerivedLogFamilyContract{identity: EventIdentity{
				Bucket: BucketComplianceActivity,
				Signal: SignalLogs,
				Name:   "authentication.failed",
			}},
			message: "identity does not match its family contract",
		},
		{
			name:  "unregistered identity",
			input: unregisteredInput,
			contract: &testSchemaDerivedLogFamilyContract{
				identity: unregisteredInput.Identity,
			},
			message: "family identity is not registered",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newSchemaDerivedLogRecord(test.input, test.contract); err == nil ||
				!strings.Contains(err.Error(), test.message) {
				t.Fatalf("schema-derived log signal error = %v", err)
			}
		})
	}
}

func TestRecordExistingConstructionPathsRetainMandatoryAndSchemaTrust(t *testing.T) {
	input := validRecordInput()
	ordinary, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Mandatory() || ordinary.SchemaDerivedFieldClasses() || ordinary.IsFloorOnly() {
		t.Fatalf("ordinary flags changed: %#v", ordinary.data)
	}

	input.FieldClasses = nil
	schemaDerived, err := newSchemaDerivedRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	if schemaDerived.Mandatory() || !schemaDerived.SchemaDerivedFieldClasses() || schemaDerived.IsFloorOnly() {
		t.Fatalf("generic schema-derived flags changed: %#v", schemaDerived.data)
	}

	input = validRecordInput()
	classified, err := newClassifiedLogRecord(input, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if !classified.Mandatory() || classified.SchemaDerivedFieldClasses() || classified.IsFloorOnly() {
		t.Fatalf("classified log flags changed: %#v", classified.data)
	}
}

func TestRecordRejectsInvalidEnvelopeMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecordInput)
	}{
		{name: "zero timestamp", mutate: func(input *RecordInput) { input.Timestamp = time.Time{} }},
		{name: "missing record ID", mutate: func(input *RecordInput) { input.RecordID = "" }},
		{name: "unregistered event", mutate: func(input *RecordInput) { input.Identity.Name = "diagnostic.unregistered" }},
		{name: "event registered for other signal", mutate: func(input *RecordInput) { input.Identity.Name = "span.workflow.run" }},
		{name: "invalid source", mutate: func(input *RecordInput) { input.Source = "Not Valid" }},
		{name: "invalid connector", mutate: func(input *RecordInput) { input.Connector = "Not Valid" }},
		{name: "invalid outcome", mutate: func(input *RecordInput) { input.Outcome = "success" }},
		{name: "invalid severity", mutate: func(input *RecordInput) { severity := Severity("WARN"); input.Severity = &severity }},
		{name: "invalid log level", mutate: func(input *RecordInput) { input.LogLevel = "NOTICE" }},
		{name: "invalid producer", mutate: func(input *RecordInput) { input.Provenance.Producer = "9gateway" }},
		{name: "long producer", mutate: func(input *RecordInput) { input.Provenance.Producer = "g" + strings.Repeat("x", 64) }},
		{name: "missing binary version", mutate: func(input *RecordInput) { input.Provenance.BinaryVersion = "" }},
		{name: "zero registry schema", mutate: func(input *RecordInput) { input.Provenance.RegistrySchemaVersion = 0 }},
		{name: "negative config generation", mutate: func(input *RecordInput) { input.Provenance.ConfigGeneration = -1 }},
		{name: "upper build commit", mutate: func(input *RecordInput) { input.Provenance.BuildCommit = "ABC123" }},
		{name: "long build commit", mutate: func(input *RecordInput) { input.Provenance.BuildCommit = strings.Repeat("a", MaxProvenanceHexBytes+1) }},
		{name: "prefixed config digest", mutate: func(input *RecordInput) { input.Provenance.ConfigDigest = "sha256:abc" }},
		{name: "long config digest", mutate: func(input *RecordInput) { input.Provenance.ConfigDigest = strings.Repeat("a", MaxProvenanceHexBytes+1) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validRecordInput()
			test.mutate(&input)
			if _, err := NewRecord(input); err == nil {
				t.Fatal("invalid envelope accepted")
			}
		})
	}
}

func TestRecordEncodedSizeBoundary(t *testing.T) {
	record, err := NewRecord(validRecordInput())
	if err != nil {
		t.Fatal(err)
	}
	record.data.connector = ""
	base, err := record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	const connectorOverhead = len(`,"connector":""`)
	padding := MaxCanonicalRecordBytes - len(base) - connectorOverhead
	if padding <= 0 {
		t.Fatalf("unexpected base record size %d", len(base))
	}
	record.data.connector = strings.Repeat("x", padding)
	exact, err := record.MarshalJSON()
	if err != nil {
		t.Fatalf("exact record boundary rejected: %v", err)
	}
	if len(exact) != MaxCanonicalRecordBytes {
		t.Fatalf("exact record size = %d", len(exact))
	}
	record.data.connector += "x"
	if _, err := record.MarshalJSON(); err == nil || strings.Contains(err.Error(), record.data.connector) {
		t.Fatalf("one-over record error = %v", err)
	}
}

func TestRecordConstructorExactEncodedSizeBoundary(t *testing.T) {
	input := validRecordInput()
	commonKey := strings.Repeat("k", 55*1024)
	nested := make(map[string]any, 70)
	classes := make(map[string]FieldClass, 71)
	for index := range 70 {
		leaf := fmt.Sprintf("leaf_%02d", index)
		nested[leaf] = true
		classes["/"+commonKey+"/"+leaf] = FieldClassMetadata
	}
	input.Body = map[string]any{commonKey: nested, "pad": ""}
	classes["/pad"] = FieldClassMetadata
	input.FieldClasses = classes

	base, err := NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	baseBytes, err := base.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	baseBody, ok := base.Body()
	if !ok {
		t.Fatal("base record body missing")
	}
	padding := MaxCanonicalRecordBytes - len(baseBytes)
	if padding <= 0 || padding > MaxCanonicalValueBytes-len(baseBody.Bytes()) {
		t.Fatalf("fixture leaves unusable legal padding %d (base=%d)", padding, len(baseBytes))
	}
	input.Body.(map[string]any)["pad"] = strings.Repeat("p", padding)

	exact, err := NewRecord(input)
	if err != nil {
		t.Fatalf("constructor rejected exact 4 MiB record: %v", err)
	}
	exactBytes, err := exact.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(exactBytes) != MaxCanonicalRecordBytes {
		t.Fatalf("constructor record size = %d, want %d", len(exactBytes), MaxCanonicalRecordBytes)
	}

	input.Body.(map[string]any)["pad"] = strings.Repeat("p", padding+1)
	if _, err := NewRecord(input); err == nil {
		t.Fatal("constructor accepted one-byte-over complete record")
	}
}

func TestRecordConstructorEnforcesCompleteEncodedSize(t *testing.T) {
	input := validRecordInput()
	commonKey := strings.Repeat("k", 64*1024)
	nested := make(map[string]any, 70)
	classes := make(map[string]FieldClass, 70)
	for index := range 70 {
		leaf := fmt.Sprintf("leaf_%02d", index)
		nested[leaf] = true
		classes["/"+commonKey+"/"+leaf] = FieldClassMetadata
	}
	input.Body = map[string]any{commonKey: nested}
	input.FieldClasses = classes
	_, err := NewRecord(input)
	if err == nil {
		t.Fatal("constructor returned an over-limit record")
	}
	if strings.Contains(err.Error(), commonKey[:128]) {
		t.Fatalf("size error echoed payload path: %v", err)
	}
}

func TestRecordPayloadErrorsDoNotEchoValues(t *testing.T) {
	secret := "highly-sensitive-secret"
	input := validRecordInput()
	input.Body = map[string]any{"message": make(chan string), "secret": secret}
	input.FieldClasses = map[string]FieldClass{"": FieldClassContent}
	_, err := NewRecord(input)
	if err == nil {
		t.Fatal("unsupported payload accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("payload value leaked through error: %v", err)
	}
}

func TestRecordIdentityErrorsDoNotEchoRejectedValues(t *testing.T) {
	secret := "sensitive-rejected-identity"
	for _, mutate := range []func(*RecordInput){
		func(input *RecordInput) { input.Identity.Name = EventName(secret) },
		func(input *RecordInput) { input.Identity.Bucket = Bucket(secret) },
		func(input *RecordInput) { input.Identity.Signal = Signal(secret) },
	} {
		input := validRecordInput()
		mutate(&input)
		_, err := NewRecord(input)
		if err == nil {
			t.Fatal("invalid identity accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("identity error echoed rejected value: %v", err)
		}
	}
}

func TestZeroRecordCannotMarshal(t *testing.T) {
	if _, err := json.Marshal(Record{}); err == nil {
		t.Fatal("zero record marshaled")
	}
}
