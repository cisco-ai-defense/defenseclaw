// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// marshalProjectedRecordByDecoding is marshalProjectedRecord of 1.0.7 rc3: it
// decoded the canonical bytes back into the member map.
func marshalProjectedRecordByDecoding(record observability.Record, payload observability.Value, metadata ProjectionMetadata) ([]byte, error) {
	if payload.IsZero() || validateProjectionMetadata(metadata) != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	metadataBytes, err := marshalProjectionJSON(metadata)
	if err != nil || len(metadataBytes) > MaxProjectionMetadataBytes {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	canonical, err := record.Bytes()
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	payloadObject, err := payload.Object()
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	switch record.Signal() {
	case observability.SignalLogs, observability.SignalTraces:
		wire["body"] = payload.Clone()
		delete(wire, "instrument_data")
	case observability.SignalMetrics:
		wire["instrument_data"] = payload.Clone()
		delete(wire, "body")
	}
	filteredClasses := make(map[string]observability.FieldClass)
	for pointer, class := range record.FieldClasses() {
		if projectionPointerResolves(payloadObject, pointer) {
			filteredClasses[pointer] = class
		}
	}
	wire["field_classes"] = filteredClasses
	wire["projection"] = metadata
	encoded, err := marshalProjectionJSON(wire)
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	return encoded, nil
}

// TestProjectionFromRecordMembersMatchesDecodedBytes pins rel-1-0-6
// GAP-0381: the projection that takes its members from the record encodes
// byte for byte as the one that decoded the record's canonical bytes, for
// every signal and built-in profile, every optional member, text with
// U+2028/U+2029 (raw and as a literal escape), HTML characters, non-ASCII
// text, numbers at the int64 and float limits, and every timestamp form.
func TestProjectionFromRecordMembersMatchesDecodedBytes(t *testing.T) {
	severity := observability.SeverityHigh
	observed := time.Date(2026, 7, 3, 5, 4, 3, 2, time.FixedZone("offset", 3600))
	body := map[string]any{
		"message": "a \\ \"quoted\" <b>&amp;</b> é 漢字 left right  `left\\u2028right`",
		"count":   int64(math.MaxInt64), "min": int64(math.MinInt64), "ratio": 0.1, "tiny": 5e-324, "big": 1.7976931348623157e308,
		"flag": true, "none": nil, "list": []any{1, "two", nil, map[string]any{"k": "v"}},
		"nested": map[string]any{"deep": map[string]any{"credential": "sk-not-a-real-key-0000"}},
	}
	classes := map[string]observability.FieldClass{
		"/message": observability.FieldClassContent, "/count": observability.FieldClassMetadata,
		"/min": observability.FieldClassMetadata, "/ratio": observability.FieldClassMetadata,
		"/tiny": observability.FieldClassMetadata, "/big": observability.FieldClassMetadata,
		"/flag": observability.FieldClassMetadata, "/none": observability.FieldClassMetadata,
		"/list/0": observability.FieldClassMetadata, "/list/1": observability.FieldClassContent,
		"/list/2": observability.FieldClassMetadata, "/list/3/k": observability.FieldClassIdentifier,
		"/nested/deep/credential": observability.FieldClassCredential,
	}
	inputs := map[string]observability.RecordInput{}
	full := observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 4, 3, 2, 1, time.FixedZone("offset", -5*3600)), ObservedAt: &observed,
		RecordID: "occurrence \\\"1", Severity: &severity, LogLevel: observability.LogLevelWarn,
		Identity: observability.EventIdentity{Bucket: observability.BucketDiagnostic, Signal: observability.SignalLogs, Name: "diagnostic.message"},
		Source:   observability.SourceGateway, Connector: "codex", Action: "diagnostic.emit", Phase: "completed",
		Outcome: observability.OutcomeCompleted,
		Correlation: observability.Correlation{SemanticEventID: "semantic-1", LogicalEventID: "logical-1",
			ConnectorInstanceID: "connector-instance-1", RunID: "run-1", RequestID: "request-1", SessionID: "session é ",
			TurnID: "turn-1", TraceID: "trace-1", SpanID: "span-1", AgentID: "agent-1", AgentInstanceID: "agent-instance-1",
			PolicyID: "policy-1", PolicyVersion: "v1", EvaluationID: "evaluation-1", ToolInvocationID: "tool <1>"},
		Provenance: observability.Provenance{Producer: "gateway.audit", BinaryVersion: "v1.2.3+build",
			RegistrySchemaVersion: 7, ConfigGeneration: math.MaxInt64, BuildCommit: "abcdef0123456789", ConfigDigest: "0123456789abcdef"},
		Body: body, FieldClasses: classes,
	}
	inputs["log with every member"] = full
	minimal := full
	minimal.ObservedAt, minimal.Severity, minimal.LogLevel = nil, nil, ""
	minimal.Connector, minimal.Action, minimal.Phase, minimal.Outcome = "", "", "", ""
	minimal.Correlation = observability.Correlation{}
	minimal.Provenance = observability.Provenance{Producer: "gateway", BinaryVersion: "v8", RegistrySchemaVersion: 1, ConfigGeneration: 0}
	minimal.Timestamp = time.Date(2026, 11, 2, 18, 0, 0, 0, time.UTC)
	inputs["log with no optional member"] = minimal
	trace := minimal
	trace.Identity = observability.EventIdentity{Bucket: observability.BucketAgentLifecycle, Signal: observability.SignalTraces, Name: "span.workflow.run"}
	trace.SpanName = "workflow.run"
	inputs["trace"] = trace
	metric := minimal
	metric.Identity = observability.EventIdentity{Bucket: observability.BucketComplianceActivity, Signal: observability.SignalMetrics, Name: "defenseclaw.activity.total"}
	metric.Body = nil
	metric.InstrumentData = map[string]any{"value": int64(3), "unit": "1"}
	metric.FieldClasses = map[string]observability.FieldClass{"/value": observability.FieldClassMetadata, "/unit": observability.FieldClassMetadata}
	inputs["metric"] = metric

	engine := newTestEngine(t)
	compared := 0
	for name, input := range inputs {
		record, err := observability.NewRecord(input)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, profileName := range []ProfileName{ProfileNone, ProfileSensitive, ProfileContent, ProfileStrict} {
			profile, ok := BuiltInProfile(profileName)
			if !ok {
				t.Fatalf("no built-in profile %q", profileName)
			}
			projection, _, err := engine.Project(record, profile)
			if err != nil {
				t.Fatalf("%s / %s: %v", name, profileName, err)
			}
			want, err := marshalProjectedRecordByDecoding(record, projection.payload, projection.metadata)
			if err != nil {
				t.Fatalf("%s / %s: decoding reference: %v", name, profileName, err)
			}
			if !bytes.Equal(projection.encoded, want) {
				t.Fatalf("%s / %s: projection bytes differ\n got %s\nwant %s", name, profileName, projection.encoded, want)
			}
			compared++
		}
	}
	if compared != 16 {
		t.Fatalf("compared %d projections, want 16", compared)
	}
}
