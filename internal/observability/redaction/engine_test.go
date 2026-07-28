// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestEngineProjectsNestedValuesInCanonicalTraversalOrder(t *testing.T) {
	body := map[string]any{
		"z_meta":     true,
		"content":    "mail person@example.invalid for help",
		"credential": "reserved credential value",
		"path":       "/srv/private/../model.json",
		"array": []any{
			map[string]any{"credential": "reserved second value", "safe": 4},
			"plain",
		},
	}
	classes := map[string]observability.FieldClass{
		"/z_meta":             observability.FieldClassMetadata,
		"/content":            observability.FieldClassContent,
		"/credential":         observability.FieldClassCredential,
		"/path":               observability.FieldClassPath,
		"/array/0/credential": observability.FieldClassCredential,
		"/array/0/safe":       observability.FieldClassMetadata,
		"/array/1":            observability.FieldClassContent,
	}
	record := newTestRecord(t, observability.SignalLogs, body, classes)
	before, _ := record.Bytes()
	engine := newTestEngine(t)
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	projection, report, err := engine.Project(record, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	metadata := projection.Metadata()
	if metadata.State != ProjectionStateTransformed || metadata.TransformedFields != 2 ||
		metadata.RemovedFields != 2 || metadata.OversizeFields != 0 || metadata.FailureCount != 0 {
		t.Fatalf("metadata = %#v", metadata)
	}
	if report.Metadata() != metadata || len(report.Entries()) != 0 {
		t.Fatalf("report = %#v/%#v", report.Metadata(), report.Entries())
	}
	projected, err := projection.Payload().Object()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := projected["credential"]; exists {
		t.Fatal("credential object property was not omitted")
	}
	array := projected["array"].([]any)
	first := array[0].(map[string]any)
	if _, exists := first["credential"]; exists {
		t.Fatal("nested credential object property was not omitted")
	}
	if !strings.Contains(projected["content"].(string), "<redacted type=pii.email") ||
		!strings.HasPrefix(projected["path"].(string), "<hashed class=path") {
		t.Fatalf("unexpected transformed payload: %#v", projected)
	}
	if after, _ := record.Bytes(); !bytes.Equal(before, after) {
		t.Fatal("canonical record was mutated")
	}
	// Mutating every returned representation must not reach the projection.
	projected["content"] = "changed"
	encoded, _ := projection.Bytes()
	encoded[0] = '['
	again, _ := projection.Payload().Object()
	if again["content"] == "changed" {
		t.Fatal("projection payload accessor aliased internal state")
	}
	againBytes, _ := projection.Bytes()
	if againBytes[0] != '{' {
		t.Fatal("projection bytes accessor aliased internal state")
	}
}

func TestEngineRemoveInArraysPreservesSlotsAndEmptyContainers(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"items": []any{"secret", map[string]any{}, []any{}}},
		map[string]observability.FieldClass{
			"/items/0": observability.FieldClassCredential,
			"/items/1": observability.FieldClassContent,
			"/items/2": observability.FieldClassMetadata,
		},
	)
	strict, _ := BuiltInProfile(ProfileStrict)
	projection, _, err := newTestEngine(t).Project(record, strict)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	items := object["items"].([]any)
	if len(items) != 3 || items[0] != nil || items[1] != nil {
		t.Fatalf("array slots = %#v", items)
	}
	if got, ok := items[2].([]any); !ok || len(got) != 0 {
		t.Fatalf("metadata empty array = %#v", items[2])
	}
	if projection.Metadata().RemovedFields != 2 {
		t.Fatalf("removed fields = %d", projection.Metadata().RemovedFields)
	}
}

func TestEngineStatesCountersAndKeylessNone(t *testing.T) {
	keyless, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	contentRecord := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": "ordinary sentence"},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	none, _ := BuiltInProfile(ProfileNone)
	raw, _, err := keyless.Project(contentRecord, none)
	if err != nil || raw.Metadata().State != ProjectionStateRaw {
		t.Fatalf("keyless none = %#v, %v", raw.Metadata(), err)
	}

	sensitive, _ := BuiltInProfile(ProfileSensitive)
	engine := newTestEngine(t)
	inspected, _, err := engine.Project(contentRecord, sensitive)
	if err != nil || inspected.Metadata().State != ProjectionStateInspected {
		t.Fatalf("inspected = %#v, %v", inspected.Metadata(), err)
	}
	content, _ := BuiltInProfile(ProfileContent)
	transformed, _, err := engine.Project(contentRecord, content)
	if err != nil || transformed.Metadata().State != ProjectionStateTransformed || transformed.Metadata().TransformedFields != 1 {
		t.Fatalf("transformed = %#v, %v", transformed.Metadata(), err)
	}
	failed, report, err := keyless.Project(contentRecord, content)
	if err != nil {
		t.Fatalf("field-level key failure must remain deliverable: %v", err)
	}
	if failed.Metadata().State != ProjectionStateFailedClosed ||
		failed.Metadata().FailureCount != 1 || failed.Metadata().TransformedFields != 1 ||
		len(report.Entries()) != 1 || report.Entries()[0].Code != "key_unavailable" {
		t.Fatalf("failed closed = %#v/%#v", failed.Metadata(), report.Entries())
	}
	object, _ := failed.Payload().Object()
	if got := object["message"].(string); got != "<redacted type=failed_closed v=1 code=key_unavailable>" {
		t.Fatalf("failed token = %q", got)
	}
}

func TestEngineSpoofShapedFailureTokenIsProcessedWithoutFalseChangeCount(t *testing.T) {
	value := "<redacted type=failed_closed v=1 code=key_unavailable>"
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": value},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	content, _ := BuiltInProfile(ProfileContent)
	keyless, _ := NewEngine(nil)
	projection, report, err := keyless.Project(record, content)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	if object["message"] != value {
		t.Fatalf("safe failed-closed token = %#v", object["message"])
	}
	if projection.Metadata().State != ProjectionStateFailedClosed ||
		projection.Metadata().FailureCount != 1 || projection.Metadata().TransformedFields != 0 ||
		len(report.Entries()) != 1 || report.Entries()[0].Code != "key_unavailable" {
		t.Fatalf("spoof-shaped failure metadata = %#v / %#v", projection.Metadata(), report.Entries())
	}
}

func TestEngineCorrelationKeyCustodyBoundary(t *testing.T) {
	var material [hashV1KeySize]byte
	for index := range material {
		material[index] = byte(index + 1)
	}
	key := newCorrelationKey(material)
	engine, err := NewEngineWithCorrelationKey(key)
	if err != nil {
		t.Fatal(err)
	}
	material[0] = 0
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": "value"},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	content, _ := BuiltInProfile(ProfileContent)
	projection, _, err := engine.Project(record, content)
	if err != nil || projection.Metadata().State != ProjectionStateTransformed {
		t.Fatalf("custodied key projection = %#v, %v", projection.Metadata(), err)
	}
	keyless, err := NewEngineWithCorrelationKey(CorrelationKey{})
	if err != nil {
		t.Fatal(err)
	}
	failed, _, err := keyless.Project(record, content)
	if err != nil || failed.Metadata().State != ProjectionStateFailedClosed {
		t.Fatalf("zero custodied key projection = %#v, %v", failed.Metadata(), err)
	}
}

func TestEngineConstructorRequiresNoKeyOrExactKey(t *testing.T) {
	if _, err := NewEngine([]byte("short")); !IsProjectionError(err, ProjectionFailureContext) {
		t.Fatalf("short key error = %v", err)
	}
	for _, key := range [][]byte{nil, bytes.Repeat([]byte{1}, hashV1KeySize)} {
		if _, err := NewEngine(key); err != nil {
			t.Fatalf("valid key length %d: %v", len(key), err)
		}
	}
}

func TestEngineWholeAndDetectScalarSemantics(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"boolean": true, "number": json.Number("1.2300"), "nothing": nil},
		map[string]observability.FieldClass{
			"/boolean": observability.FieldClassContent,
			"/number":  observability.FieldClassContent,
			"/nothing": observability.FieldClassContent,
		},
	)
	engine := newTestEngine(t)
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	detected, _, err := engine.Project(record, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	detectedObject, _ := detected.Payload().Object()
	if detectedObject["boolean"] != true || detectedObject["number"].(json.Number).String() != "1.23" || detectedObject["nothing"] != nil {
		t.Fatalf("detect altered non-string scalars: %#v", detectedObject)
	}
	content, _ := BuiltInProfile(ProfileContent)
	whole, _, err := engine.Project(record, content)
	if err != nil {
		t.Fatal(err)
	}
	wholeObject, _ := whole.Payload().Object()
	if !strings.HasPrefix(wholeObject["boolean"].(string), "<redacted type=field.content") ||
		!strings.HasPrefix(wholeObject["number"].(string), "<redacted type=field.content") ||
		wholeObject["nothing"] != nil || whole.Metadata().TransformedFields != 2 {
		t.Fatalf("whole scalar output = %#v / %#v", wholeObject, whole.Metadata())
	}
}

func TestEngineSafeFailuresFollowCanonicalTraversalOrder(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"z_content": string(rune(0x1fae0)), "a_path": "http://"},
		map[string]observability.FieldClass{
			"/z_content": observability.FieldClassContent,
			"/a_path":    observability.FieldClassPath,
		},
	)
	profile, err := NewCustomProfile(
		"hash.failures", ProfileContent, nil,
		map[observability.FieldClass]TransformationMode{observability.FieldClassContent: ModeHash},
	)
	if err != nil {
		t.Fatal(err)
	}
	projection, report, err := newTestEngine(t).Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	entries := report.Entries()
	if len(entries) != 2 {
		t.Fatalf("safe failure entries = %#v", entries)
	}
	if got := []string{entries[0].Code, entries[1].Code}; !reflect.DeepEqual(got, []string{"normalization_failed", "unicode_repertoire"}) {
		t.Fatalf("safe failure order = %v", got)
	}
	if projection.Metadata().State != ProjectionStateFailedClosed ||
		projection.Metadata().FailureCount != 2 || projection.Metadata().TransformedFields != 2 {
		t.Fatalf("failure metadata = %#v", projection.Metadata())
	}
}

func TestEngineDetectorValidatorFailureProtectsWholeField(t *testing.T) {
	input := "https://example.test/path?token=%zz"
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": input},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	projection, report, err := newTestEngine(t).Project(record, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	if got := object["message"]; got != "<redacted type=failed_closed v=1 code=validator_failed>" {
		t.Fatalf("validator failure output = %#v", got)
	}
	if projection.Metadata().State != ProjectionStateFailedClosed ||
		projection.Metadata().FailureCount != 1 || projection.Metadata().TransformedFields != 1 ||
		len(report.Entries()) != 1 || report.Entries()[0].Code != "validator_failed" {
		t.Fatalf("validator failure metadata = %#v / %#v", projection.Metadata(), report.Entries())
	}
	encoded, _ := projection.Bytes()
	if bytes.Contains(encoded, []byte(input)) {
		t.Fatal("validator failure retained the malformed raw field")
	}
}

func TestEngineOversizeAndSafeReportBound(t *testing.T) {
	oversize := strings.Repeat("a", MaxScannedStringBytes+1)
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": oversize},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	projection, _, err := newTestEngine(t).Project(record, sensitive)
	if err != nil {
		t.Fatal(err)
	}
	metadata := projection.Metadata()
	if metadata.State != ProjectionStateTransformed || metadata.TransformedFields != 1 || metadata.OversizeFields != 1 {
		t.Fatalf("oversize metadata = %#v", metadata)
	}

	body := make(map[string]any, MaxSafeReportEntries+2)
	classes := make(map[string]observability.FieldClass, MaxSafeReportEntries+2)
	for index := 0; index < MaxSafeReportEntries+2; index++ {
		key := fmt.Sprintf("field%02d", index)
		body[key] = "value"
		classes["/"+key] = observability.FieldClassContent
	}
	failedRecord := newTestRecord(t, observability.SignalLogs, body, classes)
	content, _ := BuiltInProfile(ProfileContent)
	keyless, _ := NewEngine(nil)
	failed, report, err := keyless.Project(failedRecord, content)
	if err != nil {
		t.Fatal(err)
	}
	if failed.Metadata().FailureCount != MaxSafeReportEntries+2 ||
		!failed.Metadata().FailuresTruncated || len(report.Entries()) != MaxSafeReportEntries {
		t.Fatalf("bounded report = %#v, entries=%d", failed.Metadata(), len(report.Entries()))
	}
}

func TestEngineIndependentDestinationsAndTrustedReprojection(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": "mail person@example.invalid", "secret": "reserved"},
		map[string]observability.FieldClass{
			"/message": observability.FieldClassContent,
			"/secret":  observability.FieldClassCredential,
		},
	)
	engine := newTestEngine(t)
	none, _ := BuiltInProfile(ProfileNone)
	strict, _ := BuiltInProfile(ProfileStrict)
	raw, _, err := engine.Project(record, none)
	if err != nil {
		t.Fatal(err)
	}
	locked, _, err := engine.Project(record, strict)
	if err != nil {
		t.Fatal(err)
	}
	rawObject, _ := raw.Payload().Object()
	strictObject, _ := locked.Payload().Object()
	if rawObject["message"] == nil || len(strictObject) != 0 {
		t.Fatalf("independent outputs raw=%#v strict=%#v", rawObject, strictObject)
	}
	clone, cloneReport, err := engine.Reproject(locked, strict)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := locked.Bytes()
	right, _ := clone.Bytes()
	if !bytes.Equal(left, right) || cloneReport.Metadata() != locked.Metadata() {
		t.Fatal("same-context reprojection was not an exact clone")
	}
	right[0] = '['
	again, _ := locked.Bytes()
	if again[0] != '{' {
		t.Fatal("reprojection clone aliased source bytes")
	}
	if _, _, err := engine.Reproject(locked, none); !IsProjectionError(err, ProjectionFailureContext) {
		t.Fatalf("profile mismatch error = %v", err)
	}
	other := newTestEngine(t)
	if _, _, err := other.Reproject(locked, strict); !IsProjectionError(err, ProjectionFailureContext) {
		t.Fatalf("engine mismatch error = %v", err)
	}
}

func TestEngineMetricClassEnforcement(t *testing.T) {
	engine := newTestEngine(t)
	none, _ := BuiltInProfile(ProfileNone)
	metadataMetric := newTestRecord(t, observability.SignalMetrics,
		map[string]any{"value": 3},
		map[string]observability.FieldClass{"/value": observability.FieldClassMetadata},
	)
	if _, _, err := engine.Project(metadataMetric, none); err != nil {
		t.Fatalf("metadata metric failed: %v", err)
	}
	for _, class := range []observability.FieldClass{
		observability.FieldClassContent,
		observability.FieldClassIdentifier,
	} {
		record := newTestRecord(t, observability.SignalMetrics,
			map[string]any{"value": "x"}, map[string]observability.FieldClass{"/value": class})
		if _, report, err := engine.Project(record, none); !IsProjectionError(err, ProjectionFailureMetricClass) ||
			report.Metadata().FailureCount != 1 {
			t.Fatalf("metric class %s = %v / %#v", class, err, report.Metadata())
		}
	}
	metricWithDetectorText := newTestRecord(t, observability.SignalMetrics,
		map[string]any{"value": "person@example.invalid"},
		map[string]observability.FieldClass{"/value": observability.FieldClassMetadata},
	)
	strict, _ := BuiltInProfile(ProfileStrict)
	projection, _, err := engine.Project(metricWithDetectorText, strict)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	if object["value"] != "person@example.invalid" ||
		projection.Metadata().State != ProjectionStateInspected ||
		projection.Metadata().TransformedFields != 0 {
		t.Fatalf("metric detector bypass contract = %#v / %#v", object, projection.Metadata())
	}
}

func TestEngineLegacyV7ClassAdaptersArePureAndKeyless(t *testing.T) {
	body := map[string]any{
		"metadata":   "allow",
		"identifier": "entity-value",
		"content":    "message value",
		"reason":     "RULE:dynamic value",
		"evidence":   "evidence value",
		"error":      "provider error",
		"path":       "/private/model.json",
		"credential": "credential value",
		"number":     json.Number("12.5"),
	}
	classes := map[string]observability.FieldClass{
		"/metadata": observability.FieldClassMetadata, "/identifier": observability.FieldClassIdentifier,
		"/content": observability.FieldClassContent, "/reason": observability.FieldClassReason,
		"/evidence": observability.FieldClassEvidence, "/error": observability.FieldClassError,
		"/path": observability.FieldClassPath, "/credential": observability.FieldClassCredential,
		"/number": observability.FieldClassContent,
	}
	record := newTestRecord(t, observability.SignalLogs, body, classes)
	profile, ok := BuiltInProfile(ProfileLegacyV7)
	if !ok {
		t.Fatal("legacy-v7 profile is missing")
	}
	engine, err := NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	projection, report, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	want := map[string]any{
		"metadata":   "allow",
		"identifier": legacyredaction.LegacyV7Entity("entity-value"),
		"content":    legacyredaction.LegacyV7MessageContent("message value"),
		"reason":     legacyredaction.LegacyV7Reason("RULE:dynamic value"),
		"evidence":   legacyredaction.LegacyV7Evidence("evidence value", -1, -1),
		"error":      legacyredaction.LegacyV7String("provider error"),
		"path":       legacyredaction.LegacyV7String("/private/model.json"),
		"credential": legacyredaction.LegacyV7String("credential value"),
		"number":     legacyredaction.LegacyV7MessageContent("12.5"),
	}
	if !reflect.DeepEqual(object, want) {
		t.Fatalf("legacy-v7 projection = %#v, want %#v", object, want)
	}
	if projection.Metadata().State != ProjectionStateTransformed ||
		projection.Metadata().TransformedFields != 8 || projection.Metadata().FailureCount != 0 ||
		len(report.Entries()) != 0 {
		t.Fatalf("legacy-v7 metadata = %#v / %#v", projection.Metadata(), report.Entries())
	}
	clone, _, err := engine.Reproject(projection, profile)
	if err != nil {
		t.Fatal(err)
	}
	left, _ := projection.Bytes()
	right, _ := clone.Bytes()
	if !bytes.Equal(left, right) {
		t.Fatal("legacy-v7 trusted reprojection changed bytes")
	}
}

func TestEngineMaximumPayloadAndExpansionLimit(t *testing.T) {
	const emptyObjectEncoding = len(`{"x":""}`)
	value := strings.Repeat("a", observability.MaxCanonicalValueBytes-emptyObjectEncoding)
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"x": value}, map[string]observability.FieldClass{"/x": observability.FieldClassMetadata})
	none, _ := BuiltInProfile(ProfileNone)
	projection, _, err := newTestEngine(t).Project(record, none)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(projection.Payload().Bytes()); got != observability.MaxCanonicalValueBytes {
		t.Fatalf("maximum payload size = %d", got)
	}

	body := make(map[string]any, observability.MaxCanonicalValueMembers)
	classes := make(map[string]observability.FieldClass, observability.MaxCanonicalValueMembers)
	for index := 0; index < observability.MaxCanonicalValueMembers; index++ {
		key := fmt.Sprintf("field-name-padding-padding-padding-padding-%04d", index)
		body[key] = "one@example.invalid two@example.invalid"
		classes["/"+key] = observability.FieldClassContent
	}
	expanding := newTestRecord(t, observability.SignalLogs, body, classes)
	content, _ := BuiltInProfile(ProfileContent)
	if gotProjection, report, err := newTestEngine(t).Project(expanding, content); !IsProjectionError(err, ProjectionFailureOutputLimit) ||
		report.Metadata().FailureCount != 1 {
		if err == nil {
			t.Logf("projected payload bytes=%d", len(gotProjection.Payload().Bytes()))
		}
		t.Fatalf("expansion limit = %v / %#v", err, report.Metadata())
	}
}

func TestEngineConcurrentProjectionIsRaceSafeAndDeterministic(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"message": "mail person@example.invalid"},
		map[string]observability.FieldClass{"/message": observability.FieldClassContent},
	)
	engine := newTestEngine(t)
	sensitive, _ := BuiltInProfile(ProfileSensitive)
	const workers = 16
	results := make([][]byte, workers)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			projection, _, err := engine.Project(record, sensitive)
			if err != nil {
				t.Errorf("project: %v", err)
				return
			}
			results[index], err = projection.Bytes()
			if err != nil {
				t.Errorf("bytes: %v", err)
			}
		}(index)
	}
	wait.Wait()
	for index := 1; index < len(results); index++ {
		if !bytes.Equal(results[0], results[index]) {
			t.Fatalf("worker %d produced different bytes", index)
		}
	}
}

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	engine, err := NewEngine(key)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 0
	return engine
}

func newTestRecord(
	t *testing.T,
	signal observability.Signal,
	payload map[string]any,
	classes map[string]observability.FieldClass,
) observability.Record {
	t.Helper()
	eventName := observability.EventName("diagnostic.message")
	bucket := observability.BucketDiagnostic
	input := observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		RecordID:  "projection-test",
		Identity:  observability.EventIdentity{Bucket: bucket, Signal: signal, Name: eventName},
		Source:    observability.SourceGateway,
		Provenance: observability.Provenance{
			Producer: "gateway", BinaryVersion: "v8",
			RegistrySchemaVersion: 1, ConfigGeneration: 1,
		},
		FieldClasses: classes,
	}
	if signal == observability.SignalMetrics {
		input.Identity = observability.EventIdentity{
			Bucket: observability.BucketComplianceActivity,
			Signal: signal,
			Name:   "defenseclaw.activity.total",
		}
		input.InstrumentData = payload
	} else if signal == observability.SignalTraces {
		input.Identity = observability.EventIdentity{
			Bucket: observability.BucketAgentLifecycle,
			Signal: signal,
			Name:   "span.workflow.run",
		}
		input.SpanName = "workflow.run"
		input.Body = payload
	} else {
		input.Body = payload
	}
	record, err := observability.NewRecord(input)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
