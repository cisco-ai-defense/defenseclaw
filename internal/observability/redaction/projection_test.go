// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestFieldMapPreflightRejectsMissingExtraAndStalePointers(t *testing.T) {
	value, err := observability.NewValue(map[string]any{
		"a": 1,
		"nested": map[string]any{
			"b": []any{"x", nil},
		},
		"empty": map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	object, err := value.Object()
	if err != nil {
		t.Fatal(err)
	}
	complete := map[string]observability.FieldClass{
		"/a":          observability.FieldClassMetadata,
		"/nested/b/0": observability.FieldClassContent,
		"/nested/b/1": observability.FieldClassContent,
		"/empty":      observability.FieldClassContent,
	}
	if err := preflightFieldMap(object, complete); err != nil {
		t.Fatal(err)
	}
	missing := cloneClasses(complete)
	delete(missing, "/nested/b/1")
	extra := cloneClasses(complete)
	extra["/nested"] = observability.FieldClassContent
	stale := cloneClasses(complete)
	delete(stale, "/nested/b/0")
	stale["/nested/b/2"] = observability.FieldClassContent
	for name, classes := range map[string]map[string]observability.FieldClass{
		"missing": missing, "extra": extra, "stale": stale,
	} {
		if err := preflightFieldMap(object, classes); !IsProjectionError(err, ProjectionFailureClassification) {
			t.Errorf("%s preflight error = %v", name, err)
		}
	}
	if got, want := leafPointers(object), []string{"/a", "/empty", "/nested/b/0", "/nested/b/1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("leaf order = %v, want %v", got, want)
	}
}

func TestProjectedSerializationIsExactDeterministicAndFiltersRemovedPointers(t *testing.T) {
	dynamicKey := "person@example.invalid"
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{dynamicKey: "private value", "safe": "yes", "items": []any{"credential"}},
		map[string]observability.FieldClass{
			"/" + dynamicKey: observability.FieldClassContent,
			"/safe":          observability.FieldClassMetadata,
			"/items/0":       observability.FieldClassCredential,
		},
	)
	before, _ := record.Bytes()
	strict, _ := BuiltInProfile(ProfileStrict)
	projection, _, err := newTestEngine(t).Project(record, strict)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := projection.Bytes()
	second, _ := projection.Bytes()
	if !bytes.Equal(first, second) {
		t.Fatal("projected serialization is not deterministic")
	}
	if strings.Contains(string(first), dynamicKey) {
		t.Fatal("removed dynamic property leaked through projected field_classes")
	}
	var wire map[string]any
	if err := json.Unmarshal(first, &wire); err != nil {
		t.Fatal(err)
	}
	projectionWire := wire["projection"].(map[string]any)
	wantKeys := []string{
		"redaction_profile", "detector_catalog_version", "state", "transformed_fields",
		"removed_fields", "oversize_fields", "failure_count", "failures_truncated",
	}
	if len(projectionWire) != len(wantKeys) {
		t.Fatalf("projection member set = %#v", projectionWire)
	}
	for _, key := range wantKeys {
		if _, exists := projectionWire[key]; !exists {
			t.Fatalf("projection is missing %q", key)
		}
	}
	fieldClasses := wire["field_classes"].(map[string]any)
	if _, exists := fieldClasses["/"+dynamicKey]; exists {
		t.Fatal("removed object property retained its class pointer")
	}
	if fieldClasses["/safe"] != "metadata" || fieldClasses["/items/0"] != "credential" {
		t.Fatalf("projected field classes = %#v", fieldClasses)
	}
	items := wire["body"].(map[string]any)["items"].([]any)
	if len(items) != 1 || items[0] != nil {
		t.Fatalf("removed array slot = %#v", items)
	}
	if after, _ := record.Bytes(); !bytes.Equal(before, after) {
		t.Fatal("projected serialization mutated the canonical record")
	}
}

func TestProjectionPrunesNewlyEmptyObjectsButRetainsOriginalEmptyAndArrayShape(t *testing.T) {
	dynamicKey := "container@example.invalid"
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{
			dynamicKey: map[string]any{"secret": "x"},
			"items": []any{
				map[string]any{"secret": "x"},
				map[string]any{"safe": "yes"},
				map[string]any{},
			},
		},
		map[string]observability.FieldClass{
			"/" + dynamicKey + "/secret": observability.FieldClassContent,
			"/items/0/secret":            observability.FieldClassContent,
			"/items/1/safe":              observability.FieldClassMetadata,
			"/items/2":                   observability.FieldClassMetadata,
		},
	)
	strict, _ := BuiltInProfile(ProfileStrict)
	projection, _, err := newTestEngine(t).Project(record, strict)
	if err != nil {
		t.Fatal(err)
	}
	object, _ := projection.Payload().Object()
	if _, exists := object[dynamicKey]; exists {
		t.Fatal("newly empty dynamic object property was retained")
	}
	if projection.Metadata().RemovedFields != 4 {
		t.Fatalf("descendant plus structural removals = %#v", projection.Metadata())
	}
	items := object["items"].([]any)
	if len(items) != 3 || items[0] != nil {
		t.Fatalf("array shape = %#v", items)
	}
	if retained := items[1].(map[string]any); retained["safe"] != "yes" {
		t.Fatalf("retained object = %#v", retained)
	}
	if originalEmpty := items[2].(map[string]any); len(originalEmpty) != 0 {
		t.Fatalf("original empty object = %#v", originalEmpty)
	}
	encoded, _ := projection.Bytes()
	if strings.Contains(string(encoded), dynamicKey) || strings.Contains(string(encoded), "/items/0/secret") {
		t.Fatalf("pruned container identity leaked: %s", encoded)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	fieldClasses := wire["field_classes"].(map[string]any)
	if len(fieldClasses) != 2 || fieldClasses["/items/1/safe"] != "metadata" || fieldClasses["/items/2"] != "metadata" {
		t.Fatalf("surviving field classes = %#v", fieldClasses)
	}
}

func TestProjectionMetadataRejectsSemanticContradictions(t *testing.T) {
	valid := []ProjectionMetadata{
		{RedactionProfile: "none", DetectorCatalogVersion: 1, State: ProjectionStateRaw},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateInspected},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateTransformed, RemovedFields: 1},
		{RedactionProfile: "content", DetectorCatalogVersion: 1, State: ProjectionStateFailedClosed, FailureCount: 1},
		{RedactionProfile: "content", DetectorCatalogVersion: 1, State: ProjectionStateFailedClosed, TransformedFields: 33, FailureCount: 33, FailuresTruncated: true},
	}
	for _, metadata := range valid {
		if err := validateProjectionMetadata(metadata); err != nil {
			t.Errorf("valid metadata %#v rejected: %v", metadata, err)
		}
	}
	invalid := []ProjectionMetadata{
		{},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateRaw},
		{RedactionProfile: "none", DetectorCatalogVersion: 1, State: ProjectionStateInspected},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateInspected, RemovedFields: 1},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateTransformed},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateFailedClosed, TransformedFields: 33, FailureCount: 33},
		{RedactionProfile: "strict", DetectorCatalogVersion: 1, State: ProjectionStateFailedClosed, TransformedFields: 2, FailureCount: 2, FailuresTruncated: true},
	}
	for _, metadata := range invalid {
		if err := validateProjectionMetadata(metadata); !IsProjectionError(err, ProjectionFailureSerialization) {
			t.Errorf("invalid metadata %#v error = %v", metadata, err)
		}
	}
	if MaxProjectedRecordBytes != observability.MaxCanonicalRecordBytes+4*1024 {
		t.Fatalf("projected record bound = %d", MaxProjectedRecordBytes)
	}
}

func TestProjectedSerializationUsesExactlyOneSignalPayloadArm(t *testing.T) {
	for _, signal := range []observability.Signal{observability.SignalLogs, observability.SignalTraces, observability.SignalMetrics} {
		record := newTestRecord(t, signal,
			map[string]any{"value": 1},
			map[string]observability.FieldClass{"/value": observability.FieldClassMetadata},
		)
		none, _ := BuiltInProfile(ProfileNone)
		projection, _, err := newTestEngine(t).Project(record, none)
		if err != nil {
			t.Fatal(err)
		}
		encoded, _ := projection.Bytes()
		var wire map[string]any
		if err := json.Unmarshal(encoded, &wire); err != nil {
			t.Fatal(err)
		}
		_, hasBody := wire["body"]
		_, hasInstrumentData := wire["instrument_data"]
		if signal == observability.SignalMetrics {
			if hasBody || !hasInstrumentData {
				t.Fatalf("metric payload arms = body:%t instrument:%t", hasBody, hasInstrumentData)
			}
		} else if !hasBody || hasInstrumentData {
			t.Fatalf("%s payload arms = body:%t instrument:%t", signal, hasBody, hasInstrumentData)
		}
	}
}

func TestRecordFailuresDoNotGuessFieldClassOrMode(t *testing.T) {
	none, _ := BuiltInProfile(ProfileNone)
	_, report, err := newTestEngine(t).Project(observability.Record{}, none)
	if !IsProjectionError(err, ProjectionFailureSerialization) {
		t.Fatalf("zero record error = %v", err)
	}
	if report.Metadata().FailureCount != 1 || report.Metadata().State != ProjectionStateFailedClosed || len(report.Entries()) != 0 {
		t.Fatalf("record failure report = %#v / %#v", report.Metadata(), report.Entries())
	}
}

func TestProjectedSerializationPreservesLineSeparatorEscapeParity(t *testing.T) {
	record := newTestRecord(t, observability.SignalLogs,
		map[string]any{"actual": "left\u2028right", "literal": `left\u2028right`},
		map[string]observability.FieldClass{
			"/actual":  observability.FieldClassMetadata,
			"/literal": observability.FieldClassMetadata,
		},
	)
	none, _ := BuiltInProfile(ProfileNone)
	projection, _, err := newTestEngine(t).Project(record, none)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := projection.Bytes()
	if !bytes.Contains(encoded, []byte("left\u2028right")) || !bytes.Contains(encoded, []byte(`left\\u2028right`)) {
		t.Fatalf("line separator encoding parity changed: %q", encoded)
	}
}

func cloneClasses(input map[string]observability.FieldClass) map[string]observability.FieldClass {
	result := make(map[string]observability.FieldClass, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func TestSafeReportAccessorsDoNotAlias(t *testing.T) {
	report := SafeReport{
		metadata: ProjectionMetadata{RedactionProfile: "strict", FailureCount: 1},
		entries:  []SafeFailure{{FieldClass: observability.FieldClassContent, Code: "key_unavailable"}},
	}
	entries := report.Entries()
	entries[0].Code = "changed"
	if got := report.Entries()[0].Code; got != "key_unavailable" {
		t.Fatalf("safe report entry was mutated: %q", got)
	}
}
