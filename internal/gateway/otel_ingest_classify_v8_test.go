// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

const inboundClassifierTestInstance = "local-instance"

func TestOTLPInboundGeneratedBindingsAreClosedAndUnambiguous(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	matches := allInboundCatalogMatches(t, classifier.catalog)
	if len(matches) == 0 {
		t.Fatal("generated matches are empty")
	}
	for _, match := range matches {
		match := match
		t.Run(match.ID(), func(t *testing.T) {
			positive, source := inboundFixtureLeafForMatch(t, match)
			classification, err := classifier.classify(positive, source)
			if err != nil || classification.identityState != otlpInboundIdentityMatched ||
				classification.match.ID() != match.ID() || classification.matchCount != 1 ||
				classification.shape != match.Shape() {
				t.Fatalf("positive classification = state=%d shape=%q match=%q count=%d err=%v",
					classification.identityState, classification.shape, classification.match.ID(), classification.matchCount, err)
			}

			negative, negativeSource := inboundFixtureLeafForMatch(t, match)
			if !mutateFirstFiniteInboundPredicate(match, &negative) {
				t.Fatal("generated match has no finite predicate for negative fixture")
			}
			negativeResult, err := classifier.classify(negative, negativeSource)
			if err != nil || negativeResult.identityState == otlpInboundIdentityMatched &&
				negativeResult.match.ID() == match.ID() {
				t.Fatalf("negative fixture retained match %q: result=%+v err=%v", match.ID(), negativeResult, err)
			}

			singleFault, faultSource := inboundFixtureLeafForMatch(t, match)
			if !removeFirstRequiredInboundPredicate(match, &singleFault) {
				t.Fatal("generated match has no required predicate for single-fault fixture")
			}
			faultResult, err := classifier.classify(singleFault, faultSource)
			if err != nil || faultResult.identityState == otlpInboundIdentityMatched &&
				faultResult.match.ID() == match.ID() {
				t.Fatalf("single-fault fixture retained match %q: result=%+v err=%v", match.ID(), faultResult, err)
			}
			if match.Shape() == observability.InboundShapeNativeExact &&
				faultResult.identityState != otlpInboundIdentityNativeMalformed {
				t.Fatalf("native single fault state = %d, want native malformed", faultResult.identityState)
			}
		})
	}
}

func TestOTLPInboundClassifierSourceFilteringAndTypedAmbiguity(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("codex match missing")
	}
	leaf, _ := inboundFixtureLeafForMatch(t, match)
	for source, wantState := range map[string]otlpInboundIdentityState{
		"codex":      otlpInboundIdentityMatched,
		"claudecode": otlpInboundIdentityUnsupported,
	} {
		result, err := classifier.classify(leaf, source)
		if err != nil || result.identityState != wantState {
			t.Fatalf("source %q state=%d err=%v, want %d", source, result.identityState, err, wantState)
		}
	}
	if _, err := classifier.classify(leaf, "any_authenticated"); !errorsIsInboundClassifier(err) {
		t.Fatalf("reserved source error = %v", err)
	}
	ambiguous := selectInboundIdentity([]observability.InboundMatch{match, match})
	if ambiguous.identityState != otlpInboundIdentityAmbiguous || ambiguous.matchCount != 2 || ambiguous.match.ID() != "" {
		t.Fatalf("ambiguous selection = %+v", ambiguous)
	}
}

func TestOTLPInboundClassifierFailsClosedOnInvalidDependenciesAndLeafUnion(t *testing.T) {
	if _, err := newOTLPInboundClassifierV8(""); !errorsIsInboundClassifier(err) {
		t.Fatalf("empty local instance error = %v", err)
	}
	if _, err := newOTLPInboundClassifierV8WithCatalog(observability.InboundCatalog{}, inboundClassifierTestInstance); !errorsIsInboundClassifier(err) {
		t.Fatalf("zero catalog error = %v", err)
	}
	classifier := mustOTLPInboundClassifierV8(t)
	invalid := otlpDecodedLeaf{
		signal:         otelSignalMetrics,
		metric:         &metricspb.Metric{},
		metricShape:    otlpTypedMetricGauge,
		numberPoint:    &metricspb.NumberDataPoint{},
		histogramPoint: &metricspb.HistogramDataPoint{},
	}
	if _, err := classifier.classify(invalid, "fixture-source"); !errorsIsInboundClassifier(err) {
		t.Fatalf("invalid metric union error = %v", err)
	}
}

func TestOTLPInboundClassifierRejectsRepeatedKeysWrongArmsAndCaseFolding(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.user_prompt.v1.log.model.request")
	if !ok {
		t.Fatal("codex match missing")
	}
	tests := []struct {
		name   string
		mutate func(*otlpDecodedLeaf)
	}{
		{
			name: "repeated key",
			mutate: func(leaf *otlpDecodedLeaf) {
				leaf.logRecord.Attributes = append(leaf.logRecord.Attributes, otlpClassifierStringAttribute("event.name", "codex.user_prompt"))
				leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
			},
		},
		{
			name: "wrong anyvalue arm",
			mutate: func(leaf *otlpDecodedLeaf) {
				leaf.logRecord.Attributes = replaceInboundFixtureAttribute(leaf.logRecord.Attributes, "event.name", otlpClassifierIntAttribute("event.name", 1))
				leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
			},
		},
		{
			name: "case distinct key",
			mutate: func(leaf *otlpDecodedLeaf) {
				leaf.logRecord.Attributes = replaceInboundFixtureAttribute(leaf.logRecord.Attributes, "event.name", otlpClassifierStringAttribute("Event.Name", "codex.user_prompt"))
				leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf, source := inboundFixtureLeafForMatch(t, match)
			test.mutate(&leaf)
			result, err := classifier.classify(leaf, source)
			if err != nil || result.identityState != otlpInboundIdentityUnsupported || result.matchCount != 0 {
				t.Fatalf("classification = %+v err=%v", result, err)
			}
		})
	}
}

func TestOTLPInboundClassifierTypedAttributeFaultsAcrossSignals(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	tests := []struct {
		name     string
		matchID  string
		location observability.InboundLocation
		key      string
	}{
		{name: "log leaf", matchID: "otlp.codex.user_prompt.v1.log.model.request", location: observability.InboundLocationLeafAttribute, key: "event.name"},
		{name: "span leaf", matchID: "otlp.genai.span.operation.v1.span.workflow.run", location: observability.InboundLocationLeafAttribute, key: "gen_ai.operation.name"},
		{name: "metric point", matchID: "otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage", location: observability.InboundLocationMetricPointAttribute, key: "type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			match, ok := classifier.catalog.Match(test.matchID)
			if !ok {
				t.Fatalf("match %q missing", test.matchID)
			}
			for _, fault := range []string{"duplicate", "wrong_arm"} {
				t.Run(fault, func(t *testing.T) {
					leaf, source := inboundFixtureLeafForMatch(t, match)
					index, ok := inboundAttributeIndex(leaf, test.location)
					if !ok {
						t.Fatal("fixture attribute index missing")
					}
					delete(index.values, test.key)
					if fault == "duplicate" {
						index.duplicates[test.key] = struct{}{}
					} else {
						index.values[test.key] = &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}
					}
					setInboundFixtureIndex(&leaf, test.location, index)
					result, err := classifier.classify(leaf, source)
					if err != nil || result.identityState != otlpInboundIdentityUnsupported || result.matchCount != 0 {
						t.Fatalf("classification = %+v err=%v", result, err)
					}
				})
			}
		})
	}
}

func TestOTLPInboundClassifierWorkflowDiscriminatorIsExact(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.genai.span.operation.v1.span.workflow.run")
	if !ok {
		t.Fatal("workflow match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	result, err := classifier.classify(leaf, source)
	if err != nil || result.identityState != otlpInboundIdentityMatched || result.match.ID() != match.ID() {
		t.Fatalf("workflow result = %+v err=%v", result, err)
	}
	leaf.span.Attributes = replaceInboundFixtureAttribute(
		leaf.span.Attributes,
		"gen_ai.workflow.name",
		otlpClassifierStringAttribute("Gen_AI.Workflow.Name", "fixture"),
	)
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.span.Attributes)
	result, err = classifier.classify(leaf, source)
	if err != nil || result.identityState != otlpInboundIdentityUnsupported {
		t.Fatalf("case-folded workflow result = %+v err=%v", result, err)
	}
}

func TestOTLPInboundClassifierNativeTerminalityAndSelfEcho(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.native.log.v8.log.model.request")
	if !ok {
		t.Fatal("native model-request match missing")
	}
	leaf, source := inboundFixtureLeafForMatch(t, match)
	setInboundFixtureAttribute(leaf.logRecord, classifier.catalog.WireContract().ForwardInstanceKey, inboundClassifierTestInstance)
	leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
	leaf.logRecord.Body = inboundProjectedLogBody(t, leaf)
	result, err := classifier.classify(leaf, source)
	if err != nil || result.shape != observability.InboundShapeNativeExact ||
		result.identityState != otlpInboundIdentityMatched || !result.echoRecognized || !result.selfEchoCandidate {
		t.Fatalf("self result = %+v err=%v", result, err)
	}

	other, otherSource := inboundFixtureLeafForMatch(t, match)
	setInboundFixtureAttribute(other.logRecord, classifier.catalog.WireContract().ForwardInstanceKey, "other-instance")
	other.leafAttributes = newOTLPTypedAttributeIndex(other.logRecord.Attributes)
	other.logRecord.Body = inboundProjectedLogBody(t, other)
	otherResult, err := classifier.classify(other, otherSource)
	if err != nil || otherResult.identityState != otlpInboundIdentityMatched ||
		!otherResult.echoRecognized || otherResult.selfEchoCandidate {
		t.Fatalf("other result = %+v err=%v", otherResult, err)
	}

	malformed, _ := inboundFixtureLeafForMatch(t, match)
	delete(malformed.leafAttributes.values, classifier.catalog.WireContract().ForwardDestinationKey)
	malformed.logRecord.Attributes = append(malformed.logRecord.Attributes,
		otlpClassifierStringAttribute("event.name", "codex.user_prompt"))
	malformed.leafAttributes = newOTLPTypedAttributeIndex(malformed.logRecord.Attributes)
	delete(malformed.leafAttributes.values, classifier.catalog.WireContract().ForwardDestinationKey)
	malformedResult, err := classifier.classify(malformed, "codex")
	if err != nil || malformedResult.shape != observability.InboundShapeNativeMalformed ||
		malformedResult.identityState != otlpInboundIdentityNativeMalformed || malformedResult.matchCount != 0 {
		t.Fatalf("malformed result = %+v err=%v", malformedResult, err)
	}

	wrongArm, wrongArmSource := inboundFixtureLeafForMatch(t, match)
	wrongArm.leafAttributes.values["defenseclaw.bucket"] = &commonpb.AnyValue{
		Value: &commonpb.AnyValue_BoolValue{BoolValue: true},
	}
	wrongArmResult, err := classifier.classify(wrongArm, wrongArmSource)
	if err != nil || wrongArmResult.shape != observability.InboundShapeNativeMalformed ||
		wrongArmResult.identityState != otlpInboundIdentityNativeMalformed {
		t.Fatalf("wrong-arm native result = %+v err=%v", wrongArmResult, err)
	}
}

func TestOTLPInboundClassifierNonReversibleMetricEchoUsesGeneratedWireIdentity(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	wire := classifier.catalog.WireContract()
	point := &metricspb.HistogramDataPoint{}
	resourceAttributes := []*commonpb.KeyValue{
		otlpClassifierStringAttribute(wire.SemanticInstanceKey, "original-instance"),
		otlpClassifierStringAttribute(wire.ForwardInstanceKey, inboundClassifierTestInstance),
		otlpClassifierStringAttribute(wire.ForwardDestinationKey, "loopback"),
		otlpClassifierIntAttribute(wire.ForwardHopCountKey, 1),
	}
	leaf := otlpDecodedLeaf{
		signal: otelSignalMetrics,
		resource: otlpTypedResourceContext{
			schemaURL: wire.ResourceSchemaURL, attributes: newOTLPTypedAttributeIndex(resourceAttributes),
		},
		scope: otlpTypedScopeContext{name: wire.ScopeName, schemaURL: wire.ScopeSchemaURL},
		metric: &metricspb.Metric{
			Name: "gen_ai.client.operation.duration",
			Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{point}}},
		},
		metricShape: otlpTypedMetricHistogram, histogramPoint: point,
		metricPointAttributes: newOTLPTypedAttributeIndex(nil),
	}
	result, err := classifier.classify(leaf, "fixture-source")
	if err != nil || result.shape != observability.InboundShapeNativeExact ||
		result.identityState != otlpInboundIdentityUnsupported || !result.echoRecognized ||
		!result.selfEchoCandidate || result.echoRecognizer.Family() != "metric.gen_ai.client.operation.duration" {
		t.Fatalf("histogram echo result = %+v err=%v", result, err)
	}
	setInboundFixtureResourceAttribute(&leaf, wire.ForwardInstanceKey, "other-instance")
	result, err = classifier.classify(leaf, "fixture-source")
	if err != nil || !result.echoRecognized || result.selfEchoCandidate {
		t.Fatalf("other histogram result = %+v err=%v", result, err)
	}
}

func TestOTLPInboundClassifierProjectedStructureAloneIsTerminalMalformed(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	for name, body := range map[string]string{
		"minimal structure":    `{"schema_version":1,"projection":{}}`,
		"wrong nested shape":   `{"schema_version":1,"projection":"raw"}`,
		"duplicate projection": `{"schema_version":1,"projection":{},"projection":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			leaf := otlpDecodedLeaf{
				signal: otelSignalLogs,
				logRecord: &logspb.LogRecord{
					Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: body}},
					Attributes: []*commonpb.KeyValue{
						otlpClassifierStringAttribute("event.name", "codex.user_prompt"),
					},
				},
			}
			leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
			result, err := classifier.classify(leaf, "codex")
			if err != nil || result.shape != observability.InboundShapeNativeMalformed ||
				result.identityState != otlpInboundIdentityNativeMalformed || result.matchCount != 0 {
				t.Fatalf("projected-only result = %+v err=%v", result, err)
			}
		})
	}
}

func TestOTLPInboundClassifierRejectsNonExactProjectedLogEnvelope(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.native.log.v8.log.model.request")
	if !ok {
		t.Fatal("native model-request match missing")
	}
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown top-level member", mutate: func(wire map[string]any) { wire["unknown"] = true }},
		{name: "wrong body bucket", mutate: func(wire map[string]any) { wire["bucket"] = "diagnostic" }},
		{name: "log span name present", mutate: func(wire map[string]any) { wire["span_name"] = "" }},
		{name: "empty optional action", mutate: func(wire map[string]any) { wire["action"] = "" }},
		{name: "null optional action", mutate: func(wire map[string]any) { wire["action"] = nil }},
		{name: "invalid optional severity", mutate: func(wire map[string]any) { wire["severity"] = "WARN" }},
		{name: "projection wrong shape", mutate: func(wire map[string]any) { wire["projection"] = "raw" }},
		{name: "projection wrong field type", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["failure_count"] = "zero"
		}},
		{name: "projection unknown member", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["unknown"] = true
		}},
		{name: "projection missing member", mutate: func(wire map[string]any) {
			delete(wire["projection"].(map[string]any), "removed_fields")
		}},
		{name: "raw profile mismatch", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["redaction_profile"] = "strict"
		}},
		{name: "raw action count", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["transformed_fields"] = 1
		}},
		{name: "inspected none profile", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["state"] = "inspected"
		}},
		{name: "inspected failure", mutate: func(wire map[string]any) {
			projection := wire["projection"].(map[string]any)
			projection["redaction_profile"] = "strict"
			projection["state"] = "inspected"
			projection["failure_count"] = 1
		}},
		{name: "transformed without action", mutate: func(wire map[string]any) {
			projection := wire["projection"].(map[string]any)
			projection["redaction_profile"] = "strict"
			projection["state"] = "transformed"
		}},
		{name: "transformed with failure", mutate: func(wire map[string]any) {
			projection := wire["projection"].(map[string]any)
			projection["redaction_profile"] = "strict"
			projection["state"] = "transformed"
			projection["transformed_fields"] = 1
			projection["failure_count"] = 1
		}},
		{name: "oversize exceeds transformed", mutate: func(wire map[string]any) {
			projection := wire["projection"].(map[string]any)
			projection["redaction_profile"] = "strict"
			projection["state"] = "transformed"
			projection["transformed_fields"] = 1
			projection["oversize_fields"] = 2
		}},
		{name: "unexpected failures truncation", mutate: func(wire map[string]any) {
			wire["projection"].(map[string]any)["failures_truncated"] = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf, source := inboundFixtureLeafForMatch(t, match)
			mutateInboundProjectedLogBody(t, &leaf, test.mutate)
			result, err := classifier.classify(leaf, source)
			if err != nil || result.shape != observability.InboundShapeNativeMalformed ||
				result.identityState != otlpInboundIdentityNativeMalformed || result.matchCount != 0 {
				t.Fatalf("classification = %+v err=%v", result, err)
			}
		})
	}
}

func TestOTLPInboundClassifierAcceptsRealProjectedLogWithOptionalEnvelope(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	timestamp := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	observedAt := timestamp.Add(time.Second)
	severity := observability.SeverityInfo
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp:  timestamp,
		ObservedAt: &observedAt,
		RecordID:   "real-projected-log",
		Identity: observability.EventIdentity{
			Bucket: observability.BucketDiagnostic,
			Signal: observability.SignalLogs,
			Name:   "diagnostic.message",
		},
		Severity:  &severity,
		LogLevel:  observability.LogLevelInfo,
		Source:    observability.SourceGateway,
		Connector: "codex",
		Action:    "route_test",
		Phase:     "delivery",
		Outcome:   observability.OutcomeCompleted,
		Provenance: observability.Provenance{
			Producer: "gateway", BinaryVersion: "v8",
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      1,
		},
		Body:         map[string]any{"message": "projected"},
		FieldClasses: map[string]observability.FieldClass{"/message": observability.FieldClassMetadata},
	})
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := redaction.BuiltInProfile(redaction.ProfileNone)
	if !ok {
		t.Fatal("none profile missing")
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatalf("Project() error = %v", err)
	}
	encoded, err := projection.Bytes()
	if err != nil {
		t.Fatalf("projection bytes: %v", err)
	}
	wire := classifier.catalog.WireContract()
	attributes := []*commonpb.KeyValue{
		otlpClassifierStringAttribute(wire.RecordIDKey, "real-projected-log"),
		otlpClassifierStringAttribute("defenseclaw.bucket", string(observability.BucketDiagnostic)),
		otlpClassifierStringAttribute("defenseclaw.signal", string(observability.SignalLogs)),
		otlpClassifierStringAttribute("defenseclaw.event.name", "diagnostic.message"),
		otlpClassifierStringAttribute(wire.ForwardInstanceKey, inboundClassifierTestInstance),
		otlpClassifierStringAttribute(wire.ForwardDestinationKey, "test-destination"),
		otlpClassifierIntAttribute(wire.ForwardHopCountKey, 1),
	}
	leaf := otlpDecodedLeaf{
		signal: otelSignalLogs,
		resource: otlpTypedResourceContext{attributes: newOTLPTypedAttributeIndex([]*commonpb.KeyValue{
			otlpClassifierStringAttribute(wire.SemanticInstanceKey, "original-instance"),
		})},
		logRecord: &logspb.LogRecord{
			Body:       &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(encoded)}},
			Attributes: attributes,
		},
		leafAttributes: newOTLPTypedAttributeIndex(attributes),
	}
	result, err := classifier.classify(leaf, "codex")
	if err != nil || result.shape != observability.InboundShapeNativeExact ||
		result.identityState != otlpInboundIdentityMatched ||
		result.match.ID() != "otlp.native.log.v8.log.diagnostic.message" || !result.selfEchoCandidate {
		t.Fatalf("real projected classification = %+v err=%v", result, err)
	}
}

func mustOTLPInboundClassifierV8(t *testing.T) otlpInboundClassifierV8 {
	t.Helper()
	classifier, err := newOTLPInboundClassifierV8(inboundClassifierTestInstance)
	if err != nil {
		t.Fatalf("newOTLPInboundClassifierV8() error = %v", err)
	}
	return classifier
}

func allInboundCatalogMatches(t *testing.T, catalog observability.InboundCatalog) []observability.InboundMatch {
	t.Helper()
	byID := make(map[string]observability.InboundMatch)
	for _, signal := range observability.Signals() {
		for _, source := range []string{"codex", "claudecode", "fixture-source"} {
			for _, match := range catalog.Matches(signal, source) {
				byID[match.ID()] = match
			}
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]observability.InboundMatch, len(ids))
	for index, id := range ids {
		result[index] = byID[id]
	}
	return result
}

func inboundFixtureLeafForMatch(t *testing.T, match observability.InboundMatch) (otlpDecodedLeaf, string) {
	t.Helper()
	leaf := newInboundFixtureLeaf(match.Signal())
	for _, predicate := range match.Predicates() {
		applyInboundFixturePredicate(t, &leaf, predicate)
	}
	finalizeInboundFixtureLeaf(t, &leaf)
	sources := match.Sources()
	if len(sources) == 0 {
		t.Fatal("match has no authenticated source")
	}
	source := sources[0]
	if source == "any_authenticated" {
		source = "fixture-source"
	}
	return leaf, source
}

func newInboundFixtureLeaf(signal observability.Signal) otlpDecodedLeaf {
	switch signal {
	case observability.SignalLogs:
		return otlpDecodedLeaf{signal: otelSignalLogs, logRecord: &logspb.LogRecord{}}
	case observability.SignalTraces:
		return otlpDecodedLeaf{signal: otelSignalTraces, span: &tracepb.Span{
			TraceId: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			SpanId:  []byte{1, 0, 0, 0, 0, 0, 0, 1}, StartTimeUnixNano: 1, EndTimeUnixNano: 2,
		}}
	case observability.SignalMetrics:
		point := &metricspb.NumberDataPoint{}
		return otlpDecodedLeaf{
			signal: otelSignalMetrics, metric: &metricspb.Metric{}, metricShape: otlpTypedMetricGauge,
			numberPoint: point,
		}
	default:
		return otlpDecodedLeaf{}
	}
}

func applyInboundFixturePredicate(t *testing.T, leaf *otlpDecodedLeaf, predicate observability.InboundPredicate) {
	t.Helper()
	if predicate.Operator() == observability.InboundPredicateAbsent {
		return
	}
	if _, ok := inboundFixtureAttributeSlice(leaf, predicate.Location()); ok {
		if predicate.Operator() == observability.InboundPredicateProjectedRecordJSON {
			return
		}
		var attribute *commonpb.KeyValue
		switch predicate.ValueType() {
		case observability.InboundValueString:
			value := "present"
			if values := predicate.Values(); len(values) > 0 {
				value, _ = values[0].StringValue()
			}
			attribute = otlpClassifierStringAttribute(predicate.Key(), value)
		case observability.InboundValueInt64:
			value := int64(1)
			if predicate.Operator() != observability.InboundPredicateUint32Max {
				if values := predicate.Values(); len(values) > 0 {
					value, _ = values[0].Int64Value()
				}
			}
			attribute = otlpClassifierIntAttribute(predicate.Key(), value)
		default:
			t.Fatalf("unsupported fixture attribute predicate type %q", predicate.ValueType())
		}
		appendInboundFixtureAttribute(leaf, predicate.Location(), attribute)
		return
	}
	if predicate.Operator() == observability.InboundPredicateProjectedRecordJSON ||
		predicate.Operator() == observability.InboundPredicateValidEndedSpan {
		return
	}
	value := "present"
	if values := predicate.Values(); len(values) > 0 {
		value, _ = values[0].StringValue()
	}
	switch predicate.Location() {
	case observability.InboundLocationInstrumentName:
		leaf.metric.Name = value
	case observability.InboundLocationMetricPoint:
		setInboundFixtureMetricShape(leaf, value)
	case observability.InboundLocationResourceSchemaURL:
		leaf.resource.schemaURL = value
	case observability.InboundLocationScopeName:
		leaf.scope.name = value
	case observability.InboundLocationScopeSchemaURL:
		leaf.scope.schemaURL = value
	case observability.InboundLocationSpan:
		if predicate.Key() != "$span_name" {
			t.Fatalf("unsupported span structural predicate %q", predicate.Key())
		}
		leaf.span.Name = value
	default:
		t.Fatalf("unsupported fixture structural predicate %q/%q", predicate.Location(), predicate.Key())
	}
}

func finalizeInboundFixtureLeaf(t *testing.T, leaf *otlpDecodedLeaf) {
	t.Helper()
	leaf.resource.attributes = newOTLPTypedAttributeIndex(inboundFixtureResourceAttributes(leaf))
	leaf.scope.attributes = newOTLPTypedAttributeIndex(nil)
	switch leaf.signal {
	case otelSignalLogs:
		leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.logRecord.Attributes)
		for _, predicateMatch := range []string{"defenseclaw.record.id", "defenseclaw.bucket", "defenseclaw.signal", "defenseclaw.event.name"} {
			if _, state := leaf.leafAttributes.lookup(predicateMatch); state == otlpTypedAttributeUnique {
				leaf.logRecord.Body = inboundProjectedLogBody(t, *leaf)
				break
			}
		}
	case otelSignalTraces:
		leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.span.Attributes)
	case otelSignalMetrics:
		leaf.metricPointAttributes = newOTLPTypedAttributeIndex(inboundFixtureMetricAttributes(leaf))
	}
}

func inboundFixtureAttributeSlice(leaf *otlpDecodedLeaf, location observability.InboundLocation) ([]*commonpb.KeyValue, bool) {
	switch location {
	case observability.InboundLocationResourceAttribute:
		return inboundFixtureResourceAttributes(leaf), true
	case observability.InboundLocationLeafAttribute:
		if leaf.logRecord != nil {
			return leaf.logRecord.Attributes, true
		}
		if leaf.span != nil {
			return leaf.span.Attributes, true
		}
	case observability.InboundLocationMetricPointAttribute:
		return inboundFixtureMetricAttributes(leaf), leaf.metric != nil
	}
	return nil, false
}

func appendInboundFixtureAttribute(leaf *otlpDecodedLeaf, location observability.InboundLocation, attribute *commonpb.KeyValue) {
	switch location {
	case observability.InboundLocationResourceAttribute:
		attributes := append(inboundFixtureResourceAttributes(leaf), attribute)
		setInboundFixtureResourceAttributes(leaf, attributes)
	case observability.InboundLocationLeafAttribute:
		if leaf.logRecord != nil {
			leaf.logRecord.Attributes = append(leaf.logRecord.Attributes, attribute)
		} else {
			leaf.span.Attributes = append(leaf.span.Attributes, attribute)
		}
	case observability.InboundLocationMetricPointAttribute:
		attributes := append(inboundFixtureMetricAttributes(leaf), attribute)
		setInboundFixtureMetricAttributes(leaf, attributes)
	}
}

func inboundFixtureResourceAttributes(leaf *otlpDecodedLeaf) []*commonpb.KeyValue {
	return leaf.resource.attributesToFixture()
}

func (context otlpTypedResourceContext) attributesToFixture() []*commonpb.KeyValue {
	result := make([]*commonpb.KeyValue, 0, len(context.attributes.values))
	for _, key := range context.attributes.keys() {
		value, state := context.attributes.lookup(key)
		if state == otlpTypedAttributeUnique {
			result = append(result, &commonpb.KeyValue{Key: key, Value: value})
		}
	}
	return result
}

func setInboundFixtureResourceAttributes(leaf *otlpDecodedLeaf, attributes []*commonpb.KeyValue) {
	leaf.resource.attributes = newOTLPTypedAttributeIndex(attributes)
}

func inboundFixtureMetricAttributes(leaf *otlpDecodedLeaf) []*commonpb.KeyValue {
	switch leaf.metricShape {
	case otlpTypedMetricGauge, otlpTypedMetricSum:
		return leaf.numberPoint.GetAttributes()
	case otlpTypedMetricHistogram:
		return leaf.histogramPoint.GetAttributes()
	case otlpTypedMetricExponentialHistogram:
		return leaf.exponentialHistogram.GetAttributes()
	case otlpTypedMetricSummary:
		return leaf.summaryPoint.GetAttributes()
	default:
		return nil
	}
}

func setInboundFixtureMetricAttributes(leaf *otlpDecodedLeaf, attributes []*commonpb.KeyValue) {
	switch leaf.metricShape {
	case otlpTypedMetricGauge, otlpTypedMetricSum:
		leaf.numberPoint.Attributes = attributes
	case otlpTypedMetricHistogram:
		leaf.histogramPoint.Attributes = attributes
	case otlpTypedMetricExponentialHistogram:
		leaf.exponentialHistogram.Attributes = attributes
	case otlpTypedMetricSummary:
		leaf.summaryPoint.Attributes = attributes
	}
}

func setInboundFixtureMetricShape(leaf *otlpDecodedLeaf, shape string) {
	attributes := inboundFixtureMetricAttributes(leaf)
	leaf.numberPoint = nil
	leaf.histogramPoint = nil
	leaf.exponentialHistogram = nil
	leaf.summaryPoint = nil
	switch shape {
	case "gauge":
		point := &metricspb.NumberDataPoint{Attributes: attributes}
		leaf.metricShape, leaf.numberPoint = otlpTypedMetricGauge, point
		leaf.metric.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{point}}}
	case "sum", "sum_delta", "sum_delta_monotonic":
		point := &metricspb.NumberDataPoint{Attributes: attributes}
		sum := &metricspb.Sum{DataPoints: []*metricspb.NumberDataPoint{point}}
		if shape != "sum" {
			sum.AggregationTemporality = metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
		}
		sum.IsMonotonic = shape == "sum_delta_monotonic"
		leaf.metricShape, leaf.numberPoint = otlpTypedMetricSum, point
		leaf.metric.Data = &metricspb.Metric_Sum{Sum: sum}
	case "histogram":
		point := &metricspb.HistogramDataPoint{Attributes: attributes}
		leaf.metricShape, leaf.histogramPoint = otlpTypedMetricHistogram, point
		leaf.metric.Data = &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{point}}}
	default:
		point := &metricspb.SummaryDataPoint{Attributes: attributes}
		leaf.metricShape, leaf.summaryPoint = otlpTypedMetricSummary, point
		leaf.metric.Data = &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{point}}}
	}
}

func mutateFirstFiniteInboundPredicate(match observability.InboundMatch, leaf *otlpDecodedLeaf) bool {
	for _, predicate := range match.Predicates() {
		if predicate.Operator() != observability.InboundPredicateEquals &&
			predicate.Operator() != observability.InboundPredicateOneOf {
			continue
		}
		if index, ok := inboundAttributeIndex(*leaf, predicate.Location()); ok {
			value, state := index.lookup(predicate.Key())
			if state != otlpTypedAttributeUnique {
				return false
			}
			index.values[predicate.Key()] = incompatibleInboundFixtureValue(value)
			setInboundFixtureIndex(leaf, predicate.Location(), index)
			return true
		}
		switch predicate.Location() {
		case observability.InboundLocationInstrumentName:
			leaf.metric.Name = "unsupported"
		case observability.InboundLocationMetricPoint:
			setInboundFixtureMetricShape(leaf, "unsupported")
			leaf.metricPointAttributes = newOTLPTypedAttributeIndex(nil)
		case observability.InboundLocationResourceSchemaURL:
			leaf.resource.schemaURL = "unsupported"
		case observability.InboundLocationScopeName:
			leaf.scope.name = "unsupported"
		case observability.InboundLocationScopeSchemaURL:
			leaf.scope.schemaURL = "unsupported"
		case observability.InboundLocationSpan:
			if predicate.Key() != "$span_name" {
				continue
			}
			leaf.span.Name = "unsupported"
		default:
			continue
		}
		return true
	}
	return false
}

func removeFirstRequiredInboundPredicate(match observability.InboundMatch, leaf *otlpDecodedLeaf) bool {
	for _, predicate := range match.Predicates() {
		if predicate.Operator() == observability.InboundPredicateAbsent {
			continue
		}
		if index, ok := inboundAttributeIndex(*leaf, predicate.Location()); ok {
			delete(index.values, predicate.Key())
			delete(index.duplicates, predicate.Key())
			setInboundFixtureIndex(leaf, predicate.Location(), index)
			return true
		}
		switch predicate.Location() {
		case observability.InboundLocationInstrumentName:
			leaf.metric.Name = ""
		case observability.InboundLocationMetricPoint:
			setInboundFixtureMetricShape(leaf, "unsupported")
			leaf.metricPointAttributes = newOTLPTypedAttributeIndex(nil)
		case observability.InboundLocationResourceSchemaURL:
			leaf.resource.schemaURL = ""
		case observability.InboundLocationScopeName:
			leaf.scope.name = ""
		case observability.InboundLocationScopeSchemaURL:
			leaf.scope.schemaURL = ""
		case observability.InboundLocationLogBody:
			leaf.logRecord.Body = nil
		case observability.InboundLocationSpan:
			if predicate.Key() == "$span_name" {
				leaf.span.Name = ""
			} else {
				leaf.span.EndTimeUnixNano = 0
			}
		default:
			continue
		}
		return true
	}
	return false
}

func setInboundFixtureIndex(leaf *otlpDecodedLeaf, location observability.InboundLocation, index otlpTypedAttributeIndex) {
	switch location {
	case observability.InboundLocationResourceAttribute:
		leaf.resource.attributes = index
	case observability.InboundLocationLeafAttribute:
		leaf.leafAttributes = index
	case observability.InboundLocationMetricPointAttribute:
		leaf.metricPointAttributes = index
	}
}

func incompatibleInboundFixtureValue(value *commonpb.AnyValue) *commonpb.AnyValue {
	if _, ok := value.GetValue().(*commonpb.AnyValue_StringValue); ok {
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "unsupported"}}
	}
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: -1}}
}

func inboundProjectedLogBody(t *testing.T, leaf otlpDecodedLeaf) *commonpb.AnyValue {
	t.Helper()
	recordID, _ := leaf.leafAttributes.stringValue("defenseclaw.record.id")
	bucket, _ := leaf.leafAttributes.stringValue("defenseclaw.bucket")
	signal, _ := leaf.leafAttributes.stringValue("defenseclaw.signal")
	eventName, _ := leaf.leafAttributes.stringValue("defenseclaw.event.name")
	wire := map[string]any{
		"schema_version":         observability.CurrentRecordSchemaVersion,
		"bucket_catalog_version": observability.CurrentBucketCatalogVersion,
		"timestamp":              "2026-07-06T00:00:00Z", "record_id": recordID,
		"bucket": bucket, "signal": signal, "event_name": eventName,
		"source": "gateway", "mandatory": false,
		"correlation": map[string]any{}, "provenance": map[string]any{},
		"body": map[string]any{"fixture": true}, "field_classes": map[string]any{},
		"projection": map[string]any{
			"redaction_profile": "none", "detector_catalog_version": 1, "state": "raw",
			"transformed_fields": 0, "removed_fields": 0, "oversize_fields": 0,
			"failure_count": 0, "failures_truncated": false,
		},
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(encoded)}}
}

func mutateInboundProjectedLogBody(t *testing.T, leaf *otlpDecodedLeaf, mutate func(map[string]any)) {
	t.Helper()
	text, ok := inboundLogBodyString(leaf.logRecord.GetBody())
	if !ok {
		t.Fatal("fixture log body is not a string")
	}
	var wire map[string]any
	if err := json.Unmarshal([]byte(text), &wire); err != nil {
		t.Fatal(err)
	}
	mutate(wire)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	leaf.logRecord.Body = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(encoded)}}
}

func otlpClassifierStringAttribute(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}}
}

func otlpClassifierIntAttribute(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: key, Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: value}}}
}

func replaceInboundFixtureAttribute(attributes []*commonpb.KeyValue, key string, replacement *commonpb.KeyValue) []*commonpb.KeyValue {
	result := append([]*commonpb.KeyValue(nil), attributes...)
	for index, attribute := range result {
		if attribute != nil && attribute.GetKey() == key {
			result[index] = replacement
			return result
		}
	}
	return append(result, replacement)
}

func setInboundFixtureAttribute(record *logspb.LogRecord, key, value string) {
	record.Attributes = replaceInboundFixtureAttribute(record.Attributes, key, otlpClassifierStringAttribute(key, value))
}

func setInboundFixtureResourceAttribute(leaf *otlpDecodedLeaf, key, value string) {
	attributes := replaceInboundFixtureAttribute(inboundFixtureResourceAttributes(leaf), key, otlpClassifierStringAttribute(key, value))
	setInboundFixtureResourceAttributes(leaf, attributes)
}

func errorsIsInboundClassifier(err error) bool { return errors.Is(err, errOTLPInboundClassifierV8) }
