// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func FuzzRouteSelectorValidationAndMatching(f *testing.F) {
	f.Add(byte(0), byte(0), byte(0), byte(0), byte(0), byte(0), byte(0), byte(0))
	f.Add(byte(1), byte(2), byte(1), byte(2), byte(1), byte(4), byte(1), byte(4))
	f.Add(byte(3), byte(3), byte(3), byte(3), byte(3), byte(1), byte(0), byte(3))
	f.Add(byte(5), byte(5), byte(5), byte(5), byte(5), byte(6), byte(2), byte(2))

	f.Fuzz(func(
		t *testing.T,
		bucketMode, sourceMode, connectorMode, actionMode, eventMode, severityMode, actualConnectorMode, actualSeverityMode byte,
	) {
		selector := observability.Selector{
			Buckets:     fuzzBuckets(bucketMode),
			Sources:     fuzzSources(sourceMode),
			Connectors:  fuzzStrings(connectorMode, "openclaw", "other"),
			Actions:     fuzzActions(actionMode),
			EventNames:  fuzzEventNames(eventMode),
			MinSeverity: fuzzSeverity(severityMode, true),
		}
		sourceSelector := &config.ObservabilityV8SelectorSource{
			Buckets: selector.Buckets, Sources: selector.Sources, Connectors: selector.Connectors,
			Actions: selector.Actions, EventNames: selector.EventNames, MinSeverity: selector.MinSeverity,
		}
		source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "fuzz-console", Kind: config.ObservabilityV8DestinationConsole,
			Routes: []config.ObservabilityV8RouteSource{
				{Name: "selected", Signals: []observability.Signal{observability.SignalLogs}, Selector: sourceSelector},
				{Name: "drop-rest", Signals: []observability.Signal{observability.SignalLogs}, Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{"*"}}, Action: config.ObservabilityV8RouteDrop},
			},
		}}}

		selectorErr := selector.Validate()
		plan, compileErr := config.CompileObservabilityV8(source)
		if selectorErr != nil {
			if compileErr == nil {
				t.Fatal("compiler accepted a selector rejected by the shared taxonomy")
			}
			return
		}
		if compileErr != nil {
			t.Fatalf("compiler rejected a valid selector: %v", compileErr)
		}
		evaluator, err := New(plan)
		if err != nil {
			t.Fatalf("router rejected a compiled selector: %v", err)
		}

		connectors := []string{"openclaw", "", "other"}
		connector := connectors[int(actualConnectorMode)%len(connectors)]
		actualSeverity := fuzzSeverity(actualSeverityMode, false)
		metadata := findingMetadataWith(string(actualSeverity), connector)
		result, err := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
			return newRecordNoTest(metadata, admission)
		})
		if err != nil {
			t.Fatalf("selector evaluation failed: %v", err)
		}
		got := contains(deliveryNames(result.Deliveries()), "fuzz-console")
		want := fuzzSelectorOracle(selector, metadata)
		if got != want {
			t.Fatalf("selector match=%t, want %t for %+v", got, want, selector)
		}
		assertAtMostOncePerDestination(t, result.Deliveries())
	})
}

func fuzzBuckets(mode byte) []observability.Bucket {
	values := [][]observability.Bucket{
		nil,
		{observability.BucketSecurityFinding},
		{observability.BucketDiagnostic},
		{"*"},
		{observability.BucketSecurityFinding, observability.BucketDiagnostic},
		{"unknown.bucket"},
	}
	return values[int(mode)%len(values)]
}

func fuzzSources(mode byte) []observability.Source {
	values := [][]observability.Source{
		nil,
		{observability.SourceScanner},
		{observability.SourceGateway},
		{"*"},
		{observability.SourceScanner, observability.SourceGateway},
		{observability.SourceOperator},
	}
	return values[int(mode)%len(values)]
}

func fuzzStrings(mode byte, matching, different string) []string {
	values := [][]string{nil, {matching}, {different}, {"*"}, {matching, different}, {"*", matching}}
	return values[int(mode)%len(values)]
}

func fuzzActions(mode byte) []observability.ProducerKey {
	values := [][]observability.ProducerKey{
		nil, {"scan-finding"}, {"config-update"}, {"*"}, {"scan-finding", "config-update"}, {"*", "scan-finding"},
	}
	return values[int(mode)%len(values)]
}

func fuzzEventNames(mode byte) []observability.EventName {
	values := [][]observability.EventName{
		nil, {"finding.observed"}, {"diagnostic.message"}, {"*"}, {"finding.observed", "diagnostic.message"}, {"invalid event"},
	}
	return values[int(mode)%len(values)]
}

func fuzzSeverity(mode byte, allowEmpty bool) observability.Severity {
	values := []observability.Severity{
		observability.SeverityInfo, observability.SeverityLow, observability.SeverityMedium,
		observability.SeverityHigh, observability.SeverityCritical,
	}
	if allowEmpty {
		values = append([]observability.Severity{""}, values...)
		values = append(values, observability.Severity("INVALID"))
	}
	return values[int(mode)%len(values)]
}

func fuzzSelectorOracle(selector observability.Selector, metadata Metadata) bool {
	if !fuzzValueMatches(selector.Buckets, metadata.Identity().Bucket, observability.Bucket("*")) ||
		!fuzzValueMatches(selector.Sources, metadata.Source(), observability.Source("*")) ||
		!fuzzValueMatches(selector.Connectors, metadata.Connector(), "*") ||
		!fuzzValueMatches(selector.Actions, metadata.Action(), observability.ProducerKey("*")) ||
		!fuzzValueMatches(selector.EventNames, metadata.Identity().Name, observability.EventName("*")) {
		return false
	}
	if selector.MinSeverity == "" {
		return true
	}
	actual, present := metadata.Severity()
	minimumRank, minimumOK := observability.SeverityRank(selector.MinSeverity)
	actualRank, actualOK := observability.SeverityRank(actual)
	return present && minimumOK && actualOK && actualRank >= minimumRank
}

func fuzzValueMatches[T comparable](allowed []T, actual, wildcard T) bool {
	if len(allowed) == 0 {
		return true
	}
	var zero T
	if actual == zero {
		return false
	}
	for _, candidate := range allowed {
		if candidate == wildcard || candidate == actual {
			return true
		}
	}
	return false
}
