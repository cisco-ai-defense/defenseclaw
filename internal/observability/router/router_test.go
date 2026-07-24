// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestCollectionIsIndependentAndAdmissionPrecedesConstruction(t *testing.T) {
	falseValue, trueValue := false, true
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{Collect: config.ObservabilityV8CollectSource{
			Logs: &falseValue, Traces: &falseValue, Metrics: &falseValue,
		}},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketSecurityFinding: {Collect: config.ObservabilityV8CollectSource{Logs: &trueValue}},
			observability.BucketModelIO:         {Collect: config.ObservabilityV8CollectSource{Traces: &trueValue}},
			observability.BucketPlatformHealth:  {Collect: config.ObservabilityV8CollectSource{Metrics: &trueValue}},
		},
	})

	for _, test := range []struct {
		bucket observability.Bucket
		signal observability.Signal
		want   bool
	}{
		{observability.BucketSecurityFinding, observability.SignalLogs, true},
		{observability.BucketSecurityFinding, observability.SignalTraces, false},
		{observability.BucketSecurityFinding, observability.SignalMetrics, false},
		{observability.BucketModelIO, observability.SignalLogs, false},
		{observability.BucketModelIO, observability.SignalTraces, true},
		{observability.BucketModelIO, observability.SignalMetrics, false},
		{observability.BucketPlatformHealth, observability.SignalLogs, false},
		{observability.BucketPlatformHealth, observability.SignalTraces, false},
		{observability.BucketPlatformHealth, observability.SignalMetrics, true},
	} {
		if got := evaluator.Collected(test.bucket, test.signal); got != test.want {
			t.Errorf("Collected(%s, %s) = %t, want %t", test.bucket, test.signal, got, test.want)
		}
	}
	if evaluator.Collected("future.bucket", observability.SignalLogs) || evaluator.Collected(observability.BucketModelIO, "future") {
		t.Fatal("unknown collection key was enabled")
	}

	metadata := diagnosticMetadata()
	var calls atomic.Int64
	result, err := evaluator.Evaluate(metadata, func(Admission) (observability.Record, error) {
		calls.Add(1)
		return observability.Record{}, errors.New("must not be called")
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Admission() != AdmissionDrop || calls.Load() != 0 {
		t.Fatalf("disabled result = %s, builder calls = %d", result.Admission(), calls.Load())
	}
	if _, ok := result.Record(); ok || len(result.Deliveries()) != 0 {
		t.Fatal("dropped collection unexpectedly produced a record or delivery")
	}
}

func TestAdmissionMatrix(t *testing.T) {
	falseValue := false
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
			observability.BucketModelIO:            {Collect: config.ObservabilityV8CollectSource{Traces: &falseValue}},
			observability.BucketPlatformHealth:     {Collect: config.ObservabilityV8CollectSource{Metrics: &falseValue}},
		},
	})
	for _, test := range []struct {
		name     string
		metadata Metadata
		want     Admission
	}{
		{name: "enabled ordinary log", metadata: findingMetadata(), want: AdmissionOrdinary},
		{name: "disabled ordinary log", metadata: complianceMetadata(false), want: AdmissionDrop},
		{name: "disabled mandatory log", metadata: complianceMetadata(true), want: AdmissionFloor},
		{name: "disabled trace", metadata: traceMetadata(), want: AdmissionDrop},
		{name: "disabled metric", metadata: metricMetadata(), want: AdmissionDrop},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := evaluator.Admit(test.metadata)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("admission = %s, want %s", got, test.want)
			}
		})
	}
}

func TestMandatoryFloorDisabledMatrixAndNoOrdinaryDuplication(t *testing.T) {
	falseValue := false
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "remote-a", Kind: config.ObservabilityV8DestinationConsole},
			{Name: "remote-b", Kind: config.ObservabilityV8DestinationConsole},
		},
	})
	metadata := complianceMetadata(true)
	var admissionSeen Admission
	result, err := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		admissionSeen = admission
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Admission() != AdmissionFloor || admissionSeen != AdmissionFloor {
		t.Fatalf("floor admission = %s, builder saw %s", result.Admission(), admissionSeen)
	}
	deliveries := result.Deliveries()
	if len(deliveries) != 1 || deliveries[0].DestinationName != config.ObservabilityV8LocalDestinationName ||
		!deliveries[0].MandatoryFloor {
		t.Fatalf("floor deliveries = %+v", deliveries)
	}

	metadata = complianceMetadata(false)
	result, err = evaluator.Evaluate(metadata, func(Admission) (observability.Record, error) {
		return observability.Record{}, errors.New("disabled nonmandatory builder invoked")
	})
	if err != nil || result.Admission() != AdmissionDrop || len(result.Deliveries()) != 0 {
		t.Fatalf("nonmandatory disabled result = %+v, err = %v", result.Deliveries(), err)
	}

	enabled := mustEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "remote-a", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "remote-b", Kind: config.ObservabilityV8DestinationConsole},
	}})
	metadata = complianceMetadata(true)
	result, err = enabled.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Admission() != AdmissionOrdinary {
		t.Fatalf("enabled mandatory admission = %s", result.Admission())
	}
	want := []string{"local-sqlite", "remote-a", "remote-b"}
	if got := deliveryNames(result.Deliveries()); !reflect.DeepEqual(got, want) {
		t.Fatalf("ordinary mandatory destinations = %v, want %v", got, want)
	}
	for _, delivery := range result.Deliveries() {
		if delivery.MandatoryFloor {
			t.Fatalf("ordinary mandatory record used floor path: %+v", delivery)
		}
	}
}

func TestFloorAdmissionRequiresAuthenticatedMinimalRecord(t *testing.T) {
	falseValue := false
	disabled := mustEvaluator(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
		},
	})
	metadata := complianceMetadata(true)
	if _, err := disabled.Evaluate(metadata, func(Admission) (observability.Record, error) {
		// This record is legitimately mandatory but contains the ordinary body and
		// lacks the record-core floor-only authenticity marker.
		return newRecordNoTest(metadata, AdmissionOrdinary)
	}); err == nil {
		t.Fatal("floor admission accepted a full-body mandatory record")
	}

	enabled := mustEvaluator(t, nil)
	if _, err := enabled.Evaluate(metadata, func(Admission) (observability.Record, error) {
		return newRecordNoTest(metadata, AdmissionFloor)
	}); err == nil {
		t.Fatal("ordinary admission accepted a floor-only record")
	}
}

func TestOrdinaryMetadataCannotForgeMandatoryFloor(t *testing.T) {
	falseValue := false
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
			observability.BucketDiagnostic:         {Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
		},
		Destinations: []config.ObservabilityV8DestinationSource{{Name: "remote", Kind: config.ObservabilityV8DestinationConsole}},
	})
	severity := observability.SeverityInfo
	if _, err := NewMetadata(
		observability.EventIdentity{
			Bucket: observability.BucketComplianceActivity,
			Signal: observability.SignalLogs,
			Name:   "config.change.applied",
		},
		&severity,
		observability.SourceOperator,
		"",
		"config-update",
	); err == nil {
		t.Fatal("ordinary constructor accepted a log identity that could underreport mandatory status")
	}

	// A typed fact cannot grant the floor to a classification whose catalog row
	// has no matching mandatory rule.
	nonmandatory, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"diagnostic",
		observability.ClassificationContext{
			RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{
				ControlPlaneMutation: true,
				SQLiteFailure:        true,
			},
		},
		observability.SourceSystem,
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if nonmandatory.mandatory {
		t.Fatal("unregistered mandatory facts granted floor eligibility")
	}
	var calls atomic.Int64
	result, err := evaluator.Evaluate(nonmandatory, func(Admission) (observability.Record, error) {
		calls.Add(1)
		return observability.Record{}, errors.New("disabled forged-floor builder invoked")
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Admission() != AdmissionDrop || calls.Load() != 0 || len(result.Deliveries()) != 0 {
		t.Fatalf("forged floor result = %s, calls = %d, deliveries = %+v", result.Admission(), calls.Load(), result.Deliveries())
	}
}

func TestCapabilityDefaultsAndSignalSafety(t *testing.T) {
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "logs", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "metrics", Kind: config.ObservabilityV8DestinationPrometheus, Listen: "127.0.0.1:9464", Path: "/metrics"},
		{Name: "otlp", Kind: config.ObservabilityV8DestinationOTLP, Endpoint: "https://collector.example.com"},
	}})

	for _, test := range []struct {
		name     string
		metadata Metadata
		want     []string
	}{
		{name: "log", metadata: findingMetadata(), want: []string{"local-sqlite", "logs", "otlp"}},
		{name: "trace", metadata: traceMetadata(), want: []string{"otlp"}},
		{name: "metric", metadata: metricMetadata(), want: []string{"metrics", "otlp"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluator.Evaluate(test.metadata, func(admission Admission) (observability.Record, error) {
				return newRecord(t, test.metadata, admission), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := deliveryNames(result.Deliveries()); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("destinations = %v, want %v", got, test.want)
			}
			for _, delivery := range result.Deliveries() {
				if test.metadata.Identity().Signal != observability.SignalMetrics && delivery.RedactionProfile != "none" {
					t.Fatalf("content delivery profile = %q", delivery.RedactionProfile)
				}
				if test.metadata.Identity().Signal == observability.SignalMetrics && delivery.RedactionProfile != "" {
					t.Fatalf("metric delivery has redaction profile %q", delivery.RedactionProfile)
				}
			}
		})
	}
}

func TestAdvancedRoutesFirstMatchSelectorsAndDestinationFanout(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	catchAll := []observability.Bucket{"*"}
	diagnostic := []observability.Bucket{observability.BucketDiagnostic}
	security := []observability.Bucket{observability.BucketSecurityFinding}
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{
			Name: "drop-first", Kind: config.ObservabilityV8DestinationConsole,
			Routes: []config.ObservabilityV8RouteSource{
				{Name: "drop-diagnostic", Signals: logs, Selector: &config.ObservabilityV8SelectorSource{Buckets: diagnostic}, Action: config.ObservabilityV8RouteDrop},
				{Name: "send-all", Signals: logs, Selector: &config.ObservabilityV8SelectorSource{Buckets: catchAll}},
			},
		},
		{
			Name: "send-first", Kind: config.ObservabilityV8DestinationConsole,
			Routes: []config.ObservabilityV8RouteSource{
				{Name: "send-all", Signals: logs, Selector: &config.ObservabilityV8SelectorSource{Buckets: catchAll}},
				{Name: "drop-diagnostic", Signals: logs, Selector: &config.ObservabilityV8SelectorSource{Buckets: diagnostic}, Action: config.ObservabilityV8RouteDrop},
			},
		},
		{
			Name: "selected", Kind: config.ObservabilityV8DestinationConsole,
			Routes: []config.ObservabilityV8RouteSource{
				{
					Name: "exact", Signals: logs,
					Selector: &config.ObservabilityV8SelectorSource{
						Buckets: security, Sources: []observability.Source{observability.SourceGateway, observability.SourceScanner},
						Connectors: []string{"openclaw"}, Actions: []observability.ProducerKey{"scan-finding"},
						EventNames: []observability.EventName{"finding.observed"}, MinSeverity: observability.SeverityHigh,
					},
				},
				{Name: "drop-rest", Signals: logs, Selector: &config.ObservabilityV8SelectorSource{Buckets: catchAll}, Action: config.ObservabilityV8RouteDrop},
			},
		},
		{Name: "fanout", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{Signals: logs, Buckets: security}},
	}})

	diagnosticMetadata := diagnosticMetadata()
	result, err := evaluator.Evaluate(diagnosticMetadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, diagnosticMetadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := deliveryNames(result.Deliveries()), []string{"local-sqlite", "send-first"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostic first-match destinations = %v, want %v", got, want)
	}
	for _, delivery := range result.Deliveries() {
		if delivery.DestinationName == "send-first" && delivery.RouteName != "send-all" {
			t.Fatalf("wrong winning route: %+v", delivery)
		}
	}

	metadata := findingMetadata()
	result, err = evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"drop-first", "fanout", "local-sqlite", "selected", "send-first"}
	if got := deliveryNames(result.Deliveries()); !reflect.DeepEqual(got, want) {
		t.Fatalf("fanout destinations = %v, want %v", got, want)
	}
	assertAtMostOncePerDestination(t, result.Deliveries())

	metadata = findingMetadataWith("HIGH", "other")
	result, err = evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if contains(deliveryNames(result.Deliveries()), "selected") {
		t.Fatal("AND selector matched after one field differed")
	}

	metadata = findingMetadataWith("MEDIUM", "openclaw")
	result, err = evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if contains(deliveryNames(result.Deliveries()), "selected") {
		t.Fatal("minimum severity matched a lower value")
	}

}

func TestUnmatchedRouteAndDisabledDestinationProduceNoOptionalDelivery(t *testing.T) {
	falseValue := false
	logs := []observability.Signal{observability.SignalLogs}
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{
			Name: "unmatched", Kind: config.ObservabilityV8DestinationConsole,
			Routes: []config.ObservabilityV8RouteSource{{
				Name: "diagnostic-only", Signals: logs,
				Selector: &config.ObservabilityV8SelectorSource{Buckets: []observability.Bucket{observability.BucketDiagnostic}},
			}},
		},
		{Name: "disabled", Kind: config.ObservabilityV8DestinationConsole, Enabled: &falseValue},
	}})
	metadata := findingMetadata()
	result, err := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := deliveryNames(result.Deliveries()), []string{"local-sqlite"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("destinations = %v, want %v", got, want)
	}
}

func TestEvaluatorRejectsRouteIndexAndWildcardCatalogDrift(t *testing.T) {
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "remote", Kind: config.ObservabilityV8DestinationConsole,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshot := plan.Snapshot()
	var source config.ObservabilityV8EffectiveDestination
	for _, candidate := range snapshot.Destinations {
		if candidate.Name == "remote" {
			source = candidate
			break
		}
	}
	indexDrift := compileDestinationIndex(source)
	indexDrift.routes[0].index = 7
	if err := validateDestinationIndex(indexDrift); err == nil {
		t.Fatal("router accepted route index drift")
	}

	wildcardDrift := compileDestinationIndex(source)
	wildcardDrift.routes[0].selector.buckets = map[observability.Bucket]struct{}{
		observability.BucketDiagnostic: {},
	}
	if err := validateDestinationIndex(wildcardDrift); err == nil {
		t.Fatal("router accepted wildcard without the pinned catalog")
	}
}

func TestEvaluationRejectsInvalidOrMismatchedMetadataAndPropagatesBuilderError(t *testing.T) {
	evaluator := mustEvaluator(t, nil)
	metadata := findingMetadata()

	trace := traceMetadata()
	if _, err := NewMetadata(trace.Identity(), nil, "INVALID SOURCE", trace.Connector(), trace.Action()); err == nil {
		t.Fatal("invalid ordinary metadata was constructed")
	}

	wantErr := errors.New("builder failed")
	if _, err := evaluator.Evaluate(metadata, func(Admission) (observability.Record, error) {
		return observability.Record{}, wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("builder error = %v, want %v", err, wantErr)
	}

	if _, err := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		other := findingMetadataWith("HIGH", "other")
		return newRecord(t, other, admission), nil
	}); err == nil {
		t.Fatal("mismatched built record was accepted")
	}
	if _, err := evaluator.Evaluate(metadata, nil); err == nil {
		t.Fatal("nil builder was accepted for ordinary admission")
	}
}

func TestMetadataValidationErrorsAreValueSafe(t *testing.T) {
	const secret = "super-secret-token-9384"
	_, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"scan_finding",
		observability.ClassificationContext{RawSeverity: secret},
		observability.SourceScanner,
		"openclaw",
		"scan-finding",
	)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("classified severity error was not value-safe: %v", err)
	}

	_, err = NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"activity",
		observability.ClassificationContext{EventName: observability.EventName(secret), RawSeverity: "INFO"},
		observability.SourceOperator,
		"",
		"config-update",
	)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("classified identity error was not value-safe: %v", err)
	}

	_, err = NewMetadata(
		observability.EventIdentity{
			Bucket: observability.BucketModelIO,
			Signal: observability.SignalTraces,
			Name:   observability.EventName(secret),
		},
		nil,
		observability.SourceGateway,
		"openclaw",
		"",
	)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("ordinary identity error was not value-safe: %v", err)
	}
}

func TestEvaluatorAndResultsAreImmutableAndRaceSafe(t *testing.T) {
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "one", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "two", Kind: config.ObservabilityV8DestinationConsole},
	}}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := New(plan)
	if err != nil {
		t.Fatal(err)
	}

	// Mutation of source and detached plan views cannot alter the runtime index.
	source.Destinations[0].Name = "mutated-source"
	snapshot := plan.Snapshot()
	snapshot.Destinations[1].Name = "mutated-snapshot"
	snapshot.Destinations[1].Routes[0].Selector.Buckets[0] = observability.BucketDiagnostic

	metadata := findingMetadata()
	result, err := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		return newRecord(t, metadata, admission), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"local-sqlite", "one", "two"}
	if got := deliveryNames(result.Deliveries()); !reflect.DeepEqual(got, want) {
		t.Fatalf("destinations after external mutation = %v, want %v", got, want)
	}
	detached := result.Deliveries()
	detached[0].DestinationName = "mutated-result"
	if got := deliveryNames(result.Deliveries()); !reflect.DeepEqual(got, want) {
		t.Fatalf("destinations after result mutation = %v, want %v", got, want)
	}

	const goroutines = 32
	const evaluations = 50
	var wait sync.WaitGroup
	errorsFound := make(chan error, goroutines)
	for worker := 0; worker < goroutines; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < evaluations; iteration++ {
				got, evaluateErr := evaluator.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
					return newRecordNoTest(metadata, admission)
				})
				if evaluateErr != nil {
					errorsFound <- evaluateErr
					return
				}
				if names := deliveryNames(got.Deliveries()); !reflect.DeepEqual(names, want) {
					errorsFound <- fmt.Errorf("destinations = %v", names)
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for evaluateErr := range errorsFound {
		t.Error(evaluateErr)
	}
}

func TestMetadataSelectorValueORAndWildcardRequiresPresentField(t *testing.T) {
	selector := compiledSelector{
		sources:    setOf([]observability.Source{observability.SourceGateway, observability.SourceScanner}),
		connectors: setOf([]string{"*"}),
	}
	metadata := findingMetadata()
	if !selector.matches(metadata) {
		t.Fatal("OR and wildcard selector did not match")
	}
	metadata.connector = ""
	if selector.matches(metadata) {
		t.Fatal("wildcard matched an absent selected field")
	}
	severitySelector := compiledSelector{minSeverity: observability.SeverityHigh}
	if severitySelector.matches(traceMetadata()) {
		t.Fatal("minimum severity matched absent severity")
	}
}

func BenchmarkEvaluatorAdmitDisabled(b *testing.B) {
	falseValue := false
	evaluator := mustEvaluatorForBenchmark(b, &config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{Collect: config.ObservabilityV8CollectSource{Logs: &falseValue}},
	})
	metadata := findingMetadata()
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		admission, err := evaluator.Admit(metadata)
		if err != nil || admission != AdmissionDrop {
			b.Fatalf("admission = %s, err = %v", admission, err)
		}
	}
}

func mustEvaluator(t *testing.T, source *config.ObservabilityV8Source) *Evaluator {
	t.Helper()
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := New(plan)
	if err != nil {
		t.Fatal(err)
	}
	return evaluator
}

func mustEvaluatorForBenchmark(b *testing.B, source *config.ObservabilityV8Source) *Evaluator {
	b.Helper()
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		b.Fatal(err)
	}
	evaluator, err := New(plan)
	if err != nil {
		b.Fatal(err)
	}
	return evaluator
}

func findingMetadata() Metadata {
	return findingMetadataWith("HIGH", "openclaw")
}

func findingMetadataWith(rawSeverity, connector string) Metadata {
	metadata, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"scan_finding",
		observability.ClassificationContext{RawSeverity: rawSeverity},
		observability.SourceScanner,
		connector,
		"scan-finding",
	)
	if err != nil {
		panic(err)
	}
	return metadata
}

func complianceMetadata(mandatory bool) Metadata {
	metadata, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"activity",
		observability.ClassificationContext{
			Bucket:      observability.BucketComplianceActivity,
			EventName:   "config.change.applied",
			RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{
				ControlPlaneMutation: mandatory,
			},
		},
		observability.SourceOperator,
		"",
		"config-update",
	)
	if err != nil {
		panic(err)
	}
	return metadata
}

func diagnosticMetadata() Metadata {
	metadata, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"diagnostic",
		observability.ClassificationContext{RawSeverity: "INFO"},
		observability.SourceGateway,
		"openclaw",
		"",
	)
	if err != nil {
		panic(err)
	}
	return metadata
}

func traceMetadata() Metadata {
	metadata, err := NewMetadata(
		observability.EventIdentity{
			Bucket: observability.BucketModelIO,
			Signal: observability.SignalTraces,
			Name:   "span.model.chat",
		},
		nil,
		observability.SourceGateway,
		"openclaw",
		"",
	)
	if err != nil {
		panic(err)
	}
	return metadata
}

func metricMetadata() Metadata {
	metadata, err := NewMetadata(
		observability.EventIdentity{
			Bucket: observability.BucketPlatformHealth,
			Signal: observability.SignalMetrics,
			Name:   "defenseclaw.http.auth.failures",
		},
		nil,
		observability.SourceGateway,
		"",
		"",
	)
	if err != nil {
		panic(err)
	}
	return metadata
}

func newRecord(t *testing.T, metadata Metadata, admission Admission) observability.Record {
	t.Helper()
	record, err := newRecordNoTest(metadata, admission)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func newRecordNoTest(metadata Metadata, admission Admission) (observability.Record, error) {
	if metadata.identity.Signal == observability.SignalLogs {
		builder, err := observability.NewRecordBuilder(
			observability.ClockFunc(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "record-1", nil }),
		)
		if err != nil {
			return observability.Record{}, err
		}
		kind, key, context, err := classifiedLogResolution(metadata)
		if err != nil {
			return observability.Record{}, err
		}
		if admission == AdmissionFloor {
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind:          kind,
				ProducerKey:           key,
				ClassificationContext: context,
				Source:                metadata.source,
				Connector:             metadata.connector,
				Action:                string(metadata.action),
				Provenance:            observability.Provenance{Producer: "router-test", BinaryVersion: "v8", RegistrySchemaVersion: 1},
			})
		}
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind:          kind,
			ProducerKey:           key,
			ClassificationContext: context,
			Source:                metadata.source,
			Connector:             metadata.connector,
			Action:                string(metadata.action),
			Provenance:            observability.Provenance{Producer: "router-test", BinaryVersion: "v8", RegistrySchemaVersion: 1},
			Body:                  map[string]any{"admission": admission.String()},
			FieldClasses:          map[string]observability.FieldClass{"/admission": observability.FieldClassMetadata},
		})
	}
	input := observability.RecordInput{
		Timestamp:  time.Unix(1_700_000_000, 0).UTC(),
		RecordID:   "record-1",
		Identity:   metadata.identity,
		Source:     metadata.source,
		Connector:  metadata.connector,
		Action:     string(metadata.action),
		Provenance: observability.Provenance{Producer: "router-test", BinaryVersion: "v8", RegistrySchemaVersion: 1},
	}
	if metadata.hasSeverity {
		severity := metadata.severity
		input.Severity = &severity
	}
	switch metadata.identity.Signal {
	case observability.SignalTraces:
		input.SpanName = "chat model"
		input.Body = map[string]any{"attributes": map[string]any{"model": "test"}}
		input.FieldClasses = map[string]observability.FieldClass{"/attributes/model": observability.FieldClassMetadata}
	case observability.SignalMetrics:
		input.InstrumentData = map[string]any{"value": 1.0}
		input.FieldClasses = map[string]observability.FieldClass{"/value": observability.FieldClassMetadata}
	}
	return observability.NewRecord(input)
}

func classifiedLogResolution(
	metadata Metadata,
) (observability.ProducerKind, observability.ProducerKey, observability.ClassificationContext, error) {
	context := observability.ClassificationContext{RawSeverity: string(metadata.severity)}
	switch metadata.identity.Name {
	case "finding.observed":
		return observability.ProducerGatewayEvent, "scan_finding", context, nil
	case "config.change.applied":
		context.Bucket = metadata.identity.Bucket
		context.EventName = metadata.identity.Name
		context.MandatoryFacts.ControlPlaneMutation = metadata.mandatory
		return observability.ProducerGatewayEvent, "activity", context, nil
	case "diagnostic.message":
		return observability.ProducerGatewayEvent, "diagnostic", context, nil
	default:
		return "", "", observability.ClassificationContext{}, fmt.Errorf("test helper has no classified-log mapping")
	}
}

func deliveryNames(deliveries []Delivery) []string {
	result := make([]string, len(deliveries))
	for index, delivery := range deliveries {
		result[index] = delivery.DestinationName
	}
	sort.Strings(result)
	return result
}

func assertAtMostOncePerDestination(t *testing.T, deliveries []Delivery) {
	t.Helper()
	seen := make(map[string]struct{}, len(deliveries))
	for _, delivery := range deliveries {
		if _, duplicate := seen[delivery.DestinationName]; duplicate {
			t.Errorf("destination %q selected more than once", delivery.DestinationName)
		}
		seen[delivery.DestinationName] = struct{}{}
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
