// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestTraceProjectionPipelineRoutesAndRedactsEachDestinationIndependently(t *testing.T) {
	plan := traceProjectionPlan(t, 90)
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewTraceProjectionPipeline(plan, evaluator, mustEngine(t))
	if err != nil {
		t.Fatal(err)
	}
	record := diagnosticTraceRecord(t, plan)

	outcome, err := pipeline.Process(record)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionOrdinary || len(outcome.OptionalFailures()) != 0 ||
		len(outcome.OptionalWork()) != 2 {
		t.Fatalf("trace projection outcome admission=%s work=%d failures=%d",
			outcome.Admission(), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}
	wantDestinations := []string{"raw-traces", "strict-traces"}
	wantProfiles := []string{"none", "strict"}
	for index, work := range outcome.OptionalWork() {
		if work.Delivery().DestinationName != wantDestinations[index] ||
			work.Projection().Metadata().RedactionProfile != wantProfiles[index] {
			t.Fatalf("work[%d] destination/profile=%q/%q", index,
				work.Delivery().DestinationName, work.Projection().Metadata().RedactionProfile)
		}
		identity := work.Identity()
		if identity.RecordID() != record.RecordID() || identity.Bucket() != record.Bucket() ||
			identity.Signal() != observability.SignalTraces || identity.EventName() != record.EventName() ||
			identity.OriginDestination() != "" {
			t.Fatalf("work[%d] identity=%+v", index, identity)
		}
	}
	work := outcome.OptionalWork()
	work[0].delivery.DestinationName = "mutated"
	if outcome.OptionalWork()[0].Delivery().DestinationName != "raw-traces" {
		t.Fatal("trace outcome exposed mutable delivery state")
	}
}

func TestTraceProjectionPipelineIsolatesProjectionFailure(t *testing.T) {
	plan := traceProjectionPlan(t, 90)
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	projector := &selectiveProjector{
		engine: mustEngine(t), failProfile: redaction.ProfileStrict,
		failure: redaction.ProjectionFailureSerialization,
	}
	pipeline, err := NewTraceProjectionPipeline(plan, evaluator, projector)
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := pipeline.Process(diagnosticTraceRecord(t, plan))
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.OptionalWork()) != 1 ||
		outcome.OptionalWork()[0].Delivery().DestinationName != "raw-traces" ||
		len(outcome.OptionalFailures()) != 1 ||
		outcome.OptionalFailures()[0].DestinationName() != "strict-traces" ||
		outcome.OptionalFailures()[0].Code() != OptionalFailureSerialization {
		t.Fatalf("isolated outcome work=%+v failures=%+v",
			outcome.OptionalWork(), outcome.OptionalFailures())
	}
}

func TestTraceProjectionPipelineRejectsCrossGenerationRecord(t *testing.T) {
	first := traceProjectionPlan(t, 90)
	second := traceProjectionPlan(t, 30)
	if first.Digest() == second.Digest() {
		t.Fatal("test plans have the same digest")
	}
	evaluator, err := router.New(second)
	if err != nil {
		t.Fatal(err)
	}
	pipeline, err := NewTraceProjectionPipeline(second, evaluator, mustEngine(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.Process(diagnosticTraceRecord(t, first)); err == nil {
		t.Fatal("trace pipeline accepted a record from another graph generation")
	}
	if _, err := NewTraceProjectionPipeline(first, evaluator, mustEngine(t)); err == nil {
		t.Fatal("trace pipeline accepted an evaluator from another plan")
	}
}

func traceProjectionPlan(t *testing.T, retentionDays int) *config.ObservabilityV8Plan {
	t.Helper()
	traces := []observability.Signal{observability.SignalTraces}
	diagnostic := []observability.Bucket{observability.BucketDiagnostic}
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{RetentionDays: &retentionDays},
		Destinations: []config.ObservabilityV8DestinationSource{
			{
				Name: "raw-traces", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: "https://raw.example.test",
				Send: &config.ObservabilityV8SendSource{
					Signals: traces, Buckets: diagnostic, RedactionProfile: "none",
				},
			},
			{
				Name: "strict-traces", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: "https://strict.example.test",
				Send: &config.ObservabilityV8SendSource{
					Signals: traces, Buckets: diagnostic, RedactionProfile: "strict",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func diagnosticTraceRecord(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
) observability.Record {
	t.Helper()
	var sequence atomic.Uint64
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 5, 18, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("trace-projection-%d", sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildSpanDiagnosticCanary(observability.SpanDiagnosticCanaryInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem,
			Correlation: observability.Correlation{
				TraceID: "0123456789abcdef0123456789abcdef",
				SpanID:  "0123456789abcdef",
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: 1, ConfigDigest: plan.Digest(),
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_000_000_000,
		EndTimeUnixNano:   1_783_278_000_100_000_000,
		ParentSpanID:      observability.Absent[string](),
		TraceState:        observability.Absent[string](),
		Flags:             0x101,
		Status:            observability.NewTraceStatusOK(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		Scope:                             observability.TraceScopeInput{},
		ResourceServiceName:               "defenseclaw",
		ResourceServiceNamespace:          "cisco.ai-defense",
		ResourceServiceInstanceID:         "instance-1",
		ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID:     "instance-1",
		DefenseClawDestinationID:          observability.Present("raw-traces"),
		DefenseClawDestinationSignal:      observability.Present("traces"),
		ConditionOperationTerminal:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestTraceProjectionOutcomeAccessorsAreDetached(t *testing.T) {
	outcome := TraceProjectionOutcome{
		optionalWork: []ProjectedDelivery{{}},
		optionalFailure: []OptionalFailure{{
			destinationName: "one",
		}},
	}
	work, failures := outcome.OptionalWork(), outcome.OptionalFailures()
	work = append(work, ProjectedDelivery{})
	failures[0].destinationName = "changed"
	if len(outcome.OptionalWork()) != 1 ||
		!reflect.DeepEqual([]string{outcome.OptionalFailures()[0].DestinationName()}, []string{"one"}) {
		t.Fatal("trace projection outcome accessors exposed mutable slices")
	}
}
