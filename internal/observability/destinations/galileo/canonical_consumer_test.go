// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

const canonicalRawPII = "canonical-consumer@example.test"

type canonicalCaptureAdapter struct {
	deliveries chan [][]byte
	deliver    delivery.DeliveryResult
	block      chan struct{}
	closeGate  chan struct{}
	closeErr   error
	closeCalls atomic.Uint64
	transport  otlp.ExportCounters
	mu         sync.Mutex
	closed     bool
}

func (adapter *canonicalCaptureAdapter) Counters() otlp.ExportCounters {
	if adapter == nil {
		return otlp.ExportCounters{}
	}
	return adapter.transport
}

func (adapter *canonicalCaptureAdapter) EncodedSize(sizes []int) (int, bool) {
	total := 1
	for _, size := range sizes {
		if size < 0 {
			return 0, false
		}
		total += size
	}
	return total, true
}

func (adapter *canonicalCaptureAdapter) Deliver(
	ctx context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	if adapter.block != nil {
		select {
		case <-ctx.Done():
			return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
		case <-adapter.block:
		}
	}
	items := batch.Items()
	encoded := make([][]byte, len(items))
	for index := range items {
		encoded[index] = items[index].Bytes()
	}
	if adapter.deliveries != nil {
		select {
		case adapter.deliveries <- encoded:
		default:
		}
	}
	if adapter.deliver.Outcome != "" {
		return adapter.deliver
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *canonicalCaptureAdapter) Close(ctx context.Context) error {
	adapter.closeCalls.Add(1)
	if adapter.closeGate != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-adapter.closeGate:
		}
	}
	if adapter.closeErr != nil {
		return adapter.closeErr
	}
	adapter.mu.Lock()
	adapter.closed = true
	adapter.mu.Unlock()
	return nil
}

type canonicalFailureCapture struct {
	mu     sync.Mutex
	events []CanonicalFailure
	panic  bool
}

func (capture *canonicalFailureCapture) ObserveGalileoCanonicalFailure(failure CanonicalFailure) {
	if capture.panic {
		panic("observer panic must be isolated")
	}
	capture.mu.Lock()
	capture.events = append(capture.events, failure)
	capture.mu.Unlock()
}

func (capture *canonicalFailureCapture) snapshot() []CanonicalFailure {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]CanonicalFailure(nil), capture.events...)
}

func TestCanonicalConsumerRequiresExplicitActivationAndPerformsNoPreparedIO(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-prepared", observability.BucketModelIO, "none", 1)
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, canonicalRawPII)); result != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("prepared enqueue = %s", result)
	}
	select {
	case <-fixture.adapter.deliveries:
		t.Fatal("prepared consumer performed destination I/O")
	default:
	}
	fixture.consumer.Activate()
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, canonicalRawPII)); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("active enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	flushCanonical(t, fixture.consumer)
	if counters := fixture.consumer.Counters(); !counters.Reconciled() || counters.Observed != 1 ||
		counters.Accepted != 1 || counters.Closed != 1 || counters.ClosedBeforeObservation != 1 ||
		counters.ClosedObserved != 0 {
		t.Fatalf("prepared/active reconciliation = %+v", counters)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerPreparationRejectsCrossKindAndUnboundedDependencies(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-validation", observability.BucketModelIO, "none", 1)
	base := CanonicalTraceConsumerOptions{
		Destination: fixture.destination, Generation: 1, Pipeline: fixture.pipeline,
		Adapter: fixture.adapter, Dispatcher: canonicalDispatcherConfig(fixture.destination.Name, 1, 1),
		Limits: compatibility.DefaultLimits(), Observer: fixture.failures,
	}
	tests := []struct {
		name string
		code CanonicalConsumerErrorCode
		edit func(*CanonicalTraceConsumerOptions)
	}{
		{name: "zero generation", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Generation = 0 }},
		{name: "nil pipeline", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Pipeline = nil }},
		{name: "nil adapter", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Adapter = (*canonicalCaptureAdapter)(nil) }},
		{name: "nil observer", code: CanonicalConsumerErrorInvalidDependencies, edit: func(value *CanonicalTraceConsumerOptions) { value.Observer = (*canonicalFailureCapture)(nil) }},
		{name: "general otlp", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) { value.Destination.Preset = "" }},
		{name: "wrong profile", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) { value.Destination.PresetProfile = "galileo-rich-v3" }},
		{name: "non trace selection", code: CanonicalConsumerErrorInvalidDestination, edit: func(value *CanonicalTraceConsumerOptions) {
			value.Destination.SelectedSignals = []observability.Signal{observability.SignalLogs}
		}},
		{name: "dispatcher identity", code: CanonicalConsumerErrorInvalidDispatcher, edit: func(value *CanonicalTraceConsumerOptions) { value.Dispatcher.Destination = "other" }},
		{name: "dispatcher generation", code: CanonicalConsumerErrorInvalidDispatcher, edit: func(value *CanonicalTraceConsumerOptions) { value.Dispatcher.Generation = 2 }},
		{name: "dispatcher signal", code: CanonicalConsumerErrorInvalidDispatcher, edit: func(value *CanonicalTraceConsumerOptions) {
			value.Dispatcher.Signal = string(observability.SignalLogs)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := base
			test.edit(&value)
			consumer, err := NewCanonicalTraceConsumer(value)
			if consumer != nil || !IsCanonicalConsumerError(err, test.code) ||
				bytes.Contains([]byte(fmt.Sprint(err)), []byte(canonicalRawPII)) {
				t.Fatalf("consumer=%v err=%v code=%s", consumer, err, test.code)
			}
		})
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerRoutesRedactsAndGalileoProjectsExactlyOnce(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-redacted", observability.BucketModelIO, "strict", 8)
	originalProcess := fixture.consumer.process
	var processCalls atomic.Uint64
	fixture.consumer.process = func(record observability.Record) (pipeline.TraceProjectionOutcome, error) {
		processCalls.Add(1)
		return originalProcess(record)
	}
	fixture.consumer.Activate()
	record := fixture.modelRecord(t, "contact "+canonicalRawPII)
	if result := fixture.consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	flushCanonical(t, fixture.consumer)
	batch := waitCanonicalDelivery(t, fixture.adapter.deliveries)
	if len(batch) != 1 {
		t.Fatalf("batch items = %d", len(batch))
	}
	if bytes.Contains(batch[0], []byte(canonicalRawPII)) {
		t.Fatal("Galileo payload recovered content removed by central redaction")
	}
	wire, ok := decodeProjection(batch[0])
	if !ok || wire.Profile != compatibility.ProfileID || wire.Shape != compatibility.ShapeLLM ||
		wire.RecordID != record.RecordID() || wire.Signal != string(observability.SignalTraces) {
		t.Fatalf("Galileo projection identity = %+v ok=%v", wire, ok)
	}
	if got := fixture.consumer.Counters(); got.Accepted != 1 || got.RouteDropped != 0 ||
		got.QueueDropped != 0 || got.Failed != 0 {
		t.Fatalf("consumer counters = %+v", got)
	}
	if got := processCalls.Load(); got != 1 {
		t.Fatalf("central trace projection calls = %d, want exactly one", got)
	}
	if events := fixture.failures.snapshot(); len(events) != 0 {
		t.Fatalf("unexpected failures = %+v", events)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerConfiguredRouteDropAndWrongDestinationDoNotLeakToAdapter(t *testing.T) {
	t.Parallel()
	routeDrop := newCanonicalFixture(t, "galileo-tool-only", observability.BucketToolActivity, "none", 4)
	routeDrop.consumer.Activate()
	if result := routeDrop.consumer.tryEnqueueRecord(routeDrop.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unmatched route = %s", result)
	}
	if counters := routeDrop.consumer.Counters(); !counters.Reconciled() ||
		counters.RouteDropped != 1 || counters.RouteUnmatched != 1 {
		t.Fatalf("unmatched route accounting = %+v", counters)
	}
	assertNoCanonicalDelivery(t, routeDrop.adapter.deliveries)
	shutdownCanonical(t, routeDrop.consumer)

	source := newCanonicalFixture(t, "galileo-source", observability.BucketModelIO, "none", 4)
	other := newCanonicalFixture(t, "galileo-other", observability.BucketModelIO, "none", 4)
	wrongAdapter := &canonicalCaptureAdapter{deliveries: make(chan [][]byte, 1)}
	wrongFailures := &canonicalFailureCapture{}
	wrong, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: other.destination, Generation: 4, Pipeline: source.pipeline,
		Adapter: wrongAdapter, Dispatcher: canonicalDispatcherConfig(other.destination.Name, 4, 4),
		Limits: compatibility.DefaultLimits(), Observer: wrongFailures,
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong.Activate()
	if result := wrong.tryEnqueueRecord(source.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("wrong destination = %s", result)
	}
	assertNoCanonicalDelivery(t, wrongAdapter.deliveries)
	shutdownCanonical(t, wrong)
	shutdownCanonical(t, source.consumer)
	shutdownCanonical(t, other.consumer)

	target := newCanonicalFixture(t, "galileo-target", observability.BucketModelIO, "none", 4)
	target.consumer.Activate()
	if result := target.consumer.tryEnqueueRecord(
		target.modelRecordWithCanary(t, "safe", "different-destination"),
	); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("canary target mismatch = %s", result)
	}
	if counters := target.consumer.Counters(); !counters.Reconciled() ||
		counters.RouteDropped != 1 || counters.RouteTargetMismatch != 1 {
		t.Fatalf("target mismatch accounting = %+v", counters)
	}
	shutdownCanonical(t, target.consumer)
}

func TestCanonicalConsumerRejectsUnsupportedGalileoShapeAndGenerationMismatch(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-shape", observability.BucketDiagnostic, "none", 5)
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.diagnosticRecord(t, 5)); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unsupported shape = %s", result)
	}
	if result := fixture.consumer.tryEnqueueRecord(fixture.diagnosticRecord(t, 6)); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("generation mismatch = %s", result)
	}
	assertNoCanonicalDelivery(t, fixture.adapter.deliveries)
	want := []CanonicalFailure{
		{Destination: fixture.destination.Name, Generation: 5, Code: CanonicalFailureUnsupportedShape},
		{Destination: fixture.destination.Name, Generation: 5, Code: CanonicalFailureGenerationMismatch},
	}
	if got := fixture.failures.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("failures = %+v, want %+v", got, want)
	}
	if counters := fixture.consumer.Counters(); !counters.Reconciled() ||
		counters.SchemaIneligible != 1 || counters.RouteDropped != 1 || counters.Failed != 1 {
		t.Fatalf("schema/failure accounting = %+v", counters)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerExplicitRouteReportsUnsupportedEligibleOperation(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-explicit-operation", observability.BucketModelIO, "none", 5)
	malformed := fixture.wrongAgentOperationProjection(t)
	fixture.consumer.project = func(_ redaction.Projection, limits compatibility.Limits) compatibility.Result {
		return compatibility.Project(malformed, limits)
	}
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "eligible route")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unsupported eligible operation = %s failures=%+v", result, fixture.failures.snapshot())
	}
	assertNoCanonicalDelivery(t, fixture.adapter.deliveries)
	want := []CanonicalFailure{{
		Destination: fixture.destination.Name, Generation: 5, Code: CanonicalFailureUnsupportedShape,
	}}
	if got := fixture.failures.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("unsupported eligible failures = %+v, want %+v", got, want)
	}
	if counters := fixture.consumer.Counters(); !counters.Reconciled() ||
		counters.SchemaIneligible != 1 || counters.RouteDropped != 1 || counters.RouteUnmatched != 0 {
		t.Fatalf("unsupported eligible accounting = %+v", counters)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerCapabilityDefaultDropsNonMemberWithoutFailure(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalCapabilityFixture(t, "galileo-default-membership", 5)
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.diagnosticRecord(t, 5)); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("non-member result = %s", result)
	}
	assertNoCanonicalDelivery(t, fixture.adapter.deliveries)
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "eligible")); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("eligible result = %s failures=%+v", result, fixture.failures.snapshot())
	}
	flushCanonical(t, fixture.consumer)
	if batch := waitCanonicalDelivery(t, fixture.adapter.deliveries); len(batch) != 1 {
		t.Fatalf("eligible delivery items = %d", len(batch))
	}
	if got := fixture.failures.snapshot(); len(got) != 0 {
		t.Fatalf("default-route non-member emitted failures = %+v", got)
	}
	if counters := fixture.consumer.Counters(); !counters.Reconciled() ||
		counters.Observed != 2 || counters.Accepted != 1 || counters.RouteUnmatched != 1 ||
		counters.RouteDropped != 1 || counters.SchemaIneligible != 0 {
		t.Fatalf("default-route non-member accounting = %+v", counters)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerQueueFullIsBoundedAndFlushLeavesIntakeLive(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-queue", observability.BucketModelIO, "none", 3)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := fixture.consumer.dispatcher.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	replacement, err := delivery.NewDispatcher(
		canonicalDispatcherConfigWithDelay(fixture.destination.Name, 1, 3, time.Hour), fixture.adapter,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.consumer.dispatcher = replacement
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "first")); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("first enqueue = %s failures=%+v", result, fixture.failures.snapshot())
	}
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "second")); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("queue-full enqueue = %s", result)
	}
	if got := fixture.consumer.Counters(); got.Accepted != 1 || got.QueueDropped != 1 {
		t.Fatalf("queue counters = %+v", got)
	}
	shutdownCanonical(t, fixture.consumer)

	live := newCanonicalFixture(t, "galileo-flush", observability.BucketModelIO, "none", 3)
	live.consumer.Activate()
	for _, content := range []string{"before flush", "after flush"} {
		if result := live.consumer.tryEnqueueRecord(live.modelRecord(t, content)); result != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatalf("enqueue %q = %s", content, result)
		}
		flushCanonical(t, live.consumer)
	}
	if got := live.consumer.Counters(); got.Accepted != 2 || got.Closed != 0 {
		t.Fatalf("flush stopped intake: %+v", got)
	}
	shutdownCanonical(t, live.consumer)
}

func TestCanonicalConsumerUnifiesFunnelQueueAndPartialTransportEvidence(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-evidence", observability.BucketModelIO, "none", 11)
	fixture.adapter.deliver = delivery.DeliveryResult{
		Outcome: delivery.OutcomePartial, DeliveredItems: 1, RejectedItems: 1,
	}
	fixture.adapter.transport = otlp.ExportCounters{
		Accepted: 2, Exported: 1, RejectedPartial: 1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if err := fixture.consumer.dispatcher.Close(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	replacement, err := delivery.NewDispatcher(
		canonicalDispatcherConfigWithDelay(fixture.destination.Name, 4, 11, time.Hour),
		fixture.adapter,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.consumer.dispatcher = replacement
	fixture.consumer.Activate()
	for _, content := range []string{"one", "two"} {
		if result := fixture.consumer.tryEnqueueRecord(
			fixture.modelRecord(t, content),
		); result != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatalf("enqueue %q = %s", content, result)
		}
	}
	shutdownCanonical(t, fixture.consumer)
	evidence := fixture.consumer.DeliveryEvidenceSnapshot()
	if evidence.Destination != fixture.destination.Name || evidence.Generation != 11 ||
		evidence.Profile != compatibility.ProfileID || evidence.Funnel.Observed != 2 ||
		!evidence.Funnel.Reconciled() ||
		evidence.Funnel.Accepted != 2 || evidence.Funnel.RouteDropped != 0 ||
		evidence.Funnel.SchemaIneligible != 0 || evidence.Delivery.Counters.Accepted != 2 ||
		evidence.Delivery.Counters.Delivered != 1 || evidence.Delivery.Counters.Rejected != 1 ||
		evidence.Delivery.Counters.Retried != 0 || evidence.Transport.Accepted != 2 ||
		evidence.Transport.Exported != 1 || evidence.Transport.RejectedPartial != 1 {
		t.Fatalf("unified evidence = %+v", evidence)
	}
	if evidence.Delivery.LastSuccess.IsZero() || evidence.Delivery.LastFailure.IsZero() ||
		bytes.Contains([]byte(fmt.Sprintf("%+v", evidence)), []byte(canonicalRawPII)) {
		t.Fatalf("partial/content-free evidence = %+v", evidence)
	}
}

func TestCanonicalConsumerExportsAllSixGeneratedFamiliesWithPR403Graph(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 8)}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/otel/traces", &canaryObserver{})
	fixture := newCanonicalFixtureBuckets(t, "galileo", []observability.Bucket{
		observability.BucketAgentLifecycle, observability.BucketModelIO,
		observability.BucketToolActivity, observability.BucketGuardrailEvaluation,
	}, "none", 12)
	consumer, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: fixture.destination, Generation: 12, Pipeline: fixture.pipeline,
		Adapter: adapter, Dispatcher: canonicalDispatcherConfigWithDelay("galileo", 8, 12, 100*time.Millisecond),
		Limits: compatibility.DefaultLimits(), Observer: fixture.failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer.Activate()
	records := fixture.richGalileoGraph(t)
	for _, record := range records {
		if result := consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatalf("enqueue %s = %s failures=%+v", record.EventName(), result, fixture.failures.snapshot())
		}
	}
	flushCanonical(t, consumer)
	var spans []*tracepb.Span
	for {
		select {
		case request := <-capture.requests:
			spans = append(spans, requestSpans(request)...)
		default:
			goto requestsDrained
		}
	}

requestsDrained:
	if len(spans) != 7 {
		t.Fatalf("exported spans = %d, want 7", len(spans))
	}
	families := make(map[string]int)
	byID := make(map[string]*tracepb.Span)
	for _, span := range spans {
		attributes := protoAttributes(span.Attributes)
		family := attributes["defenseclaw.span.family"].GetStringValue()
		bucket := attributes["defenseclaw.bucket"].GetStringValue()
		if family == "" || bucket == "" || span.Status == nil ||
			span.Status.Code != tracepb.Status_STATUS_CODE_OK || span.Flags != 0x101 ||
			span.TraceState != "dc=rich" {
			t.Fatalf("canonical identity/status lost family=%q bucket=%q span=%+v", family, bucket, span)
		}
		families[family]++
		byID[fmt.Sprintf("%x", span.SpanId)] = span
	}
	wantFamilies := map[string]int{
		observability.TelemetryFamilyAgentInvoke:     2,
		observability.TelemetryFamilyModelChat:       1,
		observability.TelemetryFamilyToolExecute:     1,
		observability.TelemetryFamilyRetrievalSearch: 1,
		observability.TelemetryFamilyWorkflowRun:     1,
		observability.TelemetryFamilyGuardrailJudge:  1,
	}
	if !reflect.DeepEqual(families, wantFamilies) {
		t.Fatalf("Galileo family inventory = %v, want %v", families, wantFamilies)
	}
	parents := map[string]string{
		"0000000000000001": "", "0000000000000002": "0000000000000001",
		"0000000000000003": "0000000000000002", "0000000000000004": "0000000000000003",
		"0000000000000005": "0000000000000003", "0000000000000006": "0000000000000005",
		"0000000000000007": "0000000000000004",
	}
	for spanID, parentID := range parents {
		span := byID[spanID]
		if span == nil || fmt.Sprintf("%x", span.ParentSpanId) != parentID {
			t.Errorf("topology span=%s parent=%x want=%s", spanID, span.GetParentSpanId(), parentID)
		}
	}
	rootAttributes := protoAttributes(byID["0000000000000001"].Attributes)
	childAttributes := protoAttributes(byID["0000000000000002"].Attributes)
	if rootAttributes["defenseclaw.agent.root.id"].GetStringValue() != "agent-root" ||
		childAttributes["defenseclaw.agent.parent.id"].GetStringValue() != "agent-root" ||
		childAttributes["defenseclaw.agent.lineage.provenance"].GetStringValue() != "reported" ||
		childAttributes["defenseclaw.agent.lifecycle.id"].GetStringValue() != "lifecycle-child" ||
		childAttributes["defenseclaw.agent.execution.id"].GetStringValue() != "execution-child" ||
		childAttributes["defenseclaw.agent.depth"].GetIntValue() != 1 {
		t.Fatalf("PR403 root/subagent richness lost root=%v child=%v", rootAttributes, childAttributes)
	}
	toolAttributes := protoAttributes(byID["0000000000000005"].Attributes)
	judgeAttributes := protoAttributes(byID["0000000000000007"].Attributes)
	if toolAttributes["gen_ai.tool.name"].GetStringValue() != "search" ||
		toolAttributes["defenseclaw.tool.status"].GetStringValue() != "completed" ||
		judgeAttributes["defenseclaw.guardrail.judge"].GetBoolValue() != true ||
		judgeAttributes["defenseclaw.evaluation.id"].GetStringValue() != "evaluation-rich" ||
		judgeAttributes["defenseclaw.finding.id"].GetStringValue() != "finding-rich" {
		t.Fatalf("tool/judge richness lost tool=%v judge=%v", toolAttributes, judgeAttributes)
	}
	evidence := consumer.DeliveryEvidenceSnapshot()
	if evidence.Funnel.Observed != 7 || evidence.Funnel.Accepted != 7 ||
		!evidence.Funnel.Reconciled() ||
		evidence.Delivery.Counters.Delivered != 7 || evidence.Transport.Exported != 7 ||
		evidence.Funnel.RouteDropped != 0 || evidence.Funnel.Failed != 0 {
		t.Fatalf("six-family delivery evidence = %+v", evidence)
	}
	shutdownCanonical(t, consumer)
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerShutdownIsRetryableIdempotentAndCannotReactivate(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-shutdown", observability.BucketModelIO, "none", 2)
	fixture.adapter.closeGate = make(chan struct{})
	fixture.consumer.Activate()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := fixture.consumer.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("first shutdown = %v", err)
	}
	close(fixture.adapter.closeGate)
	shutdownCanonical(t, fixture.consumer)
	shutdownCanonical(t, fixture.consumer)
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "late")); result != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("post-shutdown enqueue = %s", result)
	}
	if got := fixture.adapter.closeCalls.Load(); got != 2 {
		t.Fatalf("adapter close calls = %d, want one timed-out and one successful attempt", got)
	}
}

func TestCanonicalConsumerIsolatesPipelineAndObserverPanics(t *testing.T) {
	t.Parallel()
	fixture := newCanonicalFixture(t, "galileo-panic", observability.BucketModelIO, "none", 7)
	fixture.failures.panic = true
	fixture.consumer.process = func(observability.Record) (pipeline.TraceProjectionOutcome, error) {
		panic("pipeline panic must not escape")
	}
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(fixture.modelRecord(t, "safe")); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("panic result = %s", result)
	}
	if got := fixture.consumer.Counters(); got.Failed != 1 {
		t.Fatalf("panic counters = %+v", got)
	}
	shutdownCanonical(t, fixture.consumer)
}

func TestCanonicalConsumerPublicSurfaceHasNoRawRecordOrSDKSpanBypass(t *testing.T) {
	t.Parallel()
	typeOf := reflect.TypeOf((*CanonicalTraceConsumer)(nil))
	for _, forbidden := range []string{"EnqueueRecord", "EnqueueProjection", "OnEnd", "ExportSpans"} {
		if _, exists := typeOf.MethodByName(forbidden); exists {
			t.Fatalf("public bypass method %q exists", forbidden)
		}
	}
	if method, exists := typeOf.MethodByName("TryEnqueue"); !exists ||
		method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf(telemetry.V8CanonicalEndedSpan{}) {
		t.Fatalf("TryEnqueue signature = %+v exists=%v", method, exists)
	}
}

type canonicalFixture struct {
	destination config.ObservabilityV8EffectiveDestination
	plan        *config.ObservabilityV8Plan
	pipeline    *pipeline.TraceProjectionPipeline
	adapter     *canonicalCaptureAdapter
	failures    *canonicalFailureCapture
	consumer    *CanonicalTraceConsumer
	generation  uint64
	sequence    atomic.Uint64
}

func newCanonicalFixture(
	t *testing.T,
	name string,
	bucket observability.Bucket,
	profile string,
	generation uint64,
) *canonicalFixture {
	return newCanonicalFixtureBuckets(t, name, []observability.Bucket{bucket}, profile, generation)
}

func newCanonicalFixtureBuckets(
	t *testing.T,
	name string,
	buckets []observability.Bucket,
	profile string,
	generation uint64,
) *canonicalFixture {
	t.Helper()
	signals := []observability.Signal{observability.SignalTraces}
	destination := config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
		Endpoint: "https://example.test/otel/traces",
		Send: &config.ObservabilityV8SendSource{
			Signals: signals, Buckets: buckets, RedactionProfile: profile,
		},
	}
	return newCanonicalFixtureDestination(t, destination, generation)
}

func newCanonicalCapabilityFixture(
	t *testing.T,
	name string,
	generation uint64,
) *canonicalFixture {
	t.Helper()
	return newCanonicalFixtureDestination(t, config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo",
		Endpoint: "https://example.test/otel/traces",
	}, generation)
}

func newCanonicalFixtureDestination(
	t *testing.T,
	source config.ObservabilityV8DestinationSource,
	generation uint64,
) *canonicalFixture {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{source},
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination(source.Name)
	if !ok {
		t.Fatal("compiled Galileo destination missing")
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x43}, 32))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := pipeline.NewTraceProjectionPipeline(plan, evaluator, engine)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &canonicalCaptureAdapter{deliveries: make(chan [][]byte, 8)}
	failures := &canonicalFailureCapture{}
	consumer, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: destination, Generation: generation, Pipeline: projection,
		Adapter: adapter, Dispatcher: canonicalDispatcherConfig(source.Name, 4, generation),
		Limits: compatibility.DefaultLimits(), Observer: failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &canonicalFixture{
		destination: destination, plan: plan, pipeline: projection, adapter: adapter,
		failures: failures, consumer: consumer, generation: generation,
	}
}

func (fixture *canonicalFixture) modelRecord(t *testing.T, content string) observability.Record {
	return fixture.modelRecordWithCanary(t, content, "")
}

func (fixture *canonicalFixture) modelRecordWithCanary(
	t *testing.T,
	content, canaryDestination string,
) observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	sequence := fixture.sequence.Add(1)
	input := observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: content}},
		}},
	}}}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: observability.Present("stop"),
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: "done"}},
		}},
	}}}
	canary := observability.Absent[bool]()
	canaryOperation := observability.Absent[string]()
	canaryTarget := observability.Absent[string]()
	if canaryDestination != "" {
		canary = observability.Present(true)
		canaryOperation = observability.Present("runtime-pipeline-test")
		canaryTarget = observability.Present(canaryDestination)
	}
	record, err := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				RunID: "run-1", TurnID: "turn-1",
				TraceID: "0123456789abcdef0123456789abcdef",
				SpanID:  fmt.Sprintf("%016x", sequence),
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: int64(fixture.generation), ConfigDigest: fixture.plan.Digest(),
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: 1_783_278_000_000_000_000 + sequence,
		EndTimeUnixNano:   1_783_278_000_100_000_000 + sequence,
		TraceState:        observability.Present("dc=canonical-consumer"),
		Flags:             0x101,
		Status:            observability.NewTraceStatusOK(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-1", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-1",
		DefenseClawTelemetryCanary:    canary, DefenseClawTelemetryCanaryOperation: canaryOperation,
		DefenseClawTelemetryCanaryDestination: canaryTarget,
		GenAIInputMessages:                    observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", DefenseClawContentInputOriginalBytes: observability.Present(int64(len(content))),
		GenAIOutputMessages: observability.Present(output), DefenseClawTelemetryOutputReported: true,
		DefenseClawContentOutputState: "preserved", DefenseClawContentOutputOriginalBytes: observability.Present(int64(4)),
		GenAIOperationName: observability.Present("chat"), GenAIProviderName: observability.Present("openai"),
		GenAIRequestModel: "gpt-test", DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *canonicalFixture) richGalileoGraph(t *testing.T) []observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	const traceID = "89abcdef0123456789abcdef01234567"
	input, output := richGalileoMessages("root request", "completed response")
	resource := observability.TraceResourceInput{SchemaURL: "https://opentelemetry.io/schemas/1.42.0"}
	envelope := func(spanID string) observability.FamilyEnvelopeInput {
		return observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				RunID: "run-rich", SessionID: "session-rich", TurnID: "turn-rich",
				TraceID: traceID, SpanID: spanID, AgentID: "agent-child",
				AgentInstanceID: "instance-child", ToolInvocationID: "tool-call-rich",
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: int64(fixture.generation), ConfigDigest: fixture.plan.Digest(),
			},
		}
	}
	core := func(index uint64) (uint64, uint64) {
		return 1_783_278_100_000_000_000 + index*1_000_000,
			1_783_278_100_000_500_000 + index*1_000_000
	}
	resourceFields := func() (string, string, string, string, string) {
		return "defenseclaw", "cisco.ai-defense", "instance-rich", "test", "instance-rich"
	}

	start, end := core(1)
	service, namespace, instance, environment, defenseclawInstance := resourceFields()
	root, err := builder.BuildSpanAgentInvoke(observability.SpanAgentInvokeInput{
		Envelope: envelope("0000000000000001"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		TraceState: observability.Present("dc=rich"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		DefenseClawAgentType:          "root", GenAIConversationID: observability.Present("conversation-rich"),
		GenAIAgentID: observability.Present("agent-root"), GenAIAgentName: observability.Present("root-agent"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		DefenseClawSessionRootID:          observability.Present("session-rich"),
		DefenseClawAgentLifecycleID:       observability.Present("lifecycle-root"),
		DefenseClawAgentExecutionID:       observability.Present("execution-root"),
		DefenseClawAgentDepth:             observability.Present[int64](0),
		DefenseClawAgentLifecycleEvent:    observability.Present("session_start"),
		DefenseClawAgentLifecycleState:    observability.Present("active"),
		DefenseClawAgentPhase:             observability.Present("planning"),
		DefenseClawAgentPhaseCode:         observability.Present[int64](2),
		DefenseClawAgentSequence:          observability.Present[int64](1),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		GenAIProviderName:                   observability.Present("defenseclaw"),
		GenAIOperationName:                  observability.Present("invoke_agent"),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich root: %v", err)
	}

	start, end = core(2)
	child, err := builder.BuildSpanAgentInvoke(observability.SpanAgentInvokeInput{
		Envelope: envelope("0000000000000002"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000001"),
		TraceState:   observability.Present("dc=rich"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		DefenseClawAgentType:          "subagent", GenAIConversationID: observability.Present("conversation-rich"),
		GenAIAgentID: observability.Present("agent-child"), GenAIAgentName: observability.Present("reviewer"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		DefenseClawSessionRootID:          observability.Present("session-rich"),
		DefenseClawSessionParentID:        observability.Present("session-rich"),
		DefenseClawAgentLifecycleID:       observability.Present("lifecycle-child"),
		DefenseClawAgentExecutionID:       observability.Present("execution-child"),
		DefenseClawAgentDepth:             observability.Present[int64](1),
		DefenseClawAgentLifecycleEvent:    observability.Present("subagent_start"),
		DefenseClawAgentLifecycleState:    observability.Present("active"),
		DefenseClawAgentPhase:             observability.Present("model"),
		DefenseClawAgentPhaseCode:         observability.Present[int64](3),
		DefenseClawAgentSequence:          observability.Present[int64](2),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		GenAIProviderName:                   observability.Present("defenseclaw"),
		GenAIOperationName:                  observability.Present("invoke_agent"),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich subagent: %v", err)
	}

	start, end = core(3)
	workflow, err := builder.BuildSpanWorkflowRun(observability.SpanWorkflowRunInput{
		Envelope: envelope("0000000000000003"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000002"), TraceState: observability.Present("dc=rich"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		DefenseClawWorkflowName:       "review-turn", GenAIConversationID: observability.Present("conversation-rich"),
		GenAIAgentID: observability.Present("agent-child"), DefenseClawAgentType: observability.Present("subagent"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich workflow: %v", err)
	}

	start, end = core(4)
	model, err := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: envelope("0000000000000004"), Outcome: observability.OutcomeCompleted,
		Kind: "CLIENT", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000003"), TraceState: observability.Present("dc=rich"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		GenAIConversationID:           observability.Present("conversation-rich"), GenAIAgentID: observability.Present("agent-child"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		GenAIOperationName: observability.Present("chat"), GenAIProviderName: observability.Present("openai"),
		GenAIRequestModel: "gpt-rich", DefenseClawModelAttempt: observability.Present[int64](1),
		DefenseClawModelStreaming: observability.Present(true), DefenseClawModelFirstTokenMs: observability.Present(12.5),
		DefenseClawTelemetryTokensReported:  observability.Present(false),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich model: %v", err)
	}

	start, end = core(5)
	tool, err := builder.BuildSpanToolExecute(observability.SpanToolExecuteInput{
		Envelope: envelope("0000000000000005"), Outcome: observability.OutcomeCompleted,
		Kind: "INTERNAL", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000003"), TraceState: observability.Present("dc=rich"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		GenAIConversationID:           observability.Present("conversation-rich"), GenAIAgentID: observability.Present("agent-child"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: "search",
		GenAIToolCallID:                     observability.Present("tool-call-rich"),
		GenAIToolCallArguments:              observability.Present(observability.TelemetryStructuredGenAIToolCallArguments{}),
		GenAIToolCallResult:                 observability.Present(observability.TelemetryStructuredGenAIToolCallResult{}),
		DefenseClawToolStatus:               observability.Present("completed"),
		DefenseClawToolProvider:             observability.Present("builtin"),
		DefenseClawAgentReportedCostPresent: false, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich tool: %v", err)
	}

	start, end = core(6)
	retrieval, err := builder.BuildSpanRetrievalSearch(observability.SpanRetrievalSearchInput{
		Envelope: envelope("0000000000000006"), Outcome: observability.OutcomeCompleted,
		Kind: "CLIENT", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000005"), TraceState: observability.Present("dc=rich"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		GenAIConversationID:           observability.Present("conversation-rich"), GenAIAgentID: observability.Present("agent-child"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		GenAIInputMessages:                observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		DBOperationName: observability.Present("search"), DBCollectionName: observability.Present("knowledge"),
		DefenseClawRetrievalSourceID: "vector-store", DefenseClawRetrievalSourceType: observability.Present("vector"),
		DefenseClawRetrievalResultCount: observability.Present[int64](2),
		DefenseClawRetrievalTopK:        observability.Present[int64](5), ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich retrieval: %v", err)
	}

	start, end = core(7)
	judge, err := builder.BuildSpanGuardrailJudge(observability.SpanGuardrailJudgeInput{
		Envelope: envelope("0000000000000007"), Outcome: observability.OutcomeAllowed,
		Kind: "CLIENT", StartTimeUnixNano: start, EndTimeUnixNano: end,
		ParentSpanID: observability.Present("0000000000000004"), TraceState: observability.Present("dc=rich"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: resource,
		ResourceServiceName: service, ResourceServiceNamespace: namespace,
		ResourceServiceInstanceID: instance, ResourceDeploymentEnvironmentName: environment,
		ResourceDefenseClawInstanceID: defenseclawInstance,
		GenAIConversationID:           observability.Present("conversation-rich"), GenAIAgentID: observability.Present("agent-child"),
		DefenseClawAgentRootID:            observability.Present("agent-root"),
		DefenseClawAgentParentID:          observability.Present("agent-root"),
		DefenseClawAgentLineageProvenance: observability.Present("reported"),
		DefenseClawEvaluationID:           observability.Present("evaluation-rich"),
		DefenseClawFindingID:              observability.Present("finding-rich"),
		DefenseClawGuardrailName:          observability.Present("llm-judge"),
		DefenseClawGuardrailDecision:      observability.Present("allow"),
		DefenseClawGuardrailMode:          observability.Present("enforce"),
		DefenseClawGuardrailEnforced:      observability.Present(false),
		DefenseClawGuardrailFindingCount:  observability.Present[int64](0),
		DefenseClawJudgeKind:              "llm", GenAIOperationName: observability.Present("chat"),
		GenAIProviderName: observability.Present("openai"), GenAIRequestModel: "judge-rich",
		GenAIInputMessages: observability.Present(input), DefenseClawTelemetryInputReported: true,
		DefenseClawContentInputState: "preserved", GenAIOutputMessages: observability.Present(output),
		DefenseClawTelemetryOutputReported: true, DefenseClawContentOutputState: "preserved",
		DefenseClawTelemetryTokensReported: observability.Present(false), ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatalf("build rich judge: %v", err)
	}
	return []observability.Record{root, child, workflow, model, tool, retrieval, judge}
}

func richGalileoMessages(
	inputContent, outputContent string,
) (observability.TelemetryStructuredGenAIInputMessages, observability.TelemetryStructuredGenAIOutputMessages) {
	input := observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: inputContent}},
		}},
	}}}
	output := observability.TelemetryStructuredGenAIOutputMessages{Items: []observability.TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant", FinishReason: observability.Present("stop"),
		Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: outputContent}},
		}},
	}}}
	return input, output
}

func (fixture *canonicalFixture) diagnosticRecord(t *testing.T, generation uint64) observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	sequence := fixture.sequence.Add(1)
	record, err := builder.BuildSpanDiagnosticCanary(observability.SpanDiagnosticCanaryInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem,
			Correlation: observability.Correlation{
				TraceID: "1123456789abcdef0123456789abcdef", SpanID: fmt.Sprintf("%016x", sequence),
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "8.0.0",
				ConfigGeneration: int64(generation), ConfigDigest: fixture.plan.Digest(),
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_000_000_000 + sequence,
		EndTimeUnixNano:   1_783_278_000_100_000_000 + sequence,
		TraceState:        observability.Present("dc=canonical-consumer"),
		Flags:             0x101,
		Status:            observability.NewTraceStatusOK(),
		Resource: observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-1", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-1",
		DefenseClawDestinationID:      observability.Present(fixture.destination.Name),
		DefenseClawDestinationSignal:  observability.Present("traces"),
		ConditionOperationTerminal:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *canonicalFixture) wrongAgentOperationRecord(t *testing.T) observability.Record {
	t.Helper()
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: time.Unix(1_783_278_000, 0).UTC(), RecordID: "galileo-wrong-agent-operation",
		Identity: observability.EventIdentity{
			Bucket: observability.BucketAgentLifecycle, Signal: observability.SignalTraces,
			Name: observability.EventName(observability.TelemetryFamilyAgentInvoke),
		},
		SpanName: "invoke_agent reviewer", Source: observability.SourceGateway,
		Outcome: observability.OutcomeCompleted,
		Correlation: observability.Correlation{
			RunID: "run-wrong-operation", TraceID: "0123456789abcdef0123456789abcdef",
			SpanID: "0123456789abcdef", AgentID: "agent-wrong-operation",
		},
		Provenance: observability.Provenance{
			Producer: "defenseclaw", BinaryVersion: "8.0.0",
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(fixture.generation), ConfigDigest: fixture.plan.Digest(),
		},
		Body: map[string]any{
			"kind":       "INTERNAL",
			"attributes": map[string]any{"gen_ai.operation.name": "execute_tool"},
		},
		FieldClasses: map[string]observability.FieldClass{
			"/kind":                             observability.FieldClassMetadata,
			"/attributes/gen_ai.operation.name": observability.FieldClassMetadata,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *canonicalFixture) wrongAgentOperationProjection(t *testing.T) redaction.Projection {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := redaction.BuiltInProfile(redaction.ProfileNone)
	if !ok {
		t.Fatal("none redaction profile is unavailable")
	}
	projection, _, err := engine.Project(fixture.wrongAgentOperationRecord(t), profile)
	if err != nil {
		t.Fatal(err)
	}
	return projection
}

func (fixture *canonicalFixture) builder(t *testing.T) *observability.FamilyBuilder {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 5, 20, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("galileo-canonical-%d", fixture.sequence.Load()+1), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func canonicalDispatcherConfig(destination string, queue int, generation uint64) delivery.Config {
	return canonicalDispatcherConfigWithDelay(destination, queue, generation, 0)
}

func canonicalDispatcherConfigWithDelay(destination string, queue int, generation uint64, delay time.Duration) delivery.Config {
	return delivery.Config{
		Destination: destination, Generation: generation, Signal: string(observability.SignalTraces), Enabled: true, MaxQueueItems: queue, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: queue, MaxBatchBytes: 8 * 1024 * 1024, ScheduledDelay: delay,
		AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 1, InitialBackoff: 0, MaxBackoff: 0,
		},
		Observer: delivery.ObserverFunc(func(delivery.HealthTransition) {}),
	}
}

func flushCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.ForceFlush(ctx); err != nil {
		t.Fatalf("ForceFlush: %v", err)
	}
}

func shutdownCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func waitCanonicalDelivery(t *testing.T, deliveries <-chan [][]byte) [][]byte {
	t.Helper()
	select {
	case result := <-deliveries:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canonical Galileo delivery")
		return nil
	}
}

func assertNoCanonicalDelivery(t *testing.T, deliveries <-chan [][]byte) {
	t.Helper()
	select {
	case result := <-deliveries:
		t.Fatalf("unexpected canonical Galileo delivery: %d items", len(result))
	case <-time.After(20 * time.Millisecond):
	}
}
