// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package localobservability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const localRawPII = "agent-owner@example.test"

func TestRuntimeIdentityUsesSharedNoCycleAuthority(t *testing.T) {
	if DestinationName != observability.RuntimeLocalObservabilityDestination ||
		ProfileID != observability.RuntimeLocalObservabilityProfile {
		t.Fatalf("local observability identity drifted: destination=%q profile=%q", DestinationName, ProfileID)
	}
}

func TestGeneratedProfileOwnsExactLocalTraceEligibility(t *testing.T) {
	t.Parallel()
	manifest, err := profilemanifest.Get(ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	traceFamilies := profilemanifest.SortedFamilyIDs(manifest, observability.SignalTraces)
	if len(traceFamilies) != 25 {
		t.Fatalf("generated local trace family count = %d, want 25", len(traceFamilies))
	}
	for _, family := range []observability.EventName{
		"span.agent.invoke",
		"span.agent.transition",
		"span.model.chat",
		"span.tool.execute",
		"span.approval.resolve",
		"span.guardrail.apply",
	} {
		if !profilemanifest.Eligible(ProfileID, observability.SignalTraces, family) {
			t.Fatalf("generated profile omitted supported family %q", family)
		}
	}
	if !profilemanifest.Eligible(ProfileID, observability.SignalTraces, "span.diagnostic.canary") {
		t.Fatal("independent diagnostic canary was dropped from local compatibility input")
	}
}

func TestDiagnosticCanaryReachesLocalDeliveryWithoutReleaseCanarySemantics(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 12)
	adapter := &captureAdapter{
		deliveries: make(chan [][]byte, 1), acknowledgements: make(chan []string, 1), validate: true,
	}
	consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 1, 0))
	consumer.Activate()
	if got := consumer.tryRecord(fixture.diagnosticRecord(t)); got != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("diagnostic canary enqueue = %s", got)
	}
	flush(t, consumer)
	select {
	case delivered := <-adapter.deliveries:
		if len(delivered) != 1 {
			t.Fatalf("diagnostic delivery count = %d", len(delivered))
		}
		wire, ok := decodeWire(delivered[0], true)
		if !ok || wire.Family != observability.TelemetryFamilyDiagnosticCanary ||
			wire.Bucket != string(observability.BucketDiagnostic) {
			t.Fatalf("diagnostic local projection = family:%q bucket:%q valid:%v", wire.Family, wire.Bucket, ok)
		}
		if _, releaseMarker := wire.Body.Attributes["defenseclaw.telemetry.canary"]; releaseMarker {
			t.Fatal("independent diagnostic span gained the two-span release-canary marker")
		}
	case <-time.After(time.Second):
		t.Fatal("diagnostic canary did not reach local projected delivery")
	}
	if got := waitAcknowledgement(t, adapter.acknowledgements); len(got) != 0 {
		t.Fatalf("independent diagnostic span acknowledged as release canary: %v", got)
	}
	shutdown(t, consumer)
}

func TestProjectionPreservesRootAgentAndModelDashboardShapeWithoutFabrication(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 8)
	root := fixture.agentRecord(t, agentRecordInput{
		traceID: "0102030405060708090a0b0c0d0e0f10", spanID: "1112131415161718",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
		lifecycle: "lifecycle-0123456789abcdef", execution: "execution-0123456789abcdef",
		phase: "planning", phaseCode: 2,
	})
	model := fixture.modelRecord(t, modelRecordInput{
		traceID: "0102030405060708090a0b0c0d0e0f10", spanID: "2122232425262728",
		parentSpanID: "1112131415161718", agentID: "agent-root", rootID: "agent-root",
		agentType: "codex", lifecycle: "lifecycle-0123456789abcdef",
		execution: "execution-0123456789abcdef", decision: "alert", wouldBlock: true,
	})

	rootWire := fixture.projectRecord(t, root)
	modelWire := fixture.projectRecord(t, model)
	assertAlias(t, rootWire.Body.Attributes, "connector", "openai_codex")
	assertAlias(t, rootWire.Body.Attributes, "gen_ai.agent.type", "codex")
	if _, fabricated := rootWire.Body.Attributes["defenseclaw.agent.parent.id"]; fabricated {
		t.Fatal("root logical parent was fabricated")
	}
	if rootWire.Body.ParentSpanID != "" {
		t.Fatalf("root OTel parent = %q", rootWire.Body.ParentSpanID)
	}
	for key, want := range map[string]any{
		"gen_ai.agent.id": "agent-root", "defenseclaw.agent.root.id": "agent-root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-0123456789abcdef",
		"defenseclaw.agent.execution.id": "execution-0123456789abcdef",
		"defenseclaw.agent.phase":        "planning",
	} {
		if got := rootWire.Body.Attributes[key]; got != want {
			t.Errorf("root %s = %v, want %v", key, got, want)
		}
	}
	if rootWire.Body.Attributes["defenseclaw.agent.reported_cost.present"] != false {
		t.Fatal("missing root cost did not remain explicitly unreported")
	}
	for _, forbidden := range []string{
		"defenseclaw.agent.reported_cost.usd", "gen_ai.input.messages", "gen_ai.output.messages",
		"defenseclaw.raw_action", "defenseclaw.decision", "defenseclaw.would_block",
	} {
		if _, present := rootWire.Body.Attributes[forbidden]; present {
			t.Errorf("root fabricated %q", forbidden)
		}
	}

	assertAlias(t, modelWire.Body.Attributes, "connector", "openai_codex")
	assertAlias(t, modelWire.Body.Attributes, "gen_ai.agent.type", "codex")
	assertAlias(t, modelWire.Body.Attributes, "defenseclaw.decision", "alert")
	assertAlias(t, modelWire.Body.Attributes, "defenseclaw.would_block", true)
	if modelWire.Body.ParentSpanID != "1112131415161718" ||
		modelWire.Body.Attributes["gen_ai.request.model"] != "gpt-5.5" ||
		modelWire.Body.Attributes["defenseclaw.telemetry.tokens.reported"] != false {
		t.Fatalf("model compatibility shape = %+v", modelWire.Body)
	}
	for _, token := range []string{"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"} {
		if _, fabricated := modelWire.Body.Attributes[token]; fabricated {
			t.Errorf("model fabricated %s", token)
		}
	}
}

func TestProjectionPreservesNestedSubagentAndToolLineageWithoutInventingContent(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 9)
	child := fixture.agentRecord(t, agentRecordInput{
		traceID: "11111111111111111111111111111111", spanID: "3132333435363738",
		agentID: "agent-child", rootID: "agent-root", parentID: "agent-root",
		agentType: "reviewer", depth: 1, lifecycle: "lifecycle-1111111111111111",
		execution: "execution-2222222222222222", phase: "tool", phaseCode: 4,
	})
	tool := fixture.toolRecord(t, toolRecordInput{
		traceID: "11111111111111111111111111111111", spanID: "4142434445464748",
		parentSpanID: "3132333435363738", agentID: "agent-child", rootID: "agent-root",
		parentID: "agent-root", agentType: "reviewer", lifecycle: "lifecycle-1111111111111111",
		execution: "execution-2222222222222222",
	})

	childWire := fixture.projectRecord(t, child)
	toolWire := fixture.projectRecord(t, tool)
	if childWire.Body.ParentSpanID != "" {
		t.Fatal("delegation lineage was rewritten as an unobserved OTel parent")
	}
	for key, want := range map[string]any{
		"gen_ai.agent.id": "agent-child", "defenseclaw.agent.root.id": "agent-root",
		"defenseclaw.agent.parent.id": "agent-root", "defenseclaw.agent.depth": jsonNumber("1"),
	} {
		if !reflect.DeepEqual(childWire.Body.Attributes[key], want) {
			t.Errorf("child %s = %#v, want %#v", key, childWire.Body.Attributes[key], want)
		}
	}
	assertAlias(t, childWire.Body.Attributes, "gen_ai.agent.type", "reviewer")
	assertAlias(t, toolWire.Body.Attributes, "connector", "openai_codex")
	assertAlias(t, toolWire.Body.Attributes, "gen_ai.agent.type", "reviewer")
	if toolWire.Body.ParentSpanID != "3132333435363738" ||
		toolWire.Body.Attributes["gen_ai.tool.name"] != "shell" ||
		toolWire.Body.Attributes["defenseclaw.destination.app"] != "local-shell" {
		t.Fatalf("tool compatibility shape = %+v", toolWire.Body)
	}
	for _, forbidden := range []string{
		"gen_ai.tool.call.arguments", "gen_ai.tool.call.result", "gen_ai.input.messages", "gen_ai.output.messages",
	} {
		if _, fabricated := toolWire.Body.Attributes[forbidden]; fabricated {
			t.Errorf("tool fabricated %s", forbidden)
		}
	}
}

func TestProjectionUsesOnlyPostRedactionValuesAndDoesNotMutateSource(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "strict", 4)
	record := fixture.modelRecord(t, modelRecordInput{
		traceID: "21212121212121212121212121212121", spanID: "5152535455565758",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex",
		lifecycle: "lifecycle-3333333333333333", execution: "execution-4444444444444444",
		content: "contact " + localRawPII,
	})
	outcome, err := fixture.pipeline.Process(record)
	if err != nil || len(outcome.OptionalWork()) != 1 {
		t.Fatalf("central projection err=%v work=%d", err, len(outcome.OptionalWork()))
	}
	central := outcome.OptionalWork()[0].Projection()
	before, _ := central.Bytes()
	result := Project(central)
	encoded, ok := result.Bytes()
	if !ok || bytes.Contains(encoded, []byte(localRawPII)) {
		t.Fatalf("local projection eligible=%v reason=%s leaked=%v", ok, result.Reason(), bytes.Contains(encoded, []byte(localRawPII)))
	}
	wire, decoded := decodeWire(encoded, true)
	if !decoded {
		t.Fatal("strict local compatibility projection did not decode")
	}
	if _, _, _, _, _, transportable := wire.otlp(fixture.destination.Name); !transportable {
		t.Fatal("strict local compatibility projection was not OTLP transportable")
	}
	after, _ := central.Bytes()
	if !bytes.Equal(before, after) {
		t.Fatal("local compatibility projection mutated the central route projection")
	}
	encoded[0] ^= 0xff
	detached, ok := result.Bytes()
	if !ok || !bytes.HasPrefix(detached, []byte("{")) {
		t.Fatal("compatibility result exposed mutable bytes")
	}
}

func TestConsumerRequiresExplicitCompatibilityProfileAndHasNoRawBypass(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 1)
	adapter := &captureAdapter{deliveries: make(chan [][]byte, 1), validate: true}
	options := ConsumerOptions{
		Destination: fixture.destination, Generation: 1, Pipeline: fixture.pipeline,
		Adapter: adapter, Dispatcher: dispatcherConfig(fixture.destination.Name, 1, 0),
		Observer: ObserverFunc(func(Failure) {}),
	}
	if consumer, err := NewConsumer(options); consumer != nil || !IsError(err, ErrorInvalidDependencies) {
		t.Fatal("consumer accepted an implicit compatibility profile")
	}
	options.Profile = ProfileID
	consumer, err := NewConsumer(options)
	if err != nil || consumer == nil {
		t.Fatal("consumer rejected the explicit generated compatibility profile")
	}
	for _, forbidden := range []string{"EnqueueRecord", "OnEnd", "ExportSpans", "EnqueueProjection"} {
		if _, exists := reflect.TypeOf(consumer).MethodByName(forbidden); exists {
			t.Fatalf("raw/legacy bypass method %q is public", forbidden)
		}
	}
	method, exists := reflect.TypeOf(consumer).MethodByName("TryEnqueue")
	if !exists || method.Type.In(1) != reflect.TypeOf(telemetry.V8CanonicalEndedSpan{}) {
		t.Fatalf("TryEnqueue signature = %+v exists=%v", method, exists)
	}
	shutdown(t, consumer)
}

func TestConsumerLifecycleQueueAndProjectionAreBounded(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 3)
	adapter := &captureAdapter{deliveries: make(chan [][]byte, 4), validate: true}
	observer := &failureObserver{}
	consumer, err := NewConsumer(ConsumerOptions{
		Destination: fixture.destination, Generation: 3, Profile: ProfileID, Pipeline: fixture.pipeline,
		Adapter: adapter, Dispatcher: dispatcherConfig(fixture.destination.Name, 1, time.Hour),
		Observer: observer,
	})
	if err != nil {
		t.Fatalf("consumer construction failed: %v", err)
	}
	record := fixture.agentRecord(t, agentRecordInput{
		traceID: "31313131313131313131313131313131", spanID: "6162636465666768",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
		lifecycle: "lifecycle-5555555555555555", execution: "execution-6666666666666666",
		phase: "planning", phaseCode: 2,
	})
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("prepared enqueue = %s", got)
	}
	consumer.Activate()
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("first enqueue = %s failures=%+v", got, observer.snapshot())
	}
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("queue-full enqueue = %s", got)
	}
	shutdown(t, consumer)
	shutdown(t, consumer)
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("closed enqueue = %s", got)
	}
	if got := consumer.Counters(); got.Accepted != 1 || got.QueueDropped != 1 || got.Closed != 2 {
		t.Fatalf("consumer counters = %+v", got)
	}
	if got := observer.snapshot(); !reflect.DeepEqual(got, []Failure{{
		Destination: fixture.destination.Name, Generation: 3, Code: FailureQueueFull,
	}}) {
		t.Fatalf("observer failures = %+v", got)
	}
}

func TestConsumerForceFlushLeavesIntakeLive(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 2)
	adapter := &captureAdapter{deliveries: make(chan [][]byte, 4), validate: true}
	consumer, err := NewConsumer(ConsumerOptions{
		Destination: fixture.destination, Generation: 2, Profile: ProfileID, Pipeline: fixture.pipeline,
		Adapter: adapter, Dispatcher: dispatcherConfig(fixture.destination.Name, 4, 0),
		Observer: ObserverFunc(func(Failure) {}),
	})
	if err != nil {
		t.Fatalf("consumer construction failed: %v", err)
	}
	consumer.Activate()
	for index := 0; index < 2; index++ {
		record := fixture.agentRecord(t, agentRecordInput{
			traceID: "41414141414141414141414141414141", spanID: fmt.Sprintf("%016x", 0x7172737475767700+index),
			agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
			lifecycle: "lifecycle-7777777777777777", execution: "execution-8888888888888888",
			phase: "planning", phaseCode: 2,
		})
		if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatalf("enqueue %d = %s", index, got)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := consumer.ForceFlush(ctx); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
	}
	shutdown(t, consumer)
}

func TestConsumerIsolatesProjectionPanicWithoutContent(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 5)
	observer := &failureObserver{}
	consumer, err := NewConsumer(ConsumerOptions{
		Destination: fixture.destination, Generation: 5, Profile: ProfileID, Pipeline: fixture.pipeline,
		Adapter:    &captureAdapter{deliveries: make(chan [][]byte, 1), validate: true},
		Dispatcher: dispatcherConfig(fixture.destination.Name, 1, 0), Observer: observer,
	})
	if err != nil {
		t.Fatal(err)
	}
	consumer.project = func(redaction.Projection) Result { panic("sensitive panic text") }
	consumer.Activate()
	record := fixture.agentRecord(t, agentRecordInput{
		traceID: "51515151515151515151515151515151", spanID: "8182838485868788",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
		lifecycle: "lifecycle-9999999999999999", execution: "execution-aaaaaaaaaaaaaaaa",
		phase: "planning", phaseCode: 2,
	})
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("panic enqueue = %s", got)
	}
	want := []Failure{{Destination: fixture.destination.Name, Generation: 5, Code: FailurePanic}}
	if got := observer.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("panic failure = %+v", got)
	}
	shutdown(t, consumer)
}

func TestCanonicalOnlyBoundaryRejectsCentralBytesWithoutCompatibilityProjection(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 6)
	record := fixture.agentRecord(t, agentRecordInput{
		traceID: "61616161616161616161616161616161", spanID: "9192939495969798",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
		lifecycle: "lifecycle-bbbbbbbbbbbbbbbb", execution: "execution-cccccccccccccccc",
		phase: "planning", phaseCode: 2,
	})
	outcome, err := fixture.pipeline.Process(record)
	if err != nil || len(outcome.OptionalWork()) != 1 {
		t.Fatalf("central projection err=%v work=%d", err, len(outcome.OptionalWork()))
	}
	rawCentral, err := outcome.OptionalWork()[0].Projection().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	forged := Result{reason: ProjectionEligible, encoded: rawCentral}
	if _, ok := NewPayload(forged, ""); ok {
		t.Fatal("payload boundary accepted central bytes without local compatibility projection")
	}
	if _, ok := (forged.Bytes()); !ok {
		t.Fatal("test forged result unexpectedly invalid before payload validation")
	}
}

func TestCanaryAcknowledgementRequiresExactTargetAndCompletePair(t *testing.T) {
	const traceID = "71717171717171717171717171717171"
	fixture := newLocalFixture(t, "none", 7)
	makePair := func(target string) (observability.Record, observability.Record) {
		root := fixture.agentRecord(t, agentRecordInput{
			traceID: traceID, spanID: "a1a2a3a4a5a6a7a8", agentID: "diagnostic",
			rootID: "diagnostic", agentType: "diagnostic", depth: 0,
			lifecycle: "lifecycle-dddddddddddddddd", execution: "execution-eeeeeeeeeeeeeeee",
			phase: "planning", phaseCode: 2, canaryTarget: target,
		})
		child := fixture.modelRecord(t, modelRecordInput{
			traceID: traceID, spanID: "b1b2b3b4b5b6b7b8", parentSpanID: "a1a2a3a4a5a6a7a8",
			agentID: "diagnostic", rootID: "diagnostic", agentType: "diagnostic",
			lifecycle: "lifecycle-dddddddddddddddd", execution: "execution-eeeeeeeeeeeeeeee",
			model: "gpt-4o-mini", canaryTarget: target,
		})
		return root, child
	}

	t.Run("complete exact pair", func(t *testing.T) {
		adapter := &captureAdapter{deliveries: make(chan [][]byte, 2), validate: true, acknowledgements: make(chan []string, 2)}
		// Leave enough room for both central projections to reach the queue even
		// when the package runs under race and repository-wide coverage load.
		// The split-batch case below separately proves that independently
		// delivered halves never produce a release-canary acknowledgement.
		consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 2, 250*time.Millisecond))
		root, child := makePair(fixture.destination.Name)
		consumer.Activate()
		if consumer.tryRecord(root) != telemetry.V8CanonicalSpanEnqueueAccepted ||
			consumer.tryRecord(child) != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatal("exact canary pair was not queued")
		}
		flush(t, consumer)
		if got := waitAcknowledgement(t, adapter.acknowledgements); !reflect.DeepEqual(got, []string{traceID}) {
			t.Fatalf("canary acknowledgement = %v", got)
		}
		shutdown(t, consumer)
	})

	t.Run("wrong target", func(t *testing.T) {
		adapter := &captureAdapter{deliveries: make(chan [][]byte, 2), validate: true, acknowledgements: make(chan []string, 2)}
		consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 2, 25*time.Millisecond))
		root, child := makePair("other-local")
		consumer.Activate()
		if consumer.tryRecord(root) != telemetry.V8CanonicalSpanEnqueueDropped ||
			consumer.tryRecord(child) != telemetry.V8CanonicalSpanEnqueueDropped {
			t.Fatal("wrong-target canary was not dropped before projection")
		}
		flush(t, consumer)
		if adapter.invalidRequests.Load() != 0 {
			t.Fatal("wrong-target canary reached the compatibility adapter")
		}
		select {
		case delivery := <-adapter.deliveries:
			t.Fatalf("wrong-target canary was delivered: %d records", len(delivery))
		default:
		}
		assertNoAcknowledgement(t, adapter.acknowledgements)
		shutdown(t, consumer)
	})

	t.Run("split batches", func(t *testing.T) {
		adapter := &captureAdapter{deliveries: make(chan [][]byte, 2), validate: true, acknowledgements: make(chan []string, 2)}
		consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 2, 0))
		root, child := makePair(fixture.destination.Name)
		consumer.Activate()
		if consumer.tryRecord(root) != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatal("split root enqueue failed")
		}
		flush(t, consumer)
		if got := waitAcknowledgement(t, adapter.acknowledgements); len(got) != 0 {
			t.Fatalf("partial root acknowledged: %v", got)
		}
		if consumer.tryRecord(child) != telemetry.V8CanonicalSpanEnqueueAccepted {
			t.Fatal("split child enqueue failed")
		}
		flush(t, consumer)
		if got := waitAcknowledgement(t, adapter.acknowledgements); len(got) != 0 {
			t.Fatalf("partial child acknowledged: %v", got)
		}
		shutdown(t, consumer)
	})
}

func TestConsumerReceivesCentralRedactionBeforeCompatibilityProjection(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "strict", 10)
	adapter := &captureAdapter{deliveries: make(chan [][]byte, 1), validate: true}
	consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 1, 0))
	original := consumer.project
	var projectCalls atomic.Uint64
	consumer.project = func(projection redaction.Projection) Result {
		projectCalls.Add(1)
		if projection.Metadata().RedactionProfile != "strict" {
			t.Errorf("compatibility projector received profile %q", projection.Metadata().RedactionProfile)
		}
		encoded, err := projection.Bytes()
		if err != nil || bytes.Contains(encoded, []byte(localRawPII)) {
			t.Error("compatibility projector observed pre-redaction content")
		}
		return original(projection)
	}
	consumer.Activate()
	record := fixture.modelRecord(t, modelRecordInput{
		traceID: "81818181818181818181818181818181", spanID: "c1c2c3c4c5c6c7c8",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex",
		lifecycle: "lifecycle-ffffffffffffffff", execution: "execution-1111111111111111",
		content: "contact " + localRawPII,
	})
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("strict enqueue = %s", got)
	}
	flush(t, consumer)
	if projectCalls.Load() != 1 {
		t.Fatalf("compatibility projection calls = %d", projectCalls.Load())
	}
	shutdown(t, consumer)
}

func TestShutdownCanRetryAfterInFlightDrainDeadline(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 11)
	deliveryGate := make(chan struct{})
	deliveryStarted := make(chan struct{}, 1)
	adapter := &captureAdapter{
		deliveries: make(chan [][]byte, 1), validate: true,
		deliveryGate: deliveryGate, deliveryStarted: deliveryStarted,
	}
	consumer := newTestConsumer(t, fixture, adapter, dispatcherConfig(fixture.destination.Name, 1, 0))
	consumer.Activate()
	record := fixture.agentRecord(t, agentRecordInput{
		traceID: "91919191919191919191919191919191", spanID: "d1d2d3d4d5d6d7d8",
		agentID: "agent-root", rootID: "agent-root", agentType: "codex", depth: 0,
		lifecycle: "lifecycle-2222222222222222", execution: "execution-3333333333333333",
		phase: "planning", phaseCode: 2,
	})
	if consumer.tryRecord(record) != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatal("in-flight record was not queued")
	}
	select {
	case <-deliveryStarted:
	case <-time.After(time.Second):
		t.Fatal("delivery did not enter the adapter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err := consumer.Shutdown(ctx)
	cancel()
	if err == nil {
		t.Fatal("shutdown unexpectedly completed while delivery was blocked")
	}
	if got := consumer.tryRecord(record); got != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("stopping consumer accepted intake: %s", got)
	}
	close(deliveryGate)
	shutdown(t, consumer)
	shutdown(t, consumer)
	if adapter.closeCalls.Load() != 1 {
		t.Fatalf("adapter close calls = %d, want one successful close", adapter.closeCalls.Load())
	}
}

func TestMissingCanonicalSourcesProduceNoCompatibilityAliases(t *testing.T) {
	t.Parallel()
	fixture := newLocalFixture(t, "none", 12)
	record := fixture.modelRecord(t, modelRecordInput{
		traceID: "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1", spanID: "e1e2e3e4e5e6e7e8",
		agentID: "agent-unknown-shape", omitConnector: true,
	})
	wire := fixture.projectRecord(t, record)
	for _, key := range []string{
		"connector", "gen_ai.agent.type", "defenseclaw.agent.root.id", "defenseclaw.agent.parent.id",
		"defenseclaw.agent.lifecycle.id", "defenseclaw.agent.execution.id", "defenseclaw.raw_action",
		"defenseclaw.decision", "defenseclaw.would_block", "gen_ai.usage.input_tokens",
		"gen_ai.usage.output_tokens", "gen_ai.input.messages", "gen_ai.output.messages",
	} {
		if _, present := wire.Body.Attributes[key]; present {
			t.Errorf("missing canonical source fabricated %q", key)
		}
	}
}

type localFixture struct {
	plan        *config.ObservabilityV8Plan
	destination config.ObservabilityV8EffectiveDestination
	pipeline    *pipeline.TraceProjectionPipeline
	generation  uint64
	sequence    atomic.Uint64
}

func newLocalFixture(t *testing.T, profile string, generation uint64) *localFixture {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "local-observability", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "http://127.0.0.1:4318",
			TLS:           config.ObservabilityV8TLSSource{Insecure: true},
			NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: profile,
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination("local-observability")
	if !ok {
		t.Fatal("local destination missing")
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x54}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tracePipeline, err := pipeline.NewTraceProjectionPipeline(plan, evaluator, engine)
	if err != nil {
		t.Fatal(err)
	}
	return &localFixture{plan: plan, destination: destination, pipeline: tracePipeline, generation: generation}
}

func (fixture *localFixture) projectRecord(t *testing.T, record observability.Record) projectedWire {
	t.Helper()
	outcome, err := fixture.pipeline.Process(record)
	if err != nil || len(outcome.OptionalWork()) != 1 || len(outcome.OptionalFailures()) != 0 {
		t.Fatalf("pipeline err=%v work=%d failures=%d", err, len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}
	result := Project(outcome.OptionalWork()[0].Projection())
	encoded, ok := result.Bytes()
	if !ok {
		t.Fatalf("compatibility projection = %s", result.Reason())
	}
	wire, ok := decodeWire(encoded, true)
	if !ok {
		t.Fatal("decode compatibility projection")
	}
	_, _, scope, _, _, ok := wire.otlp(fixture.destination.Name)
	if !ok {
		t.Fatal("compatibility projection did not produce a valid OTLP span")
	}
	if scope.DroppedAttributesCount != 11 {
		t.Fatalf("scope dropped attributes=%d want=11", scope.DroppedAttributesCount)
	}
	return wire
}

type agentRecordInput struct {
	traceID, spanID, parentSpanID, agentID, rootID, parentID, agentType string
	lifecycle, execution, phase                                         string
	depth, phaseCode                                                    int64
	canaryTarget                                                        string
}

func (fixture *localFixture) agentRecord(t *testing.T, input agentRecordInput) observability.Record {
	t.Helper()
	builder := fixture.builder(t)
	canary := observability.Absent[bool]()
	canaryOperation := observability.Absent[string]()
	canaryDestination := observability.Absent[string]()
	if input.canaryTarget != "" {
		canary = observability.Present(true)
		canaryOperation = observability.Present(canaryOperationTag)
		canaryDestination = observability.Present(input.canaryTarget)
	}
	record, err := builder.BuildSpanAgentInvoke(observability.SpanAgentInvokeInput{
		Envelope: fixture.envelope(input.traceID, input.spanID, input.agentID),
		Outcome:  observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_000_000_001, EndTimeUnixNano: 1_783_278_000_100_000_001,
		ParentSpanID: optionalString(input.parentSpanID), TraceState: observability.Present("dc=local-observability"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: traceResource(),
		Scope:               observability.TraceScopeInput{DroppedAttributesCount: observability.Present[uint32](11)},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-local", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-local",
		DefenseClawConnectorSource:    observability.Present("openai_codex"), DefenseClawOperationID: observability.Present("agent-op"),
		DefenseClawTelemetryCanary: canary, DefenseClawTelemetryCanaryOperation: canaryOperation,
		DefenseClawTelemetryCanaryDestination: canaryDestination,
		GenAIConversationID:                   observability.Present("conversation-root"), GenAIAgentID: observability.Present(input.agentID),
		GenAIAgentName: observability.Present(input.agentID), DefenseClawAgentType: input.agentType,
		DefenseClawAgentRootID: observability.Present(input.rootID), DefenseClawAgentParentID: optionalString(input.parentID),
		DefenseClawSessionRootID: observability.Present("conversation-root"), DefenseClawAgentLifecycleID: observability.Present(input.lifecycle),
		DefenseClawAgentExecutionID: observability.Present(input.execution), DefenseClawAgentDepth: observability.Present(input.depth),
		DefenseClawAgentLifecycleEvent: observability.Present("session_start"), DefenseClawAgentLifecycleState: observability.Present("active"),
		DefenseClawAgentPhase: observability.Present(input.phase), DefenseClawAgentPhaseCode: observability.Present(input.phaseCode),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("invoke_agent"), ConditionConnectorKnown: true, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

type modelRecordInput struct {
	traceID, spanID, parentSpanID, agentID, rootID, agentType, lifecycle, execution, content string
	decision                                                                                 string
	wouldBlock                                                                               bool
	model, canaryTarget                                                                      string
	omitConnector                                                                            bool
}

func (fixture *localFixture) modelRecord(t *testing.T, input modelRecordInput) observability.Record {
	t.Helper()
	model := input.model
	if model == "" {
		model = "gpt-5.5"
	}
	envelope := fixture.envelope(input.traceID, input.spanID, input.agentID)
	connector := observability.Present("openai_codex")
	connectorKnown := true
	if input.omitConnector {
		envelope.Connector = ""
		connector = observability.Absent[string]()
		connectorKnown = false
	}
	canary := observability.Absent[bool]()
	canaryOperation := observability.Absent[string]()
	canaryDestination := observability.Absent[string]()
	if input.canaryTarget != "" {
		canary = observability.Present(true)
		canaryOperation = observability.Present(canaryOperationTag)
		canaryDestination = observability.Present(input.canaryTarget)
	}
	messages := observability.Absent[observability.TelemetryStructuredGenAIInputMessages]()
	reported, state := false, "not_reported"
	if input.content != "" {
		reported, state = true, "preserved"
		messages = observability.Present(observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
			Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
				observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: input.content}},
			}},
		}}})
	}
	events := []observability.TraceEventInput(nil)
	if input.decision != "" {
		event, err := observability.NewSpanModelChatGuardrailDecisionEvent(observability.SpanModelChatGuardrailDecisionEventInput{
			TimeUnixNano:                        1_783_278_000_250_000_001,
			DefenseClawGuardrailDecision:        observability.Present("block"),
			DefenseClawGuardrailEffectiveAction: observability.Present(input.decision),
			DefenseClawGuardrailWouldBlock:      observability.Present(input.wouldBlock),
		})
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	record, err := fixture.builder(t).BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: envelope,
		Outcome:  observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: 1_783_278_000_200_000_001, EndTimeUnixNano: 1_783_278_000_300_000_001,
		ParentSpanID: optionalString(input.parentSpanID), TraceState: observability.Present("dc=local-observability"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: traceResource(),
		Scope:               observability.TraceScopeInput{DroppedAttributesCount: observability.Present[uint32](11)},
		Events:              events,
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-local", ResourceDeploymentEnvironmentName: "test", ResourceDefenseClawInstanceID: "instance-local",
		DefenseClawConnectorSource: connector, DefenseClawOperationID: observability.Present("model-op"),
		DefenseClawTelemetryCanary: canary, DefenseClawTelemetryCanaryOperation: canaryOperation,
		DefenseClawTelemetryCanaryDestination: canaryDestination,
		GenAIConversationID:                   observability.Present("conversation-root"), GenAIAgentID: observability.Present(input.agentID),
		DefenseClawAgentType: optionalString(input.agentType), DefenseClawAgentRootID: optionalString(input.rootID),
		DefenseClawSessionRootID: observability.Present("conversation-root"), DefenseClawAgentLifecycleID: optionalString(input.lifecycle),
		DefenseClawAgentExecutionID: optionalString(input.execution), DefenseClawAgentReportedCostPresent: false,
		GenAIInputMessages: messages, DefenseClawTelemetryInputReported: reported, DefenseClawContentInputState: state,
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("chat"), GenAIProviderName: observability.Present("openai"),
		GenAIRequestModel: model, DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionConnectorKnown: connectorKnown, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

type toolRecordInput struct {
	traceID, spanID, parentSpanID, agentID, rootID, parentID, agentType, lifecycle, execution string
}

func (fixture *localFixture) toolRecord(t *testing.T, input toolRecordInput) observability.Record {
	t.Helper()
	record, err := fixture.builder(t).BuildSpanToolExecute(observability.SpanToolExecuteInput{
		Envelope: fixture.envelope(input.traceID, input.spanID, input.agentID),
		Outcome:  observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_400_000_001, EndTimeUnixNano: 1_783_278_000_500_000_001,
		ParentSpanID: optionalString(input.parentSpanID), TraceState: observability.Present("dc=local-observability"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(), Resource: traceResource(),
		Scope:               observability.TraceScopeInput{DroppedAttributesCount: observability.Present[uint32](11)},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-local", ResourceDeploymentEnvironmentName: "test", ResourceDefenseClawInstanceID: "instance-local",
		DefenseClawConnectorSource: observability.Present("openai_codex"), DefenseClawOperationID: observability.Present("tool-op"),
		DefenseClawDestinationApp: observability.Present("local-shell"), GenAIConversationID: observability.Present("conversation-root"),
		GenAIAgentID: observability.Present(input.agentID), DefenseClawAgentType: optionalString(input.agentType),
		DefenseClawAgentRootID: optionalString(input.rootID), DefenseClawAgentParentID: optionalString(input.parentID),
		DefenseClawSessionRootID: observability.Present("conversation-root"), DefenseClawAgentLifecycleID: optionalString(input.lifecycle),
		DefenseClawAgentExecutionID: optionalString(input.execution), DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported: false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("execute_tool"), GenAIToolName: "shell",
		GenAIToolType: observability.Present("function"), GenAIToolCallID: observability.Present("tool-call-1"),
		DefenseClawToolProvider: observability.Present("builtin"), DefenseClawToolStatus: observability.Present("completed"),
		ConditionConnectorKnown: true, ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *localFixture) diagnosticRecord(t *testing.T) observability.Record {
	t.Helper()
	record, err := fixture.builder(t).BuildSpanDiagnosticCanary(observability.SpanDiagnosticCanaryInput{
		Envelope: fixture.envelope("91919191919191919191919191919191", "d1d2d3d4d5d6d7d8", ""),
		Outcome:  observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: 1_783_278_000_600_000_001, EndTimeUnixNano: 1_783_278_000_700_000_001,
		TraceState: observability.Present("dc=local-diagnostic"), Flags: 0x101,
		Status: observability.NewTraceStatusOK(), Resource: traceResource(),
		Scope:               observability.TraceScopeInput{DroppedAttributesCount: observability.Present[uint32](11)},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-local", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-local",
		DefenseClawDestinationID:      observability.Present(fixture.destination.Name),
		DefenseClawDestinationSignal:  observability.Present("traces"),
		ConditionOperationTerminal:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func (fixture *localFixture) envelope(traceID, spanID, agentID string) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway, Connector: "openai_codex",
		Correlation: observability.Correlation{TraceID: traceID, SpanID: spanID, AgentID: agentID},
		Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: "8.0.0", ConfigGeneration: int64(fixture.generation),
			ConfigDigest: fixture.plan.Digest(),
		},
	}
}

func (fixture *localFixture) builder(t *testing.T) *observability.FamilyBuilder {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Date(2026, 7, 5, 22, 0, 0, 0, time.UTC) }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("local-projection-%d", fixture.sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func traceResource() observability.TraceResourceInput {
	return observability.TraceResourceInput{SchemaURL: "https://opentelemetry.io/schemas/1.42.0"}
}

func optionalString(value string) observability.Optional[string] {
	if value == "" {
		return observability.Absent[string]()
	}
	return observability.Present(value)
}

func assertAlias(t *testing.T, attributes map[string]any, key string, want any) {
	t.Helper()
	if got := attributes[key]; !reflect.DeepEqual(got, want) {
		t.Errorf("alias %s = %#v, want %#v", key, got, want)
	}
}

func jsonNumber(value string) any { return json.Number(value) }

type captureAdapter struct {
	deliveries       chan [][]byte
	acknowledgements chan []string
	deliveryGate     chan struct{}
	deliveryStarted  chan struct{}
	validate         bool
	closeCalls       atomic.Uint64
	invalidRequests  atomic.Uint64
}

func (*captureAdapter) EncodedSize(sizes []int) (int, bool) {
	total := 1
	for _, size := range sizes {
		total += size
	}
	return total, true
}

func (adapter *captureAdapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter.deliveryStarted != nil {
		select {
		case adapter.deliveryStarted <- struct{}{}:
		default:
		}
	}
	if adapter.deliveryGate != nil {
		select {
		case <-adapter.deliveryGate:
		case <-ctx.Done():
			return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
		}
	}
	if adapter.validate {
		request, ok := (RequestBuilder{}).BuildProjectedTraceRequest(batch.Destination(), batch)
		if !ok {
			adapter.invalidRequests.Add(1)
			return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
		}
		if adapter.acknowledgements != nil {
			acknowledged := append([]string(nil), request.CanaryTraceIDs...)
			select {
			case adapter.acknowledgements <- acknowledged:
			default:
			}
		}
	}
	items := batch.Items()
	encoded := make([][]byte, len(items))
	for index := range items {
		encoded[index] = items[index].Bytes()
	}
	select {
	case adapter.deliveries <- encoded:
	default:
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *captureAdapter) Close(context.Context) error {
	adapter.closeCalls.Add(1)
	return nil
}

type failureObserver struct {
	mu     sync.Mutex
	events []Failure
}

func (observer *failureObserver) ObserveLocalObservabilityFailure(failure Failure) {
	observer.mu.Lock()
	observer.events = append(observer.events, failure)
	observer.mu.Unlock()
}

func (observer *failureObserver) snapshot() []Failure {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return append([]Failure(nil), observer.events...)
}

func dispatcherConfig(destination string, queue int, delay time.Duration) delivery.Config {
	return delivery.Config{
		Destination: destination, Enabled: true, MaxQueueItems: queue, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: queue, MaxBatchBytes: 8 * 1024 * 1024, ScheduledDelay: delay,
		AttemptTimeout: time.Second, Retry: delivery.RetryPolicy{MaxAttempts: 1},
		Observer: delivery.ObserverFunc(func(delivery.HealthTransition) {}),
	}
}

func newTestConsumer(
	t *testing.T,
	fixture *localFixture,
	adapter TraceAdapter,
	dispatcher delivery.Config,
) *Consumer {
	t.Helper()
	consumer, err := NewConsumer(ConsumerOptions{
		Destination: fixture.destination, Generation: fixture.generation, Profile: ProfileID,
		Pipeline: fixture.pipeline, Adapter: adapter, Dispatcher: dispatcher,
		Observer: ObserverFunc(func(Failure) {}),
	})
	if err != nil {
		t.Fatal(err)
	}
	return consumer
}

func flush(t *testing.T, consumer *Consumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitAcknowledgement(t *testing.T, acknowledgements <-chan []string) []string {
	t.Helper()
	select {
	case acknowledged := <-acknowledgements:
		return acknowledged
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for canary acknowledgement result")
		return nil
	}
}

func assertNoAcknowledgement(t *testing.T, acknowledgements <-chan []string) {
	t.Helper()
	select {
	case acknowledged := <-acknowledgements:
		t.Fatalf("unexpected canary acknowledgement result: %v", acknowledged)
	case <-time.After(25 * time.Millisecond):
	}
}

func shutdown(t *testing.T, consumer *Consumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
