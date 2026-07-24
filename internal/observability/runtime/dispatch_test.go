// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type runtimeAdapterFactoryFunc func(
	context.Context,
	config.ObservabilityV8EffectiveDestination,
	telemetry.V8ResourceContext,
) (delivery.Adapter, DestinationAdapterCleanup, error)

func (function runtimeAdapterFactoryFunc) PrepareDestination(
	ctx context.Context,
	destination config.ObservabilityV8EffectiveDestination,
	resource telemetry.V8ResourceContext,
) (delivery.Adapter, DestinationAdapterCleanup, error) {
	return function(ctx, destination, resource)
}

type runtimeDeliveredItem struct {
	destination string
	bytes       []byte
	identity    delivery.RoutingIdentity
}

type runtimeRecordingAdapter struct {
	delivered chan runtimeDeliveredItem
	started   chan struct{}
	release   <-chan struct{}
	outcome   delivery.DeliveryOutcome
	startOnce sync.Once
}

type runtimeBlockingObserver struct {
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func (observer *runtimeBlockingObserver) Observe(delivery.HealthTransition) {
	observer.once.Do(func() { close(observer.started) })
	<-observer.release
}

func newRuntimeRecordingAdapter(buffer int) *runtimeRecordingAdapter {
	return &runtimeRecordingAdapter{
		delivered: make(chan runtimeDeliveredItem, buffer),
		started:   make(chan struct{}),
		outcome:   delivery.OutcomeDelivered,
	}
}

func (*runtimeRecordingAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 1, 0)
}

func (adapter *runtimeRecordingAdapter) Deliver(
	ctx context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	adapter.startOnce.Do(func() { close(adapter.started) })
	for _, item := range batch.Items() {
		adapter.delivered <- runtimeDeliveredItem{
			destination: batch.Destination(), bytes: item.Bytes(), identity: item.Identity(),
		}
	}
	if adapter.release != nil {
		select {
		case <-adapter.release:
		case <-ctx.Done():
			return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
		}
	}
	return delivery.DeliveryResult{Outcome: adapter.outcome}
}

func runtimeConsoleDestination(name, profile string, queueSize int) config.ObservabilityV8DestinationSource {
	logs := []observability.Signal{observability.SignalLogs}
	buckets := []observability.Bucket{"*"}
	destination := config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationConsole,
		Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: buckets, RedactionProfile: profile,
		},
	}
	if queueSize > 0 {
		destination.Batch.MaxQueueSize = queueSize
	}
	return destination
}

func runtimeOTLPLogDestination(name string) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: "https://8.8.8.8:4318",
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalLogs},
			Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
		},
		Batch: config.ObservabilityV8BatchSource{ScheduledDelayMS: 1},
	}
}

func runtimeWithAdapterFactory(
	t *testing.T,
	dependencies runtimeTestDependencies,
	plan *config.ObservabilityV8Plan,
	factory DestinationAdapterFactory,
	observer delivery.Observer,
) *Runtime {
	t.Helper()
	options := dependencies.options()
	options.DestinationAdapterFactory = factory
	options.DestinationObserver = observer
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close observability runtime: %v", err)
		}
	})
	return runtime
}

func runtimeContentRecordBuilder(recordID, content string) EmitBuilder {
	return func(snapshot EmitContext, _ router.Admission) (observability.Record, error) {
		builder, err := observability.NewRecordBuilder(
			observability.ClockFunc(func() time.Time {
				return time.Date(2026, 7, 3, 16, 0, 0, 0, time.UTC)
			}),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
		)
		if err != nil {
			return observability.Record{}, err
		}
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind: observability.ProducerGatewayEvent, ProducerKey: "diagnostic",
			ClassificationContext: observability.ClassificationContext{RawSeverity: "INFO"},
			Source:                observability.SourceSystem, Action: "diagnostic",
			Outcome: observability.OutcomeCompleted,
			Provenance: observability.Provenance{
				Producer: "runtime_dispatch_test", BinaryVersion: "test",
				RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
				ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
			Body: map[string]any{"message": content},
			FieldClasses: map[string]observability.FieldClass{
				"/message": observability.FieldClassContent,
			},
		})
	}
}

func receiveRuntimeDelivery(t *testing.T, adapter *runtimeRecordingAdapter) runtimeDeliveredItem {
	t.Helper()
	select {
	case item := <-adapter.delivered:
		return item
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for optional delivery")
		return runtimeDeliveredItem{}
	}
}

func TestOTLPInboundDestinationFanoutAndRedactionIsolation(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("raw-console", "none", 0),
				runtimeConsoleDestination("strict-console", "strict", 0),
			}
		},
	)
	adapters := map[string]*runtimeRecordingAdapter{}
	var mutex sync.Mutex
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		adapter := newRuntimeRecordingAdapter(2)
		mutex.Lock()
		adapters[destination.Name] = adapter
		mutex.Unlock()
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)

	const recordID = "runtime-dispatch-fanout"
	const content = "dispatch-person@example.test"
	outcome, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder(recordID, content),
	)
	if err != nil || !outcome.LocalPersisted() {
		t.Fatalf("emit persisted=%t err=%v", outcome.LocalPersisted(), err)
	}
	raw := receiveRuntimeDelivery(t, adapters["raw-console"])
	strict := receiveRuntimeDelivery(t, adapters["strict-console"])
	if raw.destination != "raw-console" || strict.destination != "strict-console" ||
		raw.identity.RecordID != recordID || raw.identity.Bucket != string(observability.BucketDiagnostic) ||
		raw.identity.Signal != string(observability.SignalLogs) || raw.identity.EventName != "diagnostic.message" ||
		raw.identity.OriginDestination != "" {
		t.Fatalf("unexpected projected delivery identities raw=%#v strict=%#v", raw.identity, strict.identity)
	}
	if !bytes.Contains(raw.bytes, []byte(content)) || bytes.Contains(strict.bytes, []byte(content)) ||
		bytes.Equal(raw.bytes, strict.bytes) {
		t.Fatal("destination projections did not retain distinct redacted bytes")
	}
	events, err := dependencies.store.ListEvents(16)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.ID == recordID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SQLite count=%d, want exactly one", count)
	}
}

func TestQueueOnlyDispatcherSeparatesProjectedQueueBytesFromEncodedWriteBytes(t *testing.T) {
	destination := config.ObservabilityV8EffectiveDestination{
		Name: "bounded-console", Kind: config.ObservabilityV8DestinationConsole,
		Enabled: true, SelectedSignals: []observability.Signal{observability.SignalLogs},
		Transport: config.ObservabilityV8TransportPlan{
			Batch: &config.ObservabilityV8BatchSource{
				MaxQueueSize: 1, MaxQueueBytes: 4_198_400,
			},
		},
	}
	compiled, ok := CompiledDispatcherConfig(destination, 1, observability.SignalLogs, nil)
	if !ok {
		t.Fatal("queue-only destination did not compile")
	}
	if compiled.MaxBatchItems != 1 || compiled.MaxBatchBytes != maxDestinationBatchBytes {
		t.Fatalf("queue-only batch limits = (%d,%d), want (1,%d)",
			compiled.MaxBatchItems, compiled.MaxBatchBytes, maxDestinationBatchBytes)
	}
	if compiled.MaxQueueBytes != 4_198_400 {
		t.Fatalf("projected queue byte ceiling changed to %d", compiled.MaxQueueBytes)
	}
	if _, ok := CompiledDispatcherConfig(destination, 0, observability.SignalLogs, nil); ok {
		t.Fatal("zero generation dispatcher config compiled")
	}
	if _, ok := CompiledDispatcherConfig(destination, 1, observability.Signal("future"), nil); ok {
		t.Fatal("unknown signal dispatcher config compiled")
	}
}

func TestRuntimeEmitLocalOnlyPersistsWithoutOptionalProjectionOrFanout(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("must-not-receive", "none", 0),
			}
		},
	)
	adapter := newRuntimeRecordingAdapter(1)
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	const recordID = "runtime-local-only"
	outcome, err := runtime.EmitLocalOnly(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder(recordID, "must stay local"),
	)
	if err != nil || !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 ||
		len(outcome.OptionalFailures()) != 0 {
		t.Fatalf("local-only outcome persisted=%t work=%d failures=%d err=%v",
			outcome.LocalPersisted(), len(outcome.OptionalWork()), len(outcome.OptionalFailures()), err)
	}
	select {
	case item := <-adapter.delivered:
		t.Fatalf("local-only record reached destination: %#v", item.identity)
	case <-time.After(100 * time.Millisecond):
	}
	events, err := dependencies.store.ListEvents(16)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.ID == recordID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("local-only SQLite count=%d, want exactly one", count)
	}
}

func TestRuntimeAdapterFactoryReceivesDetachedUnmaskedRuntimeDestination(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "unmasked-http", Kind: config.ObservabilityV8DestinationHTTPJSONL,
				Endpoint: "https://collector.example.test/v1/logs?tenant=secret-value",
				Headers: map[string]config.ObservabilityV8HeaderValue{
					"X-Test-Key": config.ObservabilityV8StaticHeader("top-secret"),
				},
			}}
		},
	)
	displayed, ok := plan.Destination("unmasked-http")
	if !ok || displayed.Transport.Endpoint == "https://collector.example.test/v1/logs?tenant=secret-value" ||
		displayed.Transport.Headers["X-Test-Key"].Static == nil ||
		*displayed.Transport.Headers["X-Test-Key"].Static == "top-secret" {
		t.Fatal("display destination was not masked before adapter preparation")
	}
	var prepared atomic.Bool
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		header := destination.Transport.Headers["X-Test-Key"]
		if destination.Transport.Endpoint != "https://collector.example.test/v1/logs?tenant=secret-value" ||
			header.Static == nil || *header.Static != "top-secret" {
			return nil, func(context.Context) error { return nil }, errors.New("masked runtime destination")
		}
		// Mutating this detached value must not alter either plan view.
		destination.Transport.Endpoint = "https://mutated.invalid"
		prepared.Store(true)
		return newRuntimeRecordingAdapter(1), func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	activeDisplayed, activeOK := runtime.Active().Plan().Destination("unmasked-http")
	if !prepared.Load() || !activeOK || activeDisplayed.Transport.Endpoint != displayed.Transport.Endpoint {
		t.Fatal("adapter preparation did not receive an isolated runtime destination")
	}
}

func TestRuntimeOptionalQueueFullAndDeliveryFailureNeverFailProducerOrPeer(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("blocked", "none", 1),
				runtimeConsoleDestination("healthy", "none", 4),
			}
		},
	)
	release := make(chan struct{})
	blocked := newRuntimeRecordingAdapter(4)
	blocked.release = release
	blocked.outcome = delivery.OutcomePermanentPayload
	healthy := newRuntimeRecordingAdapter(4)
	var transitions atomic.Int64
	observer := delivery.ObserverFunc(func(delivery.HealthTransition) { transitions.Add(1) })
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		if destination.Name == "blocked" {
			return blocked, func(context.Context) error { return nil }, nil
		}
		return healthy, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, observer)

	firstDone := make(chan error, 1)
	go func() {
		_, err := runtime.Emit(
			context.Background(), diagnosticMetadata(t),
			runtimeContentRecordBuilder("runtime-queue-first", "first"),
		)
		firstDone <- err
	}()
	select {
	case err := <-firstDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("producer waited for optional destination I/O")
	}
	select {
	case <-blocked.started:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked adapter did not begin delivery")
	}

	second, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-queue-second", "second"),
	)
	if err != nil || !second.LocalPersisted() {
		t.Fatalf("second emit persisted=%t err=%v", second.LocalPersisted(), err)
	}
	_ = receiveRuntimeDelivery(t, healthy)
	_ = receiveRuntimeDelivery(t, healthy)

	lease, graphErr := runtime.manager.Acquire(t.Context())
	if graphErr != nil {
		t.Fatal(graphErr)
	}
	componentValue, ok := lease.Component(DestinationDispatchComponentName)
	component := componentValue.(*destinationDispatchComponent)
	counters := component.byName["blocked"].dispatcher.Counters()
	lease.Release()
	if !ok || counters.Accepted != 1 || counters.Dropped != 1 {
		t.Fatalf("blocked destination counters=%+v", counters)
	}
	close(release)
	_ = receiveRuntimeDelivery(t, blocked)
	deadline := time.Now().Add(time.Second)
	for transitions.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if transitions.Load() == 0 {
		t.Fatal("bounded destination observer saw no health transitions")
	}
	events, err := dependencies.store.ListEvents(16)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, event := range events {
		seen[event.ID]++
	}
	if seen["runtime-queue-first"] != 1 || seen["runtime-queue-second"] != 1 {
		t.Fatalf("local persistence counts=%v", seen)
	}
}

func TestRuntimeBlockingOrPanickingHealthObserverCannotBlockProducer(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("observer-console", "none", 2),
			}
		},
	)
	adapter := newRuntimeRecordingAdapter(2)
	release := make(chan struct{})
	observer := &runtimeBlockingObserver{started: make(chan struct{}), release: release}
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, observer)
	select {
	case <-observer.started:
	case <-time.After(5 * time.Second):
		t.Fatal("observer did not receive activation health")
	}
	emitDone := make(chan error, 1)
	go func() {
		_, err := runtime.Emit(
			context.Background(), diagnosticMetadata(t),
			runtimeContentRecordBuilder("runtime-blocked-observer", "content"),
		)
		emitDone <- err
	}()
	select {
	case err := <-emitDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("producer waited for blocked health observer")
	}
	_ = receiveRuntimeDelivery(t, adapter)
	close(release)

	// Panic isolation is exercised independently so a recovered panic cannot
	// be mistaken for the blocked callback above being merely dropped.
	panicking := newSafeDeliveryObserver(delivery.ObserverFunc(func(delivery.HealthTransition) {
		panic("observer must not escape")
	}))
	panicking.Observe(delivery.HealthTransition{Destination: "observer-console"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := panicking.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRemovedDestinationDrainsOldGenerationAndCancellationDoesNotFanout(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	withDestination := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("removed-console", "none", 2),
			}
		},
	)
	withoutDestination := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	release := make(chan struct{})
	adapter := newRuntimeRecordingAdapter(2)
	adapter.release = release
	var cleanups atomic.Int64
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		_ config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { cleanups.Add(1); return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, withDestination, factory, nil)
	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-removed-old", "old"),
	); err != nil {
		t.Fatal(err)
	}
	_ = receiveRuntimeDelivery(t, adapter)

	reloadDone := make(chan error, 1)
	go func() {
		result, graphErr := runtime.Reload(
			context.Background(), runtimegraph.ConfigFromPlan(withoutDestination, false),
		)
		var reloadErr error
		if graphErr != nil {
			reloadErr = graphErr
		}
		if graphErr == nil && result.Status() != runtimegraph.ReloadApplied {
			reloadErr = fmt.Errorf("reload status=%s", result.Status())
		}
		reloadDone <- reloadErr
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 || cleanups.Load() != 0 {
		t.Fatalf("removed destination generation=%d cleanup=%d", runtime.Active().Generation(), cleanups.Load())
	}
	if outcome, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-removed-new", "new"),
	); err != nil || !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 {
		t.Fatalf("new generation emit persisted=%t optional=%d err=%v",
			outcome.LocalPersisted(), len(outcome.OptionalWork()), err)
	}
	close(release)
	select {
	case err := <-reloadDone:
		if err != nil {
			var graphErr *runtimegraph.Error
			if errors.As(err, &graphErr) {
				t.Fatalf("removed destination reload error code=%s component=%s", graphErr.Code(), graphErr.ComponentName())
			}
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removed destination did not drain")
	}
	if cleanups.Load() != 1 {
		t.Fatalf("removed destination cleanup=%d", cleanups.Load())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, err := runtime.Emit(
		cancelled, diagnosticMetadata(t),
		runtimeContentRecordBuilder("runtime-cancelled-no-fanout", "cancelled"),
	)
	if err == nil || !errors.Is(err, context.Canceled) || outcome.LocalPersisted() {
		t.Fatalf("cancelled emit persisted=%t err=%v", outcome.LocalPersisted(), err)
	}
	events, listErr := dependencies.store.ListEvents(16)
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, event := range events {
		if event.ID == "runtime-cancelled-no-fanout" {
			t.Fatal("cancelled record reached SQLite")
		}
	}
}

func TestRuntimeOTLPLogResourceIsProviderBoundAndRetainedAcrossReload(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	makePlan := func(generation string, aliases bool) *config.ObservabilityV8Plan {
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Resource.Attributes = map[string]string{"team.generation": generation}
				source.TracePolicy.CompatibilityAliases = &aliases
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeOTLPLogDestination("otel-logs"),
				}
			},
		)
	}
	oldRelease := make(chan struct{})
	var mutex sync.Mutex
	var adapters []*runtimeRecordingAdapter
	var resources []telemetry.V8ResourceContext
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		resource telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		if destination.Kind != config.ObservabilityV8DestinationOTLP || resource.SchemaURL() == "" {
			return nil, func(context.Context) error { return nil }, errors.New("missing provider resource")
		}
		adapter := newRuntimeRecordingAdapter(2)
		mutex.Lock()
		if len(adapters) == 0 {
			adapter.release = oldRelease
		}
		adapters = append(adapters, adapter)
		resources = append(resources, resource)
		mutex.Unlock()
		return adapter, func(context.Context) error { return nil }, nil
	})
	initial := makePlan("generation-one", true)
	options := dependencies.options()
	options.DestinationAdapterFactory = factory
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "runtime-resource-test", Environment: "test",
		ServiceInstanceID: "runtime-resource-instance", DefenseClawInstanceID: "runtime-resource-defenseclaw",
	})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(initial, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = runtime.Close(closeContext)
	})

	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("runtime-resource-old", "old"),
	); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	oldAdapter := adapters[0]
	mutex.Unlock()
	_ = receiveRuntimeDelivery(t, oldAdapter)

	reloadDone := make(chan error, 1)
	go func() {
		result, graphErr := runtime.Reload(
			context.Background(), runtimegraph.ConfigFromPlan(makePlan("generation-two", false), false),
		)
		var reloadErr error
		if graphErr != nil {
			reloadErr = graphErr
		}
		if reloadErr == nil && result.Status() != runtimegraph.ReloadApplied {
			reloadErr = fmt.Errorf("reload status=%s", result.Status())
		}
		reloadDone <- reloadErr
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 {
		t.Fatal("new resource generation did not publish while old OTLP log queue drained")
	}
	mutex.Lock()
	if len(resources) != 2 || len(adapters) != 2 {
		mutex.Unlock()
		t.Fatalf("prepared resources=%d adapters=%d", len(resources), len(adapters))
	}
	oldValues := resources[0].Values()
	newValues := resources[1].Values()
	oldDropped := resources[0].ResourceDroppedAttributesCount()
	newDropped := resources[1].ResourceDroppedAttributesCount()
	newAdapter := adapters[1]
	mutex.Unlock()
	if oldValues["team.generation"] != "generation-one" ||
		oldValues["deployment.environment"] != oldValues["deployment.environment.name"] ||
		oldDropped != 0 {
		t.Fatalf("old OTLP resource=%+v", oldValues)
	}
	if newValues["team.generation"] != "generation-two" ||
		newValues["deployment.environment"] != "" || newValues["deployment.mode"] != "" ||
		newValues["defenseclaw.device.id"] != "" || newDropped != 0 {
		t.Fatalf("new OTLP resource=%+v", newValues)
	}
	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("runtime-resource-new", "new"),
	); err != nil {
		t.Fatal(err)
	}
	_ = receiveRuntimeDelivery(t, newAdapter)
	if got := resources[0].Values()["team.generation"]; got != "generation-one" {
		t.Fatalf("old queued generation resource changed after reload: %q", got)
	}
	close(oldRelease)
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("reload error type=%T value=%#v", err, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not finish after old OTLP log queue drained")
	}
}

func TestRuntimeRejectsOTLPLogDestinationWithoutProviderResourceFactory(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeOTLPLogDestination("otel-logs"),
			}
		},
	)
	var called atomic.Bool
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		called.Store(true)
		return newRuntimeRecordingAdapter(1), func(context.Context) error { return nil }, nil
	})
	options := dependencies.options()
	options.DestinationAdapterFactory = factory
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if runtime != nil || err == nil || called.Load() {
		t.Fatalf("runtime=%p error=%v adapter-called=%t", runtime, err, called.Load())
	}
}

func TestRuntimeReloadKeepsOldProjectedBytesWithOldQueueGeneration(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	makePlan := func(profile string) *config.ObservabilityV8Plan {
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("reload-console", profile, 2),
				}
			},
		)
	}
	oldRelease := make(chan struct{})
	var factoryMu sync.Mutex
	var prepared []*runtimeRecordingAdapter
	var cleanupCount atomic.Int64
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		_ config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		adapter := newRuntimeRecordingAdapter(2)
		factoryMu.Lock()
		if len(prepared) == 0 {
			adapter.release = oldRelease
		}
		prepared = append(prepared, adapter)
		factoryMu.Unlock()
		return adapter, func(context.Context) error { cleanupCount.Add(1); return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, makePlan("none"), factory, nil)
	const content = "reload-person@example.test"
	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("runtime-reload-old", content),
	); err != nil {
		t.Fatal(err)
	}
	oldDelivery := receiveRuntimeDelivery(t, prepared[0])

	reloadDone := make(chan error, 1)
	go func() {
		result, err := runtime.Reload(
			context.Background(), runtimegraph.ConfigFromPlan(makePlan("strict"), false),
		)
		if err != nil {
			reloadDone <- err
			return
		}
		if result.Status() != runtimegraph.ReloadApplied {
			reloadDone <- fmt.Errorf("reload status=%s", result.Status())
			return
		}
		reloadDone <- nil
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 {
		t.Fatal("candidate graph did not publish while old queue drained")
	}
	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("runtime-reload-new", content),
	); err != nil {
		t.Fatal(err)
	}
	factoryMu.Lock()
	newAdapter := prepared[1]
	factoryMu.Unlock()
	newDelivery := receiveRuntimeDelivery(t, newAdapter)
	if !bytes.Contains(oldDelivery.bytes, []byte(content)) || bytes.Contains(newDelivery.bytes, []byte(content)) {
		t.Fatal("reload moved projected bytes across redaction/queue generations")
	}
	if cleanupCount.Load() != 0 {
		t.Fatal("old adapter cleaned before its queued delivery drained")
	}
	close(oldRelease)
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not finish after old queue drained")
	}
	if cleanupCount.Load() != 1 {
		t.Fatalf("old generation cleanup count=%d", cleanupCount.Load())
	}
}

func TestRuntimeRejectedDestinationCandidateCleansPreparedAdaptersAndKeepsOldGraph(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initial := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	var cleanupCalls atomic.Int64
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		cleanup := func(context.Context) error {
			cleanupCalls.Add(1)
			return nil
		}
		if destination.Name == "reject-second" {
			return nil, cleanup, errors.New("unbounded adapter detail must not escape")
		}
		return newRuntimeRecordingAdapter(1), cleanup, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, initial, factory, nil)
	old := runtime.Active()
	candidate := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("prepared-first", "none", 0),
				runtimeConsoleDestination("reject-second", "none", 0),
			}
		},
	)
	result, err := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
	if err == nil || err.Code() != runtimegraph.ErrorInitialization ||
		err.ComponentName() != DestinationDispatchComponentName ||
		result.Status() != runtimegraph.ReloadRejected || runtime.Active() != old {
		t.Fatalf("rejected result=%s err=%v active=%p old=%p", result.Status(), err, runtime.Active(), old)
	}
	if bytes.Contains([]byte(err.Error()), []byte("unbounded")) || cleanupCalls.Load() != 2 {
		t.Fatalf("rejection leaked detail or missed cleanup: err=%v cleanup=%d", err, cleanupCalls.Load())
	}
}

func TestRuntimeDestinationAdaptersCleanupInReverseAcquisitionOrder(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("cleanup-first", "none", 0),
				runtimeConsoleDestination("cleanup-second", "none", 0),
			}
		},
	)
	var mutex sync.Mutex
	var cleaned []string
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return newRuntimeRecordingAdapter(1), func(context.Context) error {
			mutex.Lock()
			cleaned = append(cleaned, destination.Name)
			mutex.Unlock()
			return nil
		}, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := runtime.Close(ctx); err != nil {
		t.Fatal(err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if fmt.Sprint(cleaned) != "[cleanup-second cleanup-first]" {
		t.Fatalf("adapter cleanup order=%v", cleaned)
	}
}

func TestRuntimeDispatchConcurrentStressPreservesExactlyOnceLocalAndFanout(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("stress-a", "none", 128),
				runtimeConsoleDestination("stress-b", "sensitive", 128),
			}
		},
	)
	adapters := map[string]*runtimeRecordingAdapter{}
	var mutex sync.Mutex
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		adapter := newRuntimeRecordingAdapter(128)
		mutex.Lock()
		adapters[destination.Name] = adapter
		mutex.Unlock()
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)

	const count = 64
	errorsSeen := make(chan error, count)
	var workers sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			id := fmt.Sprintf("runtime-dispatch-stress-%03d", index)
			outcome, err := runtime.Emit(
				context.Background(), diagnosticMetadata(t), runtimeContentRecordBuilder(id, id+"@example.test"),
			)
			if err != nil || !outcome.LocalPersisted() {
				errorsSeen <- fmt.Errorf("%s persisted=%t err=%v", id, outcome.LocalPersisted(), err)
			}
		}()
	}
	workers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	for _, name := range []string{"stress-a", "stress-b"} {
		seen := map[string]int{}
		for index := 0; index < count; index++ {
			seen[receiveRuntimeDelivery(t, adapters[name]).identity.RecordID]++
		}
		if len(seen) != count {
			t.Fatalf("%s delivered unique records=%d, want %d", name, len(seen), count)
		}
		for id, occurrences := range seen {
			if occurrences != 1 {
				t.Errorf("%s record %s delivery count=%d", name, id, occurrences)
			}
		}
	}
	events, err := dependencies.store.ListEvents(count + 16)
	if err != nil {
		t.Fatal(err)
	}
	local := map[string]int{}
	for _, event := range events {
		if bytes.HasPrefix([]byte(event.ID), []byte("runtime-dispatch-stress-")) {
			local[event.ID]++
		}
	}
	if len(local) != count {
		t.Fatalf("local unique records=%d, want %d", len(local), count)
	}
	for id, occurrences := range local {
		if occurrences != 1 {
			t.Errorf("local record %s count=%d", id, occurrences)
		}
	}
}

var _ DestinationAdapterFactory = runtimeAdapterFactoryFunc(nil)
var _ delivery.Adapter = (*runtimeRecordingAdapter)(nil)
