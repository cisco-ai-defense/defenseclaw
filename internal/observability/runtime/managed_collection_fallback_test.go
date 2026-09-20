// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
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

func managedFallbackRuntimePlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
	collectLogs bool,
	endpoint string,
	withOperatorDestination bool,
) *config.ObservabilityV8Plan {
	t.Helper()
	base := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Logs = &collectLogs
			if withOperatorDestination {
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("operator-console", "none", 0),
				}
			}
		},
	)
	plan, err := config.WithObservabilityV8ManagedAIDDestination(
		base,
		config.ObservabilityV8ManagedAIDOptions{
			DeploymentMode: "managed_enterprise",
			Endpoint:       endpoint,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

type managedFallbackAdapters struct {
	mu       sync.Mutex
	byName   map[string]*runtimeRecordingAdapter
	byTarget map[string]*runtimeRecordingAdapter
}

func newManagedFallbackAdapters() *managedFallbackAdapters {
	return &managedFallbackAdapters{
		byName:   make(map[string]*runtimeRecordingAdapter),
		byTarget: make(map[string]*runtimeRecordingAdapter),
	}
}

func (adapters *managedFallbackAdapters) factory() DestinationAdapterFactory {
	return runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		adapter := newRuntimeRecordingAdapter(8)
		adapters.mu.Lock()
		adapters.byName[destination.Name] = adapter
		adapters.byTarget[destination.Transport.Endpoint] = adapter
		adapters.mu.Unlock()
		return adapter, func(context.Context) error { return nil }, nil
	})
}

func (adapters *managedFallbackAdapters) named(t *testing.T, name string) *runtimeRecordingAdapter {
	t.Helper()
	adapters.mu.Lock()
	defer adapters.mu.Unlock()
	adapter := adapters.byName[name]
	if adapter == nil {
		t.Fatalf("destination %q was not prepared", name)
	}
	return adapter
}

func (adapters *managedFallbackAdapters) targeted(t *testing.T, endpoint string) *runtimeRecordingAdapter {
	t.Helper()
	adapters.mu.Lock()
	defer adapters.mu.Unlock()
	adapter := adapters.byTarget[endpoint+config.ObservabilityV8ManagedAIDIngestPath]
	if adapter == nil {
		t.Fatalf("managed endpoint %q was not prepared", endpoint)
	}
	return adapter
}

func newManagedFallbackRuntime(
	t *testing.T,
	dependencies runtimeTestDependencies,
	plan *config.ObservabilityV8Plan,
	adapters *managedFallbackAdapters,
) *Runtime {
	t.Helper()
	options := dependencies.options()
	options.DestinationAdapterFactory = adapters.factory()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "managed-fallback-test", Environment: "test",
		ServiceInstanceID: "managed-fallback-test-instance",
	})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close managed fallback runtime: %v", err)
		}
	})
	return runtime
}

func receiveManagedFallbackDelivery(
	t *testing.T,
	adapter *runtimeRecordingAdapter,
) runtimeDeliveredItem {
	t.Helper()
	select {
	case item := <-adapter.delivered:
		return item
	case <-time.After(8 * time.Second):
		t.Fatal("timed out waiting for managed fallback delivery")
		return runtimeDeliveredItem{}
	}
}

func assertNoRuntimeDelivery(t *testing.T, adapter *runtimeRecordingAdapter) {
	t.Helper()
	select {
	case item := <-adapter.delivered:
		t.Fatalf("unexpected destination delivery: %#v", item.identity)
	case <-time.After(150 * time.Millisecond):
	}
}

func countRuntimeRecord(t *testing.T, dependencies runtimeTestDependencies, recordID string) int {
	t.Helper()
	events, err := dependencies.store.ListEvents(256)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.ID == recordID {
			count++
		}
	}
	return count
}

func TestRuntimeManagedFallbackDisabledVerdictReachesOnlyManagedDestination(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := managedFallbackRuntimePlan(
		t, dependencies, false, "https://managed-disabled.example.test", true,
	)
	adapters := newManagedFallbackAdapters()
	runtime := newManagedFallbackRuntime(t, dependencies, plan, adapters)
	managed := adapters.named(t, config.ObservabilityV8ManagedAIDDestinationName)
	operator := adapters.named(t, "operator-console")

	const recordID = "managed-fallback-disabled"
	const content = "managed-fallback-person@example.test"
	var builds atomic.Int64
	delegate := runtimeContentRecordBuilder(recordID, content)
	outcome, err := runtime.Emit(t.Context(), diagnosticMetadata(t), func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		builds.Add(1)
		return delegate(snapshot, admission)
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionDrop || outcome.LocalPersisted() ||
		!outcome.ManagedOnly() || builds.Load() != 1 || len(outcome.OptionalWork()) != 1 {
		t.Fatalf("managed outcome=%s persisted=%t managed=%t builds=%d work=%d",
			outcome.Admission(), outcome.LocalPersisted(), outcome.ManagedOnly(),
			builds.Load(), len(outcome.OptionalWork()))
	}
	item := receiveManagedFallbackDelivery(t, managed)
	if item.destination != config.ObservabilityV8ManagedAIDDestinationName ||
		item.identity.RecordID != recordID || item.identity.OriginDestination != "" ||
		bytes.Contains(item.bytes, []byte(content)) {
		t.Fatalf("managed fallback delivery=%#v retained_content=%t",
			item.identity, bytes.Contains(item.bytes, []byte(content)))
	}
	assertNoRuntimeDelivery(t, managed)
	assertNoRuntimeDelivery(t, operator)
	if got := countRuntimeRecord(t, dependencies, recordID); got != 0 {
		t.Fatalf("managed-only SQLite count=%d, want zero", got)
	}
}

func TestRuntimeManagedFallbackEnabledVerdictUsesOrdinaryPathExactlyOnce(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := managedFallbackRuntimePlan(
		t, dependencies, true, "https://managed-enabled.example.test", true,
	)
	adapters := newManagedFallbackAdapters()
	runtime := newManagedFallbackRuntime(t, dependencies, plan, adapters)
	managed := adapters.named(t, config.ObservabilityV8ManagedAIDDestinationName)
	operator := adapters.named(t, "operator-console")

	const recordID = "managed-fallback-enabled"
	var builds atomic.Int64
	delegate := runtimeContentRecordBuilder(recordID, "ordinary-content")
	outcome, err := runtime.Emit(t.Context(), diagnosticMetadata(t), func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		builds.Add(1)
		return delegate(snapshot, admission)
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionOrdinary || !outcome.LocalPersisted() ||
		outcome.ManagedOnly() || builds.Load() != 1 || len(outcome.OptionalWork()) != 2 {
		t.Fatalf("ordinary outcome=%s persisted=%t managed=%t builds=%d work=%d",
			outcome.Admission(), outcome.LocalPersisted(), outcome.ManagedOnly(),
			builds.Load(), len(outcome.OptionalWork()))
	}
	if item := receiveManagedFallbackDelivery(t, managed); item.identity.RecordID != recordID {
		t.Fatalf("managed ordinary record=%q", item.identity.RecordID)
	}
	if item := receiveManagedFallbackDelivery(t, operator); item.identity.RecordID != recordID {
		t.Fatalf("operator ordinary record=%q", item.identity.RecordID)
	}
	assertNoRuntimeDelivery(t, managed)
	assertNoRuntimeDelivery(t, operator)
	if got := countRuntimeRecord(t, dependencies, recordID); got != 1 {
		t.Fatalf("ordinary SQLite count=%d, want one", got)
	}
}

func TestRuntimeManagedFallbackExcludesLocalOnlyAndInboundCalls(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := managedFallbackRuntimePlan(
		t, dependencies, false, "https://managed-excluded.example.test", false,
	)
	adapters := newManagedFallbackAdapters()
	runtime := newManagedFallbackRuntime(t, dependencies, plan, adapters)
	managed := adapters.named(t, config.ObservabilityV8ManagedAIDDestinationName)
	metadata := diagnosticMetadata(t)
	var builds atomic.Int64
	builder := func(EmitContext, router.Admission) (observability.Record, error) {
		builds.Add(1)
		return observability.Record{}, fmt.Errorf("excluded builder must stay lazy")
	}
	localOnly, err := runtime.EmitLocalOnly(t.Context(), metadata, builder)
	if err != nil || localOnly.Admission() != router.AdmissionDrop || localOnly.ManagedOnly() {
		t.Fatalf("local-only outcome=%+v err=%v", localOnly, err)
	}

	lease, graphErr := runtime.manager.Acquire(t.Context())
	if graphErr != nil {
		t.Fatal(graphErr)
	}
	inbound, inboundErr := runtime.emitWithLeaseControls(
		t.Context(), lease, metadata, builder, false, "", false, true,
	)
	lease.Release()
	if inboundErr != nil || inbound.Admission() != router.AdmissionDrop || inbound.ManagedOnly() ||
		builds.Load() != 0 {
		t.Fatalf("inbound outcome=%+v builds=%d err=%v", inbound, builds.Load(), inboundErr)
	}
	assertNoRuntimeDelivery(t, managed)
	if got := countRuntimeRecord(t, dependencies, "excluded"); got != 0 {
		t.Fatalf("excluded SQLite count=%d", got)
	}
}

func TestRuntimeManagedFallbackReloadKeepsGenerationIsolation(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	const firstEndpoint = "https://managed-first.example.test"
	const secondEndpoint = "https://managed-second.example.test"
	firstPlan := managedFallbackRuntimePlan(t, dependencies, false, firstEndpoint, false)
	secondPlan := managedFallbackRuntimePlan(t, dependencies, false, secondEndpoint, false)
	adapters := newManagedFallbackAdapters()
	runtime := newManagedFallbackRuntime(t, dependencies, firstPlan, adapters)
	firstAdapter := adapters.targeted(t, firstEndpoint)

	started := make(chan EmitContext, 1)
	release := make(chan struct{})
	emitDone := make(chan error, 1)
	delegate := runtimeContentRecordBuilder("managed-fallback-generation-one", "generation-one")
	go func() {
		_, err := runtime.Emit(context.Background(), diagnosticMetadata(t), func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
			started <- snapshot
			<-release
			return delegate(snapshot, admission)
		})
		emitDone <- err
	}()
	firstSnapshot := <-started
	if firstSnapshot.Generation() != 1 || firstSnapshot.Digest() != firstPlan.Digest() {
		t.Fatalf("first snapshot=%d/%q", firstSnapshot.Generation(), firstSnapshot.Digest())
	}

	reloadDone := make(chan error, 1)
	go func() {
		result, reloadErr := runtime.Reload(
			context.Background(), runtimegraph.ConfigFromPlan(secondPlan, false),
		)
		if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
			reloadDone <- fmt.Errorf("reload status=%s err=%v", result.Status(), reloadErr)
			return
		}
		reloadDone <- nil
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 || runtime.Active().Digest() != secondPlan.Digest() {
		close(release)
		t.Fatalf("replacement graph=%d/%q", runtime.Active().Generation(), runtime.Active().Digest())
	}
	secondAdapter := adapters.targeted(t, secondEndpoint)
	close(release)
	if err := <-emitDone; err != nil {
		t.Fatal(err)
	}
	if err := <-reloadDone; err != nil {
		t.Fatal(err)
	}
	item := receiveManagedFallbackDelivery(t, firstAdapter)
	if item.identity.RecordID != "managed-fallback-generation-one" {
		t.Fatalf("old-generation record=%q", item.identity.RecordID)
	}
	assertNoRuntimeDelivery(t, secondAdapter)
	if got := countRuntimeRecord(t, dependencies, "managed-fallback-generation-one"); got != 0 {
		t.Fatalf("managed-only reload SQLite count=%d", got)
	}
}
