// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestDestinationHealthSnapshotInventoryQueueActivityAndCopySafety(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	disabled := false
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("live-console", "none", 4),
				{Name: "disabled-console", Kind: config.ObservabilityV8DestinationConsole, Enabled: &disabled},
			}
		},
	)
	release := make(chan struct{})
	adapter := newRuntimeRecordingAdapter(2)
	adapter.release = release
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)

	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("health-queued", "queued"),
	); err != nil {
		t.Fatal(err)
	}
	select {
	case <-adapter.started:
	case <-time.After(5 * time.Second):
		t.Fatal("delivery did not enter the in-flight queue")
	}

	snapshot, err := runtime.DestinationHealthSnapshot(t.Context())
	if err != nil || snapshot.Generation != 1 || snapshot.PlanDigest != plan.Digest() ||
		len(snapshot.Destinations) != 3 {
		t.Fatalf("snapshot=%+v err=%v", snapshot, err)
	}
	local := destinationHealthByName(t, snapshot, config.ObservabilityV8LocalDestinationName)
	if !local.Enabled || local.Kind != config.ObservabilityV8DestinationLocalSQLite ||
		local.State != delivery.HealthHealthy || local.Queue != nil {
		t.Fatalf("local health=%+v", local)
	}
	disabledHealth := destinationHealthByName(t, snapshot, "disabled-console")
	if disabledHealth.Enabled || disabledHealth.State != delivery.HealthDisabled ||
		disabledHealth.Queue != nil || len(disabledHealth.Sources) != 0 {
		t.Fatalf("disabled health=%+v", disabledHealth)
	}
	live := destinationHealthByName(t, snapshot, "live-console")
	if !live.Enabled || live.State != delivery.HealthHealthy || live.Queue == nil ||
		live.Queue.Items != 1 || live.Queue.InFlightItems != 1 || live.Queue.MaxItems != 4 ||
		live.Counters.Accepted != 1 || live.Counters.Delivered != 0 ||
		len(live.Sources) != 1 || live.Sources[0].Signal != string(observability.SignalLogs) {
		t.Fatalf("live health=%+v", live)
	}

	// Mutating the returned tree cannot alter the generation component.
	live.Queue.Items = 99
	live.Signals[0] = observability.SignalMetrics
	live.Sources[0].Queue.Bytes = 99
	fresh, err := runtime.DestinationHealthSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	freshLive := destinationHealthByName(t, fresh, "live-console")
	if freshLive.Queue.Items != 1 || freshLive.Signals[0] != observability.SignalLogs ||
		freshLive.Sources[0].Queue.Bytes == 99 {
		t.Fatalf("snapshot retained caller mutation: %+v", freshLive)
	}

	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		fresh, err = runtime.DestinationHealthSnapshot(t.Context())
		if err == nil {
			freshLive = destinationHealthByName(t, fresh, "live-console")
			if freshLive.Counters.Delivered == 1 && !freshLive.LastSuccess.IsZero() {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("successful delivery activity not observed: %+v err=%v", freshLive, err)
}

func TestDestinationHealthSnapshotNeverReturnsRetiringGeneration(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	makePlan := func(profile string) *config.ObservabilityV8Plan {
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("generation-console", profile, 2),
				}
			},
		)
	}
	oldRelease := make(chan struct{})
	prepared := 0
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		adapter := newRuntimeRecordingAdapter(2)
		if prepared == 0 {
			adapter.release = oldRelease
		}
		prepared++
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, makePlan("none"), factory, nil)
	if _, err := runtime.Emit(
		t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("health-old", "old"),
	); err != nil {
		t.Fatal(err)
	}

	reloadDone := make(chan *runtimegraph.Error, 1)
	go func() {
		_, reloadErr := runtime.Reload(
			context.Background(), runtimegraph.ConfigFromPlan(makePlan("strict"), false),
		)
		reloadDone <- reloadErr
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() == 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	for index := 0; index < 100; index++ {
		snapshot, err := runtime.DestinationHealthSnapshot(t.Context())
		if err != nil || snapshot.Generation != 2 {
			t.Fatalf("snapshot generation=%d err=%v", snapshot.Generation, err)
		}
		row := destinationHealthByName(t, snapshot, "generation-console")
		for _, source := range row.Sources {
			if source.Generation != 2 {
				t.Fatalf("stale source escaped: %+v", source)
			}
		}
	}
	close(oldRelease)
	select {
	case err := <-reloadDone:
		if err != nil {
			t.Fatalf("reload failed code=%s component=%s field=%s err=%v",
				err.Code(), err.ComponentName(), err.FieldPath(), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not retire old generation")
	}
}

func destinationHealthByName(
	t *testing.T,
	snapshot DestinationHealthSnapshot,
	name string,
) *DestinationHealth {
	t.Helper()
	for index := range snapshot.Destinations {
		if snapshot.Destinations[index].Name == name {
			return &snapshot.Destinations[index]
		}
	}
	t.Fatalf("destination %q not found in %+v", name, snapshot.Destinations)
	return nil
}
