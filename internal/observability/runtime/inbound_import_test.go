// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func inboundImportPlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
	retentionDays int,
	logs bool,
	metrics bool,
) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, retentionDays,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Logs = &logs
			source.Defaults.Collect.Metrics = new(bool)
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				observability.BucketAgentLifecycle: {
					Collect: config.ObservabilityV8CollectSource{Metrics: &metrics},
				},
			}
		})
}

func newInboundRuntimeForTest(
	t *testing.T,
	dependencies runtimeTestDependencies,
	plan *config.ObservabilityV8Plan,
	adapterFactory DestinationAdapterFactory,
) *Runtime {
	t.Helper()
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "inbound-runtime-test",
		DefenseClawInstanceID: "inbound-runtime-test",
	})
	options.DestinationAdapterFactory = adapterFactory
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close inbound runtime: %v", closeErr)
		}
	})
	return runtime
}

func TestInboundImportBatchPinsLogAndMetricTargetsToOneReloadGeneration(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &runtimeMetricPipelines{sinks: make(map[uint64]*runtimeMetricSink)}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "inbound-batch-runtime",
		GenerationPipelines: pipelines.build,
	})
	initial := inboundImportPlan(t, dependencies, 30, true, true)
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(initial, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})

	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	var logGeneration atomic.Uint64
	outcome, err := batch.EmitLog(t.Context(), diagnosticMetadata(t), runtimeRecordBuilder(
		"inbound-import-log-1", diagnosticIdentity(),
		func(snapshot EmitContext) { logGeneration.Store(snapshot.Generation()) },
	))
	if err != nil || !outcome.LocalPersisted() || logGeneration.Load() != 1 {
		t.Fatalf("generation-one log outcome=%+v generation=%d err=%v", outcome, logGeneration.Load(), err)
	}

	candidate := inboundImportPlan(t, dependencies, 31, true, true)
	type reloadOutcome struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}
	reloaded := make(chan reloadOutcome, 1)
	go func() {
		result, reloadErr := runtime.Reload(context.Background(), runtimegraph.ConfigFromPlan(candidate, false))
		reloaded <- reloadOutcome{result: result, err: reloadErr}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 {
		t.Fatal("reload did not publish generation two")
	}
	select {
	case result := <-reloaded:
		t.Fatalf("reload retired generation one before batch close: status=%s err=%v", result.result.Status(), result.err)
	default:
	}

	var metricGeneration atomic.Uint64
	recorded, err := batch.RecordGeneratedMetric(t.Context(), generatedMetricFamily, func(
		snapshot EmitContext,
	) (observability.Record, error) {
		metricGeneration.Store(snapshot.Generation())
		return runtimeGeneratedMetricRecord(t, snapshot)
	})
	if err != nil || recorded != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) ||
		metricGeneration.Load() != 1 {
		t.Fatalf("generation-one metric=%+v generation=%d err=%v", recorded, metricGeneration.Load(), err)
	}
	if pipelines.sink(t, 1).records.Load() != 1 || pipelines.sink(t, 2).records.Load() != 0 {
		t.Fatal("pinned batch metric crossed into the published generation")
	}

	batch.Close()
	select {
	case result := <-reloaded:
		if result.err != nil || result.result.Status() != runtimegraph.ReloadApplied {
			t.Fatalf("reload status=%s err=%v", result.result.Status(), result.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not retire generation one after batch close")
	}

	second, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	metricGeneration.Store(0)
	if _, err := second.RecordGeneratedMetric(t.Context(), generatedMetricFamily, func(
		snapshot EmitContext,
	) (observability.Record, error) {
		metricGeneration.Store(snapshot.Generation())
		return runtimeGeneratedMetricRecord(t, snapshot)
	}); err != nil || metricGeneration.Load() != 2 {
		t.Fatalf("new batch generation=%d err=%v", metricGeneration.Load(), err)
	}
}

func TestOTLPInboundCollectionBeforeConstruction(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := inboundImportPlan(t, dependencies, 30, false, false)
	runtime := newInboundRuntimeForTest(t, dependencies, plan, nil)
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()

	var ordinaryBuilds atomic.Int64
	dropped, err := batch.EmitLog(t.Context(), diagnosticMetadata(t), func(
		snapshot EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		ordinaryBuilds.Add(1)
		return runtimeRecordBuilder("disabled-import", diagnosticIdentity(), nil)(snapshot, admission)
	})
	if err != nil || dropped.Admission() != router.AdmissionDrop || dropped.LocalPersisted() || ordinaryBuilds.Load() != 0 {
		t.Fatalf("disabled log outcome=%+v builds=%d err=%v", dropped, ordinaryBuilds.Load(), err)
	}

	_, err = batch.EmitLog(t.Context(), activityMetadata(t), runtimeRecordBuilder(
		"forbidden-import-floor", activityIdentity(), nil,
	))
	var importErr *InboundImportError
	if !errors.As(err, &importErr) || importErr.Code() != InboundImportFloorRejected {
		t.Fatalf("mandatory import error=%v", err)
	}
	events, listErr := dependencies.store.ListEvents(16)
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(events) != 0 {
		t.Fatalf("disabled/floor imported logs persisted: %#v", events)
	}

	batch.Close()
	batch.Close()
	if _, err := batch.RecordGeneratedMetric(t.Context(), generatedMetricFamily, func(
		snapshot EmitContext,
	) (observability.Record, error) {
		return runtimeGeneratedMetricRecord(t, snapshot)
	}); err == nil {
		t.Fatal("closed inbound batch accepted metric work")
	}
	if _, err := batch.EmitLog(t.Context(), diagnosticMetadata(t), runtimeRecordBuilder(
		"closed-import", diagnosticIdentity(), nil,
	)); err == nil {
		t.Fatal("closed inbound batch accepted log work")
	}
}
