// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type discardGraphReporter struct{}

func (*discardGraphReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

func (*discardGraphReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type runtimeTestDependencies struct {
	storePath           string
	judgePath           string
	store               *audit.Store
	engine              *redaction.Engine
	builder             *observability.RecordBuilder
	reporter            *discardGraphReporter
	retentionReaper     *fakeRetentionReaper
	retentionController *RetentionController
	retentionScheduler  *scriptedRetentionScheduler
}

func newRuntimeTestDependencies(t *testing.T) runtimeTestDependencies {
	t.Helper()
	directory := t.TempDir()
	storePath := filepath.Join(directory, "audit.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var failureID atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 3, 12, 0, 0, int(failureID.Load()), time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("runtime-projection-failure-%d", failureID.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	retentionReaper := newFakeRetentionReaper(90)
	retentionScheduler := newScriptedRetentionScheduler()
	retentionController, err := newRetentionController(
		retentionReaper,
		RetentionControllerOptions{Scheduler: retentionScheduler},
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeTestDependencies{
		storePath: storePath,
		judgePath: filepath.Join(directory, "judge-bodies.db"),
		store:     store, engine: engine, builder: builder, reporter: &discardGraphReporter{},
		retentionReaper: retentionReaper, retentionController: retentionController,
		retentionScheduler: retentionScheduler,
	}
}

func (dependencies runtimeTestDependencies) options() Options {
	return Options{
		Store:  dependencies.store,
		Engine: dependencies.engine, RecordBuilder: dependencies.builder,
		Reporter: dependencies.reporter, RetentionController: dependencies.retentionController,
	}
}

func runtimeTestPlan(
	t *testing.T,
	storePath string,
	judgePath string,
	retentionDays int,
	mutate func(*config.ObservabilityV8Source),
) *config.ObservabilityV8Plan {
	t.Helper()
	source := &config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: storePath, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
	}}
	if mutate != nil {
		mutate(source)
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func newRuntimeForTest(
	t *testing.T,
	dependencies runtimeTestDependencies,
	plan *config.ObservabilityV8Plan,
	retainJudgeBodies bool,
) *Runtime {
	t.Helper()
	runtime, err := New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, retainJudgeBodies), dependencies.options(),
	)
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

func diagnosticMetadata(t *testing.T) router.Metadata {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"diagnostic",
		observability.ClassificationContext{RawSeverity: "INFO"},
		observability.SourceSystem,
		"",
		"diagnostic",
	)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func activityMetadata(t *testing.T) router.Metadata {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		"activity",
		observability.ClassificationContext{
			Bucket:    observability.BucketComplianceActivity,
			EventName: "config.change.applied", RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
		},
		observability.SourceSystem,
		"",
		"config-change",
	)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

type testLogIdentity struct {
	kind    observability.ProducerKind
	key     observability.ProducerKey
	context observability.ClassificationContext
	action  string
}

func runtimeRecordBuilder(
	recordID string,
	identity testLogIdentity,
	onSnapshot func(EmitContext),
) EmitBuilder {
	return func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		if onSnapshot != nil {
			onSnapshot(snapshot)
		}
		builder, err := observability.NewRecordBuilder(
			observability.ClockFunc(func() time.Time {
				return time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC)
			}),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
		)
		if err != nil {
			return observability.Record{}, err
		}
		provenance := observability.Provenance{
			Producer: "runtime_test", BinaryVersion: "test",
			RegistrySchemaVersion: observability.CurrentRecordSchemaVersion,
			ConfigGeneration:      int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		if admission == router.AdmissionFloor {
			return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
				ProducerKind: identity.kind, ProducerKey: identity.key,
				ClassificationContext: identity.context,
				Source:                observability.SourceSystem, Action: identity.action,
				Outcome: observability.OutcomeCompleted, Provenance: provenance,
			})
		}
		return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
			ProducerKind: identity.kind, ProducerKey: identity.key,
			ClassificationContext: identity.context,
			Source:                observability.SourceSystem, Action: identity.action,
			Outcome: observability.OutcomeCompleted, Provenance: provenance,
			Body: map[string]any{"message": "runtime-test"},
			FieldClasses: map[string]observability.FieldClass{
				"/message": observability.FieldClassContent,
			},
		})
	}
}

func diagnosticIdentity() testLogIdentity {
	return testLogIdentity{
		kind: observability.ProducerGatewayEvent, key: "diagnostic",
		context: observability.ClassificationContext{RawSeverity: "INFO"},
		action:  "diagnostic",
	}
}

func activityIdentity() testLogIdentity {
	return testLogIdentity{
		kind: observability.ProducerGatewayEvent, key: "activity",
		context: observability.ClassificationContext{
			Bucket:    observability.BucketComplianceActivity,
			EventName: "config.change.applied", RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
		},
		action: "config-change",
	}
}

func TestRuntimeBindsReadyRealSQLitePathAndLeavesStoreCallerOwned(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	wrongPlan := runtimeTestPlan(
		t, filepath.Join(filepath.Dir(dependencies.storePath), "different.db"),
		dependencies.judgePath, 90, nil,
	)
	_, err := New(t.Context(), runtimegraph.ConfigFromPlan(wrongPlan, false), dependencies.options())
	var runtimeErr *Error
	if !errors.As(err, &runtimeErr) || runtimeErr.Code() != ErrorStorePathMismatch {
		t.Fatalf("wrong store path error=%v", err)
	}

	runtime := newRuntimeForTest(t, dependencies, plan, false)
	if runtime.store != dependencies.store || runtime.store.DatabasePath() != dependencies.storePath {
		t.Fatal("runtime did not retain the exact caller-owned store identity")
	}
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !dependencies.store.Ready() {
		t.Fatal("runtime shutdown closed its caller-owned SQLite store")
	}
}

func TestRuntimeRetentionOnlyReloadReplacesGraphAndReusesStore(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initialPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initialPlan, false)
	oldGraph := runtime.Active()
	oldLease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	oldComponent, ok := oldLease.Component(LocalLogComponentName)
	if !ok {
		t.Fatal("initial local component is unavailable")
	}
	oldLocal := oldComponent.(*localLogComponent)
	oldLease.Release()

	candidatePlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	result, reloadErr := runtime.Reload(
		t.Context(), runtimegraph.ConfigFromPlan(candidatePlan, false),
	)
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("retention reload result=%s err=%v", result.Status(), reloadErr)
	}
	newGraph := result.ActiveGraph()
	if newGraph == oldGraph || newGraph.Generation() != oldGraph.Generation()+1 || newGraph.RetentionDays() != 30 {
		t.Fatalf("new graph=%p generation=%d retention=%d", newGraph, newGraph.Generation(), newGraph.RetentionDays())
	}
	newLease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer newLease.Release()
	newComponent, ok := newLease.Component(LocalLogComponentName)
	if !ok {
		t.Fatal("replacement local component is unavailable")
	}
	newLocal := newComponent.(*localLogComponent)
	if newLocal == oldLocal || newLocal.store != dependencies.store || oldLocal.store != dependencies.store {
		t.Fatal("retention reload did not replace only generation state around the stable store")
	}
}

func TestRuntimeTelemetryProviderSharesExactGraphGenerationAndRetirement(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initialPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "runtime-test", Environment: "test", ServiceInstanceID: "runtime-test-instance",
	})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(initialPlan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close observability runtime: %v", closeErr)
		}
	})

	providerForActiveGraph := func() (*telemetry.Provider, uint64) {
		t.Helper()
		graph := runtime.Active()
		if graph == nil {
			t.Fatal("runtime has no active graph")
		}
		lease, acquireErr := runtime.manager.Acquire(t.Context())
		if acquireErr != nil {
			t.Fatal(acquireErr)
		}
		defer lease.Release()
		provider, ok := telemetry.V8ProviderFromLease(lease)
		if !ok {
			t.Fatal("runtime graph has no telemetry provider")
		}
		digest, generation, bound := provider.V8PlanBinding()
		if !bound || digest != graph.Digest() || generation != graph.Generation() {
			t.Fatalf("provider/graph binding = %q/%d and %q/%d", digest, generation, graph.Digest(), graph.Generation())
		}
		return provider, generation
	}

	first, firstGeneration := providerForActiveGraph()
	candidate := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", result.Status(), reloadErr)
	}
	second, secondGeneration := providerForActiveGraph()
	if first == second || secondGeneration != firstGeneration+1 {
		t.Fatalf("provider/generation reused across reload: %p/%d -> %p/%d", first, firstGeneration, second, secondGeneration)
	}
	if first.Enabled() {
		t.Fatal("retired runtime graph left telemetry provider enabled")
	}
}

func TestRuntimeRejectsExactRestartFieldsAndKeepsActiveGraph(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initialPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initialPlan, false)
	oldGraph := runtime.Active()

	tests := []struct {
		name      string
		candidate runtimegraph.Config
		field     string
	}{
		{
			name: "local path",
			candidate: runtimegraph.ConfigFromPlan(runtimeTestPlan(
				t, filepath.Join(filepath.Dir(dependencies.storePath), "next-audit.db"),
				dependencies.judgePath, 90, nil,
			), false),
			field: runtimegraph.FieldLocalPath,
		},
		{
			name: "judge body path",
			candidate: runtimegraph.ConfigFromPlan(runtimeTestPlan(
				t, dependencies.storePath,
				filepath.Join(filepath.Dir(dependencies.judgePath), "next-judge.db"), 90, nil,
			), false),
			field: runtimegraph.FieldJudgeBodiesPath,
		},
		{
			name:      "judge retention switch",
			candidate: runtimegraph.ConfigFromPlan(initialPlan, true),
			field:     runtimegraph.FieldRetainJudgeBodies,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := runtime.Reload(t.Context(), test.candidate)
			if err == nil || err.Code() != runtimegraph.ErrorRestartRequired ||
				err.FieldPath() != test.field || result.Status() != runtimegraph.ReloadRejected {
				t.Fatalf("result=%s error=%v field=%q", result.Status(), err, err.FieldPath())
			}
			if result.ActiveGraph() != oldGraph || runtime.Active() != oldGraph {
				t.Fatal("restart-required reload replaced the active graph")
			}
		})
	}
}

func TestRuntimeFailedCandidateLeavesOldGraphActive(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initialPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initialPlan, false)
	oldGraph := runtime.Active()
	candidatePlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "console", Kind: config.ObservabilityV8DestinationConsole,
			}}
		},
	)
	result, err := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidatePlan, false))
	if err == nil || err.Code() != runtimegraph.ErrorInitialization ||
		err.ComponentName() != DestinationDispatchComponentName || result.Status() != runtimegraph.ReloadRejected {
		t.Fatalf("result=%s error=%v component=%q", result.Status(), err, err.ComponentName())
	}
	if result.ActiveGraph() != oldGraph || runtime.Active() != oldGraph {
		t.Fatal("failed candidate changed the active graph")
	}
}

func TestRuntimeConcurrentEmitAndReloadStayCoherentAndPersistExactlyOnce(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	planA := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	planB := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	runtime := newRuntimeForTest(t, dependencies, planA, false)
	metadata := diagnosticMetadata(t)

	type provenance struct {
		digest     string
		generation uint64
	}
	const recordCount = 96
	expected := make(map[string]provenance, recordCount)
	var expectedMu sync.Mutex
	start := make(chan struct{})
	errCh := make(chan error, recordCount+24)
	var workers sync.WaitGroup
	for index := 0; index < recordCount; index++ {
		index := index
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			id := fmt.Sprintf("runtime-concurrent-%03d", index)
			outcome, err := runtime.Emit(t.Context(), metadata, runtimeRecordBuilder(
				id, diagnosticIdentity(), func(snapshot EmitContext) {
					expectedMu.Lock()
					expected[id] = provenance{digest: snapshot.Digest(), generation: snapshot.Generation()}
					expectedMu.Unlock()
				},
			))
			if err != nil {
				errCh <- err
				return
			}
			if !outcome.LocalPersisted() || outcome.Admission() != router.AdmissionOrdinary {
				errCh <- fmt.Errorf("record %s was not persisted", id)
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for index := 0; index < 24; index++ {
			candidate := planB
			if index%2 == 1 {
				candidate = planA
			}
			result, err := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
			if err != nil || result.Status() != runtimegraph.ReloadApplied {
				errCh <- fmt.Errorf("reload %d status=%s err=%v", index, result.Status(), err)
				return
			}
		}
	}()
	close(start)
	workers.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	events, err := dependencies.store.ListEvents(recordCount + 16)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int, recordCount)
	for _, event := range events {
		expectedMu.Lock()
		want, tracked := expected[event.ID]
		expectedMu.Unlock()
		if !tracked {
			continue
		}
		counts[event.ID]++
		if event.ContentHash != want.digest || event.Generation != want.generation {
			t.Errorf("record %s persisted digest/generation %s/%d, want %s/%d",
				event.ID, event.ContentHash, event.Generation, want.digest, want.generation)
		}
	}
	if len(expected) != recordCount {
		t.Fatalf("builders invoked for %d records, want %d", len(expected), recordCount)
	}
	for id := range expected {
		if counts[id] != 1 {
			t.Errorf("SQLite count for %s=%d, want exactly one", id, counts[id])
		}
	}
}

func TestRuntimeCollectionDisabledDoesNotInvokeBuilder(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			disabled := false
			source.Defaults.Collect.Logs = &disabled
		},
	)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	var calls atomic.Int64
	outcome, err := runtime.Emit(t.Context(), diagnosticMetadata(t), func(EmitContext, router.Admission) (observability.Record, error) {
		calls.Add(1)
		return observability.Record{}, errors.New("disabled builder must not run")
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionDrop || outcome.LocalPersisted() || calls.Load() != 0 {
		t.Fatalf("disabled outcome=%s persisted=%t calls=%d",
			outcome.Admission(), outcome.LocalPersisted(), calls.Load())
	}
}

func TestRuntimeRejectsRecordBuiltForDifferentGraph(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	const recordID = "runtime-wrong-graph"
	_, err := runtime.Emit(t.Context(), diagnosticMetadata(t), func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		return runtimeRecordBuilder(recordID, diagnosticIdentity(), nil)(EmitContext{
			plan: snapshot.Plan(), digest: snapshot.Digest(), generation: snapshot.Generation() + 1,
		}, admission)
	})
	var pipelineErr *pipeline.Error
	if !errors.As(err, &pipelineErr) || pipelineErr.Code() != pipeline.ErrorRecordBuild {
		t.Fatalf("mismatched graph record error=%v", err)
	}
	events, listErr := dependencies.store.ListEvents(16)
	if listErr != nil {
		t.Fatal(listErr)
	}
	for _, event := range events {
		if event.ID == recordID {
			t.Fatal("record with mismatched graph provenance reached SQLite")
		}
	}
}

func TestRuntimeMandatoryFloorPersistsWhenCollectionDisabled(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			disabled := false
			source.Defaults.Collect.Logs = &disabled
		},
	)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	const recordID = "runtime-mandatory-floor"
	outcome, err := runtime.Emit(
		t.Context(), activityMetadata(t), runtimeRecordBuilder(recordID, activityIdentity(), nil),
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionFloor || !outcome.LocalPersisted() {
		t.Fatalf("floor outcome=%s persisted=%t", outcome.Admission(), outcome.LocalPersisted())
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
		t.Fatalf("mandatory floor SQLite count=%d, want one", count)
	}
}

var _ runtimegraph.Reporter = (*discardGraphReporter)(nil)
