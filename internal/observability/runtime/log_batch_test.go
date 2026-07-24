// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestRuntimeLogBatchPinsOneGenerationAcrossConcurrentReload(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initial := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initial, false)

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var generations [2]atomic.Uint64
	items := make([]LogBatchItem, 2)
	for index := range items {
		index := index
		items[index] = LogBatchItem{
			Context: context.Background(), Metadata: diagnosticMetadata(t),
			Builder: runtimeRecordBuilder(
				"batch-generation-"+string(rune('a'+index)), diagnosticIdentity(),
				func(snapshot EmitContext) {
					generations[index].Store(snapshot.Generation())
					if index == 0 {
						once.Do(func() { close(entered) })
						<-release
					}
				},
			),
		}
	}
	type result struct {
		outcomes int
		err      error
	}
	done := make(chan result, 1)
	go func() {
		outcomes, err := runtime.EmitBatch(t.Context(), items)
		done <- result{outcomes: len(outcomes), err: err}
	}()
	<-entered
	candidate := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	type reloadResult struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}
	reloadDone := make(chan reloadResult, 1)
	go func() {
		result, err := runtime.Reload(
			t.Context(), runtimegraph.ConfigFromPlan(candidate, false),
		)
		reloadDone <- reloadResult{result: result, err: err}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 {
		t.Fatal("replacement generation was not published while the batch lease was live")
	}
	close(release)
	reload := <-reloadDone
	reloaded, reloadErr := reload.result, reload.err
	if reloadErr != nil || reloaded.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%s err=%v", reloaded.Status(), reloadErr)
	}
	completed := <-done
	if completed.err != nil || completed.outcomes != 2 {
		t.Fatalf("batch outcomes=%d err=%v", completed.outcomes, completed.err)
	}
	if first, second := generations[0].Load(), generations[1].Load(); first != 1 || second != first {
		t.Fatalf("batch generations=%d/%d, want 1/1", first, second)
	}
	events, err := dependencies.store.ListEvents(10)
	if err != nil || len(events) != 2 {
		t.Fatalf("persisted batch events=%d err=%v", len(events), err)
	}
}

func TestRuntimeLogBatchStopsAtFirstFailureAndReturnsCompletedPrefix(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	wantErr := errors.New("batch-build-failed")
	var thirdBuilt atomic.Bool
	items := []LogBatchItem{
		{Context: t.Context(), Metadata: diagnosticMetadata(t), Builder: runtimeRecordBuilder("batch-prefix-a", diagnosticIdentity(), nil)},
		{Context: t.Context(), Metadata: diagnosticMetadata(t), Builder: func(EmitContext, router.Admission) (observability.Record, error) {
			return observability.Record{}, wantErr
		}},
		{Context: t.Context(), Metadata: diagnosticMetadata(t), Builder: func(EmitContext, router.Admission) (observability.Record, error) {
			thirdBuilt.Store(true)
			return observability.Record{}, nil
		}},
	}
	outcomes, err := runtime.EmitBatch(t.Context(), items)
	if err == nil || len(outcomes) != 1 || !outcomes[0].LocalPersisted() || thirdBuilt.Load() {
		t.Fatalf("prefix outcomes=%d err=%v third_built=%t", len(outcomes), err, thirdBuilt.Load())
	}
	events, listErr := dependencies.store.ListEvents(10)
	if listErr != nil || len(events) != 1 || events[0].ID != "batch-prefix-a" {
		t.Fatalf("persisted prefix=%#v err=%v", events, listErr)
	}
}

func TestRuntimeLogBatchRejectsInvalidBoundsBeforeConstruction(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	for name, items := range map[string][]LogBatchItem{
		"empty":       nil,
		"nil context": {{Metadata: diagnosticMetadata(t), Builder: runtimeRecordBuilder("never", diagnosticIdentity(), nil)}},
		"nil builder": {{Context: t.Context(), Metadata: diagnosticMetadata(t)}},
		"too many":    make([]LogBatchItem, MaxLogBatchItems+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runtime.EmitBatch(t.Context(), items); err == nil {
				t.Fatal("invalid batch was accepted")
			}
		})
	}
}
