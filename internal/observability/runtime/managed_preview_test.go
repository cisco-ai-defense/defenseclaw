// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestProjectManagedLogIsPureAndMatchesDelivery(t *testing.T) {
	for _, collect := range []bool{false, true} {
		t.Run(fmt.Sprint(collect), func(t *testing.T) {
			deps := newRuntimeTestDependencies(t)
			plan := managedFallbackRuntimePlan(t, deps, collect, "https://preview.example.test", true)
			adapters := newManagedFallbackAdapters()
			runtime := newManagedFallbackRuntime(t, deps, plan, adapters)
			const id = "preview-managed-record"
			const content = "preview-person@example.test"
			builder := runtimeContentRecordBuilder(id, content)
			before := managedPreviewEnqueueCounts(t, runtime)
			preview, err := runtime.ProjectManagedLog(t.Context(), diagnosticMetadata(t), builder)
			if err != nil {
				t.Fatal(err)
			}
			work := preview.OptionalWork()
			if preview.LocalPersisted() || len(work) != 1 || work[0].Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
				t.Fatalf("preview persisted=%t work=%d; want one managed projection only", preview.LocalPersisted(), len(work))
			}
			encoded, err := work[0].Projection().Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(content)) {
				t.Fatal("preview retained sensitive source content")
			}
			if n := countRuntimeRecord(t, deps, id); n != 0 {
				t.Fatalf("preview wrote %d records", n)
			}
			if after := managedPreviewEnqueueCounts(t, runtime); !reflect.DeepEqual(before, after) {
				t.Fatalf("preview attempted to enqueue work: before=%v after=%v", before, after)
			}
			outcome, err := runtime.Emit(t.Context(), diagnosticMetadata(t), builder)
			if err != nil {
				t.Fatal(err)
			}
			if after := managedPreviewEnqueueCounts(t, runtime); after[config.ObservabilityV8ManagedAIDDestinationName][0] != before[config.ObservabilityV8ManagedAIDDestinationName][0]+1 {
				t.Fatalf("ordinary emit did not enqueue one managed item: before=%v after=%v", before, after)
			}
			for _, actual := range outcome.OptionalWork() {
				if actual.Delivery().DestinationName != config.ObservabilityV8ManagedAIDDestinationName {
					continue
				}
				body, err := actual.Projection().Bytes()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(encoded, body) {
					t.Fatal("preview differs from actual managed projection")
				}
				return
			}
			t.Fatal("ordinary emit did not produce the managed projection")
		})
	}
}

// Enqueue counters change synchronously in Emit, independently of worker
// scheduling. Delivery channels cannot prove that pure preview queued nothing.
func managedPreviewEnqueueCounts(t *testing.T, runtime *Runtime) map[string][3]uint64 {
	t.Helper()
	lease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	value, ok := lease.Component(DestinationDispatchComponentName)
	component, typed := value.(*destinationDispatchComponent)
	if !ok || !typed {
		t.Fatal("destination dispatcher is unavailable")
	}
	counts := make(map[string][3]uint64, len(component.byName))
	for name, target := range component.byName {
		c := target.dispatcher.Counters()
		counts[name] = [3]uint64{c.Accepted, c.Rejected, c.Dropped}
	}
	return counts
}
