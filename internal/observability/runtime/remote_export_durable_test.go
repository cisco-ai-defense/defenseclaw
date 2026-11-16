// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// A record held for its local write (RemoteExportAfterLocalWrite) is one its
// producer may write again, differently, if the local store loses it. So it
// leaves only once the local store keeps it through a power loss: never as
// a managed-only projection, which the local store does not keep, and not
// while the store cannot flush its committed writes, in a single emit or in
// a batch. A default record still leaves in both cases (GAP-1536).
func TestRuntimeAfterLocalWriteSendsOnlyDurableLocalRecords(t *testing.T) {
	t.Run("managed-only projection", func(t *testing.T) {
		dependencies := newRuntimeTestDependencies(t)
		plan := managedFallbackRuntimePlan(t, dependencies, false, "https://managed-held.example.test", false)
		adapters := newManagedFallbackAdapters()
		runtime := newManagedFallbackRuntime(t, dependencies, plan, adapters)
		managed := adapters.named(t, config.ObservabilityV8ManagedAIDDestinationName)

		held := observability.WithRemoteExport(t.Context(), observability.RemoteExportAfterLocalWrite)
		outcome, err := runtime.Emit(held, diagnosticMetadata(t), runtimeContentRecordBuilder("managed-held", "managed-held"))
		if err != nil {
			t.Fatal(err)
		}
		if !outcome.ManagedOnly() || outcome.LocalPersisted() {
			t.Fatalf("outcome managed=%t persisted=%t, want a managed-only projection", outcome.ManagedOnly(), outcome.LocalPersisted())
		}
		assertNoRuntimeDelivery(t, managed)
		if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("managed-default", "managed-default")); err != nil {
			t.Fatal(err)
		}
		if item := receiveManagedFallbackDelivery(t, managed); item.identity.RecordID != "managed-default" {
			t.Fatalf("managed destination received %q, want managed-default", item.identity.RecordID)
		}
	})

	t.Run("local store cannot flush", func(t *testing.T) {
		dependencies := newRuntimeTestDependencies(t)
		plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("sink", "none", 8),
				}
			},
		)
		sink := newRuntimeRecordingAdapter(8)
		factory := runtimeAdapterFactoryFunc(func(
			context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext,
		) (delivery.Adapter, DestinationAdapterCleanup, error) {
			return sink, func(context.Context) error { return nil }, nil
		})
		runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
		database, err := sql.Open("sqlite", dependencies.storePath)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		refuseFlush := func(on bool) {
			t.Helper()
			statement := `DROP TRIGGER IF EXISTS remote_export_no_flush`
			if on {
				statement = `CREATE TRIGGER remote_export_no_flush BEFORE UPDATE ON observability_store_readiness
					BEGIN SELECT RAISE(ABORT, 'disk I/O error'); END`
			}
			if _, err := database.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
		held := observability.WithRemoteExport(t.Context(), observability.RemoteExportAfterLocalWrite)
		emitBatch := func(ctx context.Context, id string) {
			t.Helper()
			if _, err := runtime.EmitAtomicBatch(ctx, []LogBatchItem{{
				Context: ctx, Metadata: diagnosticMetadata(t), Builder: runtimeContentRecordBuilder(id, id),
			}}); err != nil {
				t.Fatal(err)
			}
		}

		refuseFlush(true)
		if _, err := runtime.Emit(held, diagnosticMetadata(t), runtimeContentRecordBuilder("held-unflushed", "held-unflushed")); err != nil {
			t.Fatal(err)
		}
		emitBatch(held, "held-batch-unflushed")
		assertNoRuntimeDelivery(t, sink)
		for _, id := range []string{"held-unflushed", "held-batch-unflushed"} {
			if got := countRuntimeRecord(t, dependencies, id); got != 1 {
				t.Fatalf("%s stored %d times, want once", id, got)
			}
		}
		if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t), runtimeContentRecordBuilder("default-unflushed", "default-unflushed")); err != nil {
			t.Fatal(err)
		}
		if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "default-unflushed" {
			t.Fatalf("sink received %q, want default-unflushed", item.identity.RecordID)
		}

		refuseFlush(false)
		if _, err := runtime.Emit(held, diagnosticMetadata(t), runtimeContentRecordBuilder("held-flushed", "held-flushed")); err != nil {
			t.Fatal(err)
		}
		if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "held-flushed" {
			t.Fatalf("sink received %q, want held-flushed", item.identity.RecordID)
		}
		emitBatch(held, "held-batch-flushed")
		if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != "held-batch-flushed" {
			t.Fatalf("sink received %q, want held-batch-flushed", item.identity.RecordID)
		}
		assertNoRuntimeDelivery(t, sink)
	})
}
