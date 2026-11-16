// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// offerChange emits one offer of a spooled change, as its sender does: one
// attempt of tracker, the store already holding it when storedLocally.
func offerChange(
	t *testing.T, runtime *Runtime, tracker *observability.RemoteDelivery, storedLocally bool, builder EmitBuilder,
) error {
	t.Helper()
	return offerChangeIn(t, t.Context(), runtime, tracker, storedLocally, builder)
}

// offerChangeIn is offerChange on ctx.
func offerChangeIn(
	t *testing.T, ctx context.Context, runtime *Runtime, tracker *observability.RemoteDelivery, storedLocally bool,
	builder EmitBuilder,
) error {
	t.Helper()
	if storedLocally {
		ctx = observability.WithSkipLocalWrite(ctx)
	}
	tracker.BeginAttempt()
	defer tracker.EndAttempt()
	_, err := runtime.Emit(observability.WithRemoteDelivery(ctx, tracker), diagnosticMetadata(t), builder)
	return err
}

// settleChange waits until tracker's last attempt has nothing in flight and
// returns whether every destination has the change.
func settleChange(t *testing.T, tracker *observability.RemoteDelivery) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if settled, delivered := tracker.Settled(); settled {
			return delivered
		}
		if time.Now().After(deadline) {
			t.Fatal("the deliveries of the offer did not settle")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A change event is a spooled occurrence its one sender offers until every
// sink has it: the local store and each destination, each on its own.
// While SQLite reads but cannot insert, the destination still gets the
// change, and only once however often it is offered: a later offer skips a
// destination that has it in flight or acknowledged it. Once the store
// takes it the change is stored once, and no destination gets it again
// until a new sender (a restart) offers it. Before, a change was exported
// only after its local row was written and flushed, so a remote sink
// waited on the local store, and an offer made while a delivery was in
// flight sent the destination a second copy.
func TestRuntimeSendsAChangeToEachSinkOnItsOwn(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("sink", "none", 8),
			}
		},
	)
	sink := newRuntimeRecordingAdapter(16)
	release := make(chan struct{})
	sink.release = release
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
	defer database.Close() //nolint:errcheck
	if _, err := database.Exec(`CREATE TRIGGER local_history_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	const recordID = "runtime-change-sinks"
	build := runtimeContentRecordBuilder(recordID, "change")
	tracker := observability.NewRemoteDelivery()
	if err := offerChange(t, runtime, tracker, false, build); err == nil {
		t.Fatal("the offer stored the change under a failing SQLite writer")
	}
	if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != recordID {
		t.Fatalf("the destination received %q, want the change while the store is down", item.identity.RecordID)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := offerChange(t, runtime, tracker, false, build); err == nil {
			t.Fatalf("offer %d stored the change under a failing SQLite writer", attempt)
		}
	}
	assertNoRuntimeDelivery(t, sink)
	if settled, _ := tracker.Settled(); settled {
		t.Fatal("an offer with a delivery in flight settled")
	}
	close(release)
	if !settleChange(t, tracker) || !tracker.Acknowledged("sink") {
		t.Fatal("the acknowledged delivery did not settle as delivered")
	}
	// No second copy was queued behind the one in flight.
	assertNoRuntimeDelivery(t, sink)
	if _, err := database.Exec(`DROP TRIGGER local_history_full`); err != nil {
		t.Fatal(err)
	}
	if err := offerChange(t, runtime, tracker, false, build); err != nil {
		t.Fatalf("offer after the store recovered: %v", err)
	}
	if err := offerChange(t, runtime, tracker, true, build); err != nil {
		t.Fatalf("offer of the stored change: %v", err)
	}
	assertNoRuntimeDelivery(t, sink)
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the offers left %d stored rows, want 1", n)
	}
	restarted := observability.NewRemoteDelivery()
	if err := offerChange(t, runtime, restarted, true, build); err != nil {
		t.Fatal(err)
	}
	if item := receiveRuntimeDelivery(t, sink); item.identity.RecordID != recordID {
		t.Fatalf("the destination received %q after a restart", item.identity.RecordID)
	}
	if !settleChange(t, restarted) {
		t.Fatal("the offer after a restart did not settle as delivered")
	}
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the offer after a restart left %d stored rows, want 1", n)
	}
}

// A change event stays in its spool until every remote destination has it.
// The runtime tells the change's RemoteDelivery the outcome of each
// destination; an offer of a change the store holds (WithSkipLocalWrite)
// writes nothing locally and goes only to the destinations that did not
// acknowledge an earlier offer. After a restart (a new RemoteDelivery) it
// goes to every destination again. An atomic batch, which writes every
// item, refuses it.
func TestRuntimeReplaysAStoredChangeOnlyToDestinationsThatLackIt(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("acks", "none", 8),
				runtimeConsoleDestination("refuses", "none", 8),
			}
		},
	)
	adapters := map[string]*runtimeRecordingAdapter{
		"acks": newRuntimeRecordingAdapter(16), "refuses": newRuntimeRecordingAdapter(16),
	}
	adapters["refuses"].outcome = delivery.OutcomePermanentPayload
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context, destination config.ObservabilityV8EffectiveDestination, _ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapters[destination.Name], func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, plan, factory, nil)
	const recordID = "runtime-change-replay"
	build := runtimeContentRecordBuilder(recordID, "change")
	offer := func(tracker *observability.RemoteDelivery, stored bool) {
		t.Helper()
		if err := offerChange(t, runtime, tracker, stored, build); err != nil {
			t.Fatalf("offer (stored %t): %v", stored, err)
		}
	}
	received := func(name string) {
		t.Helper()
		if item := receiveRuntimeDelivery(t, adapters[name]); item.identity.RecordID != recordID {
			t.Fatalf("%s received %q", name, item.identity.RecordID)
		}
	}

	tracker := observability.NewRemoteDelivery()
	offer(tracker, false)
	received("acks")
	received("refuses")
	if settleChange(t, tracker) {
		t.Fatal("an offer a destination refused settled as delivered")
	}
	if !tracker.Acknowledged("acks") || tracker.Acknowledged("refuses") {
		t.Fatal("the acknowledgements are not per destination")
	}
	offer(tracker, true)
	received("refuses")
	assertNoRuntimeDelivery(t, adapters["acks"])
	if settleChange(t, tracker) {
		t.Fatal("an offer the destination refused again settled as delivered")
	}
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the offers left %d stored rows, want 1", n)
	}

	restarted := observability.NewRemoteDelivery()
	offer(restarted, true)
	received("acks")
	received("refuses")
	settleChange(t, restarted)
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the offer after a restart left %d stored rows, want 1", n)
	}

	if _, err := runtime.EmitAtomicBatch(t.Context(), []LogBatchItem{{
		Context: observability.WithSkipLocalWrite(t.Context()), Metadata: diagnosticMetadata(t),
		Builder: runtimeContentRecordBuilder("runtime-change-batch-stored", "change"),
	}}); err == nil {
		t.Fatal("an atomic batch took an occurrence the store already holds")
	}
	assertNoRuntimeDelivery(t, adapters["acks"])
}

// A config reload keeps a pending change deliverable, as the same record:
// the sender keeps the change and its RemoteDelivery, and its next offer
// goes to the destinations of the generation the reload made, still built
// on the config its record was pinned on (observability.WithPinnedProvenance).
// The store still holds it once. Any other record must still name the
// current generation: a record of the replaced one without the pin, or a
// pinned offer whose record names another config. Before, the offer after
// the reload was rebuilt on the new generation, so the destination got
// another record under the id the first offer had.
func TestRuntimeSendsAPendingChangeAfterAReload(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	makePlan := func(generation string) *config.ObservabilityV8Plan {
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
			func(source *config.ObservabilityV8Source) {
				source.Resource.Attributes = map[string]string{"team.generation": generation}
				source.Destinations = []config.ObservabilityV8DestinationSource{
					runtimeConsoleDestination("sink", "none", 8),
				}
			},
		)
	}
	adapter := newRuntimeRecordingAdapter(16)
	adapter.outcome = delivery.OutcomePermanentPayload
	factory := runtimeAdapterFactoryFunc(func(
		context.Context, config.ObservabilityV8EffectiveDestination, telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapter, func(context.Context) error { return nil }, nil
	})
	runtime := runtimeWithAdapterFactory(t, dependencies, makePlan("one"), factory, nil)
	const recordID = "runtime-change-reload"
	var first EmitContext
	storing := func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		first = snapshot
		return runtimeContentRecordBuilder(recordID, "change")(snapshot, admission)
	}
	tracker := observability.NewRemoteDelivery()
	if err := offerChange(t, runtime, tracker, false, storing); err != nil {
		t.Fatal(err)
	}
	_ = receiveRuntimeDelivery(t, adapter)
	if settleChange(t, tracker) {
		t.Fatal("a refused offer settled as delivered")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result, graphErr := runtime.Reload(ctx, runtimegraph.ConfigFromPlan(makePlan("two"), false))
	if graphErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload status=%v err=%v", result.Status(), graphErr)
	}
	active := runtime.Active()
	if active.Generation() == first.Generation() || active.Digest() == first.Digest() {
		t.Fatal("the reload kept the generation and digest")
	}
	adapter.outcome = delivery.OutcomeDelivered
	pinned := observability.WithPinnedProvenance(t.Context(), observability.PinnedProvenance{
		ConfigGeneration: first.Generation(), ConfigDigest: first.Digest(),
	})
	asPinned := func(_ EmitContext, admission router.Admission) (observability.Record, error) {
		return runtimeContentRecordBuilder(recordID, "change")(first, admission)
	}
	if err := offerChangeIn(t, pinned, runtime, tracker, true, runtimeContentRecordBuilder(recordID, "change")); err == nil {
		t.Fatal("a pinned offer whose record names the current config was accepted")
	}
	assertNoRuntimeDelivery(t, adapter)
	if err := offerChangeIn(t, pinned, runtime, tracker, true, asPinned); err != nil {
		t.Fatalf("an offer of the pending change after a reload: %v", err)
	}
	item := receiveRuntimeDelivery(t, adapter)
	if item.identity.RecordID != recordID || !strings.Contains(string(item.bytes), first.Digest()) ||
		strings.Contains(string(item.bytes), active.Digest()) {
		t.Fatalf("the offer after the reload is not the pinned record: %s", item.bytes)
	}
	if !settleChange(t, tracker) {
		t.Fatal("the offer after the reload did not settle as delivered")
	}
	if n := countRuntimeRecord(t, dependencies, recordID); n != 1 {
		t.Fatalf("the reload and the offers left %d stored rows, want 1", n)
	}
	stale := func(_ EmitContext, admission router.Admission) (observability.Record, error) {
		return runtimeContentRecordBuilder("runtime-change-stale", "stale")(first, admission)
	}
	if _, err := runtime.Emit(t.Context(), diagnosticMetadata(t), stale); err == nil {
		t.Fatal("a new record of the replaced generation was accepted")
	}
	assertNoRuntimeDelivery(t, adapter)
}
