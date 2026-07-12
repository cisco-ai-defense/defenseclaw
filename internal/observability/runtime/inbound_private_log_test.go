// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type inboundSQLiteCheckingAdapter struct {
	recording          *runtimeRecordingAdapter
	check              func(string) bool
	sqliteBeforeRemote atomic.Bool
}

func (adapter *inboundSQLiteCheckingAdapter) EncodedSize(sizes []int) (int, bool) {
	return adapter.recording.EncodedSize(sizes)
}

func (adapter *inboundSQLiteCheckingAdapter) Deliver(
	ctx context.Context,
	batch delivery.Batch,
) delivery.DeliveryResult {
	for _, item := range batch.Items() {
		if adapter.check(item.Identity().RecordID) {
			adapter.sqliteBeforeRemote.Store(true)
		}
	}
	return adapter.recording.Deliver(ctx, batch)
}

func TestInboundPrivateMandatoryFamilyLogPersistsOrdinarySQLiteRecord(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	logs := true
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Logs = &logs
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("remote", "none", 0),
			}
		},
	)
	recording := newRuntimeRecordingAdapter(1)
	checking := &inboundSQLiteCheckingAdapter{
		recording: recording,
		check: func(recordID string) bool {
			events, listErr := dependencies.store.ListEvents(16)
			if listErr != nil {
				return false
			}
			for _, event := range events {
				if event.ID == recordID {
					return true
				}
			}
			return false
		},
	}
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return checking, func(context.Context) error { return nil }, nil
	})
	runtime := newInboundRuntimeForTest(t, dependencies, plan, factory)
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()

	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target, ok := catalog.Target("otlp.native.log.v8.log.config.change.applied.log.config.change.applied")
	if !ok {
		t.Fatal("missing config-change imported target")
	}
	context, ok := target.ImportContext()
	if !ok {
		t.Fatal("config-change imported target has no context")
	}
	severity := observability.SeverityInfo
	metadata, err := router.NewInboundImportedLogMetadata(target, context, &severity, "codex")
	if err != nil {
		t.Fatal(err)
	}
	operation := inboundRuntimeField(t, target, "defenseclaw.admin.operation")
	var occurrenceCalls atomic.Int64
	familyBuilder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(func() time.Time {
			t.Fatal("private imported log consulted producer clock")
			return time.Time{}
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			occurrenceCalls.Add(1)
			return "inbound-runtime-config-change", nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt := time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC)
	var built observability.Record
	outcome, err := batch.EmitLog(t.Context(), metadata, func(
		snapshot EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			t.Fatalf("imported mandatory-family admission = %s", admission)
		}
		record, buildErr := familyBuilder.BuildLog(
			target,
			context,
			observability.InboundImportedLogInput{
				Timestamp: receipt.Add(-time.Second), ReceiptTime: receipt,
				Correlation: observability.Correlation{RequestID: "request-1"},
				Provenance: observability.InboundLocalProvenanceInput{
					BinaryVersion: "test", ConfigGeneration: int64(snapshot.Generation()),
					ConfigDigest: snapshot.Digest(),
				},
				Import: observability.InboundImportProvenanceInput{
					AuthenticatedSource: "codex", UpstreamInstanceID: "upstream-instance",
					UpstreamRecordID: "123e4567-e89b-12d3-a456-426614174000",
					IngressHopCount:  1, LastHopInstanceID: "forwarder-instance",
					LastHopDestination: "upstream-otlp",
				},
				Severity: observability.Present(observability.SeverityInfo),
				LogLevel: observability.Present(observability.LogLevelInfo),
				Outcome:  observability.Present(observability.OutcomeApplied),
				Fields: []observability.InboundMappedField{
					observability.NewInboundMappedString(operation, "config-update"),
				},
			},
		)
		built = record
		return record, buildErr
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionOrdinary || !outcome.LocalPersisted() ||
		occurrenceCalls.Load() != 1 || built.RecordID() != "inbound-runtime-config-change" ||
		built.Mandatory() || built.IsFloorOnly() {
		t.Fatalf("outcome=%+v calls=%d record=%s mandatory=%t floor=%t",
			outcome, occurrenceCalls.Load(), built.RecordID(), built.Mandatory(), built.IsFloorOnly())
	}
	delivered := receiveRuntimeDelivery(t, recording)
	if delivered.identity.RecordID != built.RecordID() || delivered.destination != "remote" ||
		!checking.sqliteBeforeRemote.Load() {
		t.Fatalf("remote delivery=%+v sqlite-before-remote=%t", delivered, checking.sqliteBeforeRemote.Load())
	}
	events, err := dependencies.store.ListEvents(16)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, event := range events {
		if event.ID == built.RecordID() {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("imported SQLite rows = %d, want exactly one", count)
	}
}

func TestInboundPrivateMandatoryFamilyCollectionDisabledBeforeConstruction(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := inboundImportPlan(t, dependencies, 30, false, false)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	target, context, metadata, _ := inboundRuntimeConfigChangeFixture(t)
	_ = target
	_ = context
	var builderCalls atomic.Int64
	outcome, err := batch.EmitLog(t.Context(), metadata, func(
		EmitContext,
		router.Admission,
	) (observability.Record, error) {
		builderCalls.Add(1)
		return observability.Record{}, nil
	})
	if err != nil || outcome.Admission() != router.AdmissionDrop || outcome.LocalPersisted() ||
		builderCalls.Load() != 0 {
		t.Fatalf("disabled outcome=%+v calls=%d err=%v", outcome, builderCalls.Load(), err)
	}
}

func TestOTLPInboundSQLiteBeforeRemote(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	logs := true
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Logs = &logs
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("remote", "none", 0),
			}
		},
	)
	recording := newRuntimeRecordingAdapter(1)
	factory := runtimeAdapterFactoryFunc(func(
		context.Context,
		config.ObservabilityV8EffectiveDestination,
		telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return recording, func(context.Context) error { return nil }, nil
	})
	runtime := newInboundRuntimeForTest(t, dependencies, plan, factory)
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()

	database, err := sql.Open("sqlite", dependencies.storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`CREATE TRIGGER reject_private_import
		BEFORE INSERT ON audit_events
		WHEN NEW.id = 'inbound-runtime-persistence-failure'
		BEGIN SELECT RAISE(ABORT, 'injected private import failure'); END`); err != nil {
		t.Fatal(err)
	}

	target, context, metadata, operation := inboundRuntimeConfigChangeFixture(t)
	var occurrenceCalls atomic.Int64
	outcome, err := batch.EmitLog(t.Context(), metadata, inboundRuntimeConfigChangeBuilder(
		t, target, context, operation, "inbound-runtime-persistence-failure", &occurrenceCalls, nil,
	))
	if err == nil || outcome.LocalPersisted() || occurrenceCalls.Load() != 1 ||
		len(outcome.OptionalWork()) != 0 {
		t.Fatalf("persistence-failure outcome=%+v calls=%d err=%v", outcome, occurrenceCalls.Load(), err)
	}
	select {
	case delivery := <-recording.delivered:
		t.Fatalf("SQLite-failed import reached remote adapter: %+v", delivery)
	case <-time.After(250 * time.Millisecond):
	}
}

func TestInboundPrivateLogOriginAndTerminalPoliciesStayOutsideCanonicalRecord(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	logs := true
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Logs = &logs
			source.Destinations = []config.ObservabilityV8DestinationSource{
				runtimeConsoleDestination("upstream-otlp", "none", 0),
				runtimeConsoleDestination("sibling", "none", 0),
			}
		},
	)
	adapters := map[string]*runtimeRecordingAdapter{
		"upstream-otlp": newRuntimeRecordingAdapter(4),
		"sibling":       newRuntimeRecordingAdapter(4),
	}
	factory := runtimeAdapterFactoryFunc(func(
		_ context.Context,
		destination config.ObservabilityV8EffectiveDestination,
		_ telemetry.V8ResourceContext,
	) (delivery.Adapter, DestinationAdapterCleanup, error) {
		return adapters[destination.Name], func(context.Context) error { return nil }, nil
	})
	runtime := newInboundRuntimeForTest(t, dependencies, plan, factory)
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	target, importContext, metadata, operation := inboundRuntimeConfigChangeFixture(t)
	originPolicy, err := NewInboundOriginDestination("upstream-otlp")
	if err != nil {
		t.Fatal(err)
	}

	var calls atomic.Int64
	var originRecord observability.Record
	originOutcome, err := batch.EmitImportedLog(
		t.Context(), metadata, originPolicy,
		inboundRuntimeConfigChangeBuilder(
			t, target, importContext, operation, "inbound-origin-log", &calls, &originRecord,
		),
	)
	if err != nil || !originOutcome.LocalPersisted() || calls.Load() != 1 {
		t.Fatalf("origin outcome=%+v calls=%d err=%v", originOutcome, calls.Load(), err)
	}
	sibling := receiveRuntimeDelivery(t, adapters["sibling"])
	if sibling.identity.RecordID != originRecord.RecordID() {
		t.Fatalf("sibling delivery=%+v record=%s", sibling, originRecord.RecordID())
	}
	select {
	case delivered := <-adapters["upstream-otlp"].delivered:
		t.Fatalf("origin received recursive import: %+v", delivered)
	case <-time.After(200 * time.Millisecond):
	}
	encoded, err := originRecord.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte(`"origin_destination"`)) {
		t.Fatal("private origin was serialized into the canonical record")
	}

	// The canonical last_hop_destination intentionally contains the same text.
	// Without the authenticated local policy it cannot suppress either sibling.
	var foreignRecord observability.Record
	foreignOutcome, err := batch.EmitLog(
		t.Context(), metadata,
		inboundRuntimeConfigChangeBuilder(
			t, target, importContext, operation, "inbound-foreign-log", &calls, &foreignRecord,
		),
	)
	if err != nil || !foreignOutcome.LocalPersisted() {
		t.Fatalf("foreign outcome=%+v err=%v", foreignOutcome, err)
	}
	for name, adapter := range adapters {
		delivered := receiveRuntimeDelivery(t, adapter)
		if delivered.identity.RecordID != foreignRecord.RecordID() || delivered.destination != name {
			t.Fatalf("foreign delivery %s=%+v", name, delivered)
		}
	}

	terminalOutcome, err := batch.EmitImportedLog(
		t.Context(), metadata, SuppressAllInboundOptionalExport(),
		inboundRuntimeConfigChangeBuilder(
			t, target, importContext, operation, "inbound-terminal-log", &calls, nil,
		),
	)
	if err != nil || !terminalOutcome.LocalPersisted() || len(terminalOutcome.OptionalWork()) != 0 {
		t.Fatalf("terminal outcome=%+v err=%v", terminalOutcome, err)
	}
	for name, adapter := range adapters {
		select {
		case delivered := <-adapter.delivered:
			t.Fatalf("terminal import reached %s: %+v", name, delivered)
		case <-time.After(100 * time.Millisecond):
		}
	}

	beforeInvalid := calls.Load()
	invalidOutcome, err := batch.EmitImportedLog(
		t.Context(), metadata,
		InboundOptionalExportPolicy{originDestination: "not a stable token"},
		inboundRuntimeConfigChangeBuilder(
			t, target, importContext, operation, "invalid-origin-log", &calls, nil,
		),
	)
	var importErr *InboundImportError
	if !errors.As(err, &importErr) || importErr.Code() != InboundImportInvalidInput ||
		invalidOutcome.LocalPersisted() || calls.Load() != beforeInvalid {
		t.Fatalf("invalid outcome=%+v calls=%d err=%v", invalidOutcome, calls.Load(), err)
	}

	events, err := dependencies.store.ListEvents(16)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, event := range events {
		counts[event.ID]++
	}
	for _, id := range []string{"inbound-origin-log", "inbound-foreign-log", "inbound-terminal-log"} {
		if counts[id] != 1 {
			t.Fatalf("SQLite count[%s]=%d", id, counts[id])
		}
	}
	if counts["invalid-origin-log"] != 0 {
		t.Fatal("invalid origin constructed or persisted a log")
	}
}

func inboundRuntimeConfigChangeFixture(t *testing.T) (
	observability.InboundTarget,
	observability.InboundImportContext,
	router.Metadata,
	observability.InboundTargetField,
) {
	t.Helper()
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target, ok := catalog.Target("otlp.native.log.v8.log.config.change.applied.log.config.change.applied")
	if !ok {
		t.Fatal("missing config-change imported target")
	}
	context, ok := target.ImportContext()
	if !ok {
		t.Fatal("config-change imported target has no context")
	}
	severity := observability.SeverityInfo
	metadata, err := router.NewInboundImportedLogMetadata(target, context, &severity, "codex")
	if err != nil {
		t.Fatal(err)
	}
	return target, context, metadata, inboundRuntimeField(t, target, "defenseclaw.admin.operation")
}

func inboundRuntimeConfigChangeBuilder(
	t *testing.T,
	target observability.InboundTarget,
	context observability.InboundImportContext,
	operation observability.InboundTargetField,
	recordID string,
	occurrenceCalls *atomic.Int64,
	captured *observability.Record,
) EmitBuilder {
	t.Helper()
	return func(snapshot EmitContext, admission router.Admission) (observability.Record, error) {
		if admission != router.AdmissionOrdinary {
			t.Fatalf("imported mandatory-family admission = %s", admission)
		}
		builder, err := observability.NewInboundImportBuilder(
			observability.ClockFunc(func() time.Time { return time.Time{} }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) {
				occurrenceCalls.Add(1)
				return recordID, nil
			}),
		)
		if err != nil {
			return observability.Record{}, err
		}
		receipt := time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC)
		record, err := builder.BuildLog(target, context, observability.InboundImportedLogInput{
			Timestamp: receipt.Add(-time.Second), ReceiptTime: receipt,
			Correlation: observability.Correlation{RequestID: "request-1"},
			Provenance: observability.InboundLocalProvenanceInput{
				BinaryVersion: "test", ConfigGeneration: int64(snapshot.Generation()),
				ConfigDigest: snapshot.Digest(),
			},
			Import: observability.InboundImportProvenanceInput{
				AuthenticatedSource: "codex", UpstreamInstanceID: "upstream-instance",
				UpstreamRecordID: "123e4567-e89b-12d3-a456-426614174000",
				IngressHopCount:  1, LastHopInstanceID: "forwarder-instance",
				LastHopDestination: "upstream-otlp",
			},
			Severity: observability.Present(observability.SeverityInfo),
			LogLevel: observability.Present(observability.LogLevelInfo),
			Outcome:  observability.Present(observability.OutcomeApplied),
			Fields: []observability.InboundMappedField{
				observability.NewInboundMappedString(operation, "config-update"),
			},
		})
		if captured != nil {
			*captured = record
		}
		return record, err
	}
}

func inboundRuntimeField(
	t *testing.T,
	target observability.InboundTarget,
	name string,
) observability.InboundTargetField {
	t.Helper()
	for _, field := range target.Fields() {
		if field.FieldRef() == name {
			return field
		}
	}
	t.Fatalf("target %s has no field %s", target.ID(), name)
	return observability.InboundTargetField{}
}
