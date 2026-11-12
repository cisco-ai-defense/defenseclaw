// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

const rejectedTestToken = "ghp_1234567890abcdefghijklmnopqrstuv"

func rejectedRecordWriterGoroutines() int {
	buf := make([]byte, 1<<20)
	n := goruntime.Stack(buf, true)
	return strings.Count(string(buf[:n]), "(*rejectedRecordWriter).run")
}

func keepRejectedPlan(t *testing.T, dependencies runtimeTestDependencies, keep bool) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, func(source *config.ObservabilityV8Source) {
		source.Local.KeepRejectedRecords = &keep
	})
}

// buildRefusedHookDecision runs one generated log through the v8 schema gate
// with a hook result outside its enum, so the gate refuses it.
func buildRefusedHookDecision(t *testing.T) {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }), observability.TimeOrderedOccurrenceIDs,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.BuildLogCompatHookDecision(observability.LogCompatHookDecisionInput{
		Envelope: observability.FamilyEnvelopeInput{
			ObservedAt: observability.Present(time.Now().UTC()),
			Source:     observability.SourceGateway, Connector: "codex", Action: "hook", Phase: "completed",
			Correlation: observability.Correlation{RunID: "run-1"},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "rejected_test", BinaryVersion: "v8-test", ConfigGeneration: 1,
				BuildCommit: "abcd", ConfigDigest: "cafe",
			},
		},
		Outcome:                             observability.OutcomeAllowed,
		DefenseClawRequestID:                observability.Present("rejected-runtime-request"),
		DefenseClawHookEvent:                "PreToolUse",
		DefenseClawHookResult:               "success",
		DefenseClawGuardrailEffectiveAction: "allow", DefenseClawGuardrailRawAction: "allow",
		DefenseClawSecuritySeverity: "INFO", DefenseClawGuardrailMode: "observe",
		DefenseClawGuardrailReason: observability.Present("denied: token=" + rejectedTestToken),
	})
	if !observability.IsFamilyBuildError(err, observability.FamilyBuildConstraint) {
		t.Fatalf("the schema gate did not refuse the record: %v", err)
	}
}

func waitRejectedRows(t *testing.T, store *audit.Store, want int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		count, err := store.CountRejectedRecords(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if count == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejected rows=%d, want %d", count, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitRejectedWriters(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := rejectedRecordWriterGoroutines()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("rejected-record writer goroutines=%d, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Principle 5: with the key off (the default) the runtime starts no writer
// goroutine, installs no sink and writes no row; a refused record is only
// counted by its producer, as before.
func TestRejectedRecordStoreOffStartsNothingAndWritesNothing(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	before := rejectedRecordWriterGoroutines()
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	if plan.Snapshot().Local.KeepRejectedRecords {
		t.Fatal("keep_rejected_records is on by default")
	}
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	if observability.RejectedRecordSinkInstalled() {
		t.Fatal("a sink is installed while the store is off")
	}
	if after := rejectedRecordWriterGoroutines(); after != before {
		t.Fatalf("writer goroutines %d -> %d while off", before, after)
	}
	buildRefusedHookDecision(t)
	time.Sleep(50 * time.Millisecond)
	if count, err := dependencies.store.CountRejectedRecords(t.Context()); err != nil || count != 0 {
		t.Fatalf("rows=%d err=%v while off", count, err)
	}
	if stats := runtime.RejectedRecordStats(); stats != (RejectedRecordStats{}) {
		t.Fatalf("stats=%+v while off", stats)
	}
}

func TestRejectedRecordStoreOnKeepsARedactedCopyAndReloadOffStopsIt(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	runtime := newRuntimeForTest(t, dependencies, keepRejectedPlan(t, dependencies, true), false)
	if !observability.RejectedRecordSinkInstalled() {
		t.Fatal("on: no sink installed")
	}
	waitRejectedWriters(t, 1)
	buildRefusedHookDecision(t)
	waitRejectedRows(t, dependencies.store, 1)
	rows, err := dependencies.store.ListRejectedRecords(t.Context(), audit.RejectedRecordQuery{Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	row := rows[0]
	if row.Signal != "logs" || row.ReasonCode != "constraint_violation" || row.Field != "defenseclaw.hook.result" ||
		row.Connector != "codex" || row.Source != "gateway" || row.EventName == "" || row.Family == "" ||
		row.PayloadState != audit.RejectedPayloadRedacted {
		t.Fatalf("row=%+v", row)
	}
	if !bytes.Contains(row.Payload, []byte(`"defenseclaw.hook.result":"success"`)) {
		t.Fatalf("the refused value is not in the kept copy: %s", row.Payload)
	}
	if bytes.Contains(row.Payload, []byte(rejectedTestToken)) {
		t.Fatalf("a secret was stored unredacted: %s", row.Payload)
	}
	// The counter moves just after the commit the row count already sees.
	deadline := time.Now().Add(5 * time.Second)
	for runtime.RejectedRecordStats().Stored != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("stats=%+v", runtime.RejectedRecordStats())
		}
		time.Sleep(10 * time.Millisecond)
	}

	result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(keepRejectedPlan(t, dependencies, false), false))
	if reloadErr != nil {
		t.Fatalf("reload off: %v (%+v)", reloadErr, result)
	}
	if observability.RejectedRecordSinkInstalled() {
		t.Fatal("the sink stayed installed after the key was turned off")
	}
	waitRejectedWriters(t, 0)
	buildRefusedHookDecision(t)
	time.Sleep(50 * time.Millisecond)
	waitRejectedRows(t, dependencies.store, 1)
}

func TestRejectedRecordWriterDropsAndCountsInsteadOfBlocking(t *testing.T) {
	factory := &rejectedRecordFactory{}
	writer := &rejectedRecordWriter{
		factory: factory, maxRows: audit.RejectedRecordsMinRows,
		queue: make(chan observability.RejectedRecord, 2),
		stop:  make(chan struct{}), done: make(chan struct{}), now: time.Now,
	}
	writer.OfferRejectedRecord(observability.RejectedRecord{})
	if stats := factory.counters.snapshot(); stats.DroppedStopping != 1 {
		t.Fatalf("an inactive writer queued: %+v", stats)
	}
	writer.accepting.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < audit.RejectedRecordsMinRows+10; index++ {
			writer.OfferRejectedRecord(observability.RejectedRecord{})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OfferRejectedRecord blocked on a full queue")
	}
	stats := factory.counters.snapshot()
	if len(writer.queue) != 2 || stats.DroppedQueue != uint64(audit.RejectedRecordsMinRows-2) || stats.DroppedRunCap != 10 {
		t.Fatalf("queued=%d stats=%+v", len(writer.queue), stats)
	}
}

func TestRejectedRecordWriterKeepsMetadataWhenThePayloadCannotBeKept(t *testing.T) {
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := redaction.BuiltInProfile(redaction.ProfileSensitive)
	writer := &rejectedRecordWriter{factory: &rejectedRecordFactory{engine: engine}, profile: profile, now: time.Now}
	unclassified := writer.row(observability.RejectedRecord{
		Reason: observability.FamilyBuildConstraint, Body: map[string]any{"a": "b"},
	}, time.Now())
	if unclassified.PayloadState != audit.RejectedPayloadRedactionFailed || string(unclassified.Payload) != "{}" ||
		len(unclassified.OmittedFields) != 1 || unclassified.OmittedFields[0] != "a" {
		t.Fatalf("unclassified row=%+v", unclassified)
	}
	body, classes := map[string]any{}, map[string]observability.FieldClass{}
	for index := 0; index < 5; index++ {
		key := "field." + strings.Repeat("k", index+1)
		body[key] = strings.Repeat("v", 4<<10)
		classes["/"+key] = observability.FieldClassMetadata
	}
	oversize := writer.row(observability.RejectedRecord{Body: body, FieldClasses: classes}, time.Now())
	if oversize.PayloadState != audit.RejectedPayloadOmittedOversize || len(oversize.OmittedFields) != 5 {
		t.Fatalf("oversize row state=%s omitted=%v", oversize.PayloadState, oversize.OmittedFields)
	}
}

func TestRejectedRecordStoreIsNeverOnForSecureClient(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	factory := &rejectedRecordFactory{store: dependencies.store, engine: dependencies.engine, secureClient: true}
	component, err := factory.Prepare(context.Background(),
		runtimegraph.BuildInput{Config: runtimegraph.ConfigFromPlan(keepRejectedPlan(t, dependencies, true), false)},
		&runtimegraph.Acquisitions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, off := component.(*rejectedRecordsOff); !off {
		t.Fatalf("Secure Client component=%T", component)
	}
}
