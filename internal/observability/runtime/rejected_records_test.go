// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	goruntime "runtime"
	"strings"
	"sync"
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

func offerRejectedForTest(writer *rejectedRecordWriter) {
	if writer.ReserveRejectedRecord() {
		writer.OfferRejectedRecord(observability.RejectedRecord{})
	}
}

func idleRejectedWriter(factory *rejectedRecordFactory, maxRows, queue int) *rejectedRecordWriter {
	return &rejectedRecordWriter{
		factory: factory, maxRows: maxRows, queue: make(chan observability.RejectedRecord, queue),
		stop: make(chan struct{}), done: make(chan struct{}), now: time.Now,
		profiles: map[observability.Bucket]redaction.Profile{},
	}
}

func TestRejectedRecordWriterDropsAndCountsInsteadOfBlocking(t *testing.T) {
	factory := &rejectedRecordFactory{}
	writer := idleRejectedWriter(factory, audit.RejectedRecordsMinRows, 2)
	offerRejectedForTest(writer)
	if stats := factory.counters.snapshot(); stats.DroppedStopping != 1 {
		t.Fatalf("an inactive writer queued: %+v", stats)
	}
	writer.accepting.Store(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for index := 0; index < audit.RejectedRecordsMinRows+10; index++ {
			offerRejectedForTest(writer)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a refused record blocked on a full queue")
	}
	// A full queue drops without using the run's rows: only queued rows count
	// toward the cap.
	stats := factory.counters.snapshot()
	if len(writer.queue) != 2 || writer.queued.Load() != 2 ||
		stats.DroppedQueue != uint64(audit.RejectedRecordsMinRows+8) || stats.DroppedRunCap != 0 {
		t.Fatalf("queued=%d reserved=%d stats=%+v", len(writer.queue), writer.queued.Load(), stats)
	}
}

func TestRejectedRecordRunCapCountsQueuedRowsAndResetsPerGeneration(t *testing.T) {
	factory := &rejectedRecordFactory{}
	first := idleRejectedWriter(factory, audit.RejectedRecordsMinRows, rejectedRecordQueueItems)
	first.accepting.Store(true)
	for index := 0; index < audit.RejectedRecordsMinRows+10; index++ {
		offerRejectedForTest(first)
	}
	if stats := factory.counters.snapshot(); len(first.queue) != audit.RejectedRecordsMinRows || stats.DroppedRunCap != 10 {
		t.Fatalf("queued=%d stats=%+v", len(first.queue), stats)
	}
	// The next generation (a reload, or turning the key off and on) starts a
	// new run with its own count.
	second := idleRejectedWriter(factory, audit.RejectedRecordsMinRows, rejectedRecordQueueItems)
	second.accepting.Store(true)
	offerRejectedForTest(second)
	if len(second.queue) != 1 {
		t.Fatal("a new run inherited the previous run's cap")
	}
}

// Every refused record offered while intake stops is either written or
// counted as dropped: no offer can queue after Drain's final pass.
func TestRejectedRecordDrainAccountsForEveryOffer(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	factory := &rejectedRecordFactory{store: dependencies.store, engine: dependencies.engine}
	component, err := factory.Prepare(context.Background(),
		runtimegraph.BuildInput{Config: runtimegraph.ConfigFromPlan(keepRejectedPlan(t, dependencies, true), false)},
		&runtimegraph.Acquisitions{})
	if err != nil {
		t.Fatal(err)
	}
	writer := component.(*rejectedRecordWriter)
	writer.Activate()
	defer observability.ClearRejectedRecordSink()
	const producers, each = 8, 200
	var wait sync.WaitGroup
	for producer := 0; producer < producers; producer++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < each; index++ {
				if writer.ReserveRejectedRecord() {
					writer.OfferRejectedRecord(observability.RejectedRecord{
						Signal: observability.SignalLogs, Bucket: observability.BucketComplianceActivity,
						Reason: observability.FamilyBuildConstraint, Body: map[string]any{},
						FieldClasses: map[string]observability.FieldClass{},
					})
				}
			}
		}()
	}
	time.Sleep(2 * time.Millisecond)
	if err := writer.Drain(lifecycleTestContext(t)); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	stats := factory.counters.snapshot()
	total := stats.Stored + stats.WriteFailed + stats.DroppedQueue + stats.DroppedRunCap + stats.DroppedStopping
	if total != producers*each || len(writer.queue) != 0 {
		t.Fatalf("accounted %d of %d offers (queue left %d): %+v", total, producers*each, len(writer.queue), stats)
	}
	if count, _ := dependencies.store.CountRejectedRecords(t.Context()); uint64(count) != stats.Stored {
		t.Fatalf("rows=%d stored=%d", count, stats.Stored)
	}
}

func TestRejectedRecordWriterTrimsALoweredCapInBoundedBatches(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	rows := make([]audit.RejectedRecordRow, 0, audit.RejectedRecordMaxBatch)
	for batch := 0; batch < 80; batch++ {
		rows = rows[:0]
		for index := 0; index < audit.RejectedRecordMaxBatch; index++ {
			rows = append(rows, audit.RejectedRecordRow{Signal: "logs", ReasonCode: "constraint_violation"})
		}
		if err := dependencies.store.InsertRejectedRecords(t.Context(), rows, audit.RejectedRecordsMaxRows); err != nil {
			t.Fatal(err)
		}
	}
	writer := idleRejectedWriter(&rejectedRecordFactory{store: dependencies.store}, audit.RejectedRecordsMinRows, 1)
	writer.trimPause = time.Millisecond
	writer.trim()
	if count, _ := dependencies.store.CountRejectedRecords(t.Context()); count != audit.RejectedRecordsMinRows {
		t.Fatalf("rows after trim=%d want %d", count, audit.RejectedRecordsMinRows)
	}
}

const rejectedTestPrivateKey = "-----BEGIN PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----"

func rejectedSecretsRecord(bucket observability.Bucket) observability.RejectedRecord {
	return observability.RejectedRecord{
		Bucket: bucket, Reason: observability.FamilyBuildConstraint,
		Body: map[string]any{
			"gen_ai.prompt":           "please summarise the merger memo for project bluebird",
			"defenseclaw.file.body":   "root:x:0:0:root:/root:/bin/bash\ndb_password_line_here",
			"defenseclaw.key":         "key material\n" + rejectedTestPrivateKey,
			"defenseclaw.hook.result": "success",
		},
		FieldClasses: map[string]observability.FieldClass{
			"/gen_ai.prompt":           observability.FieldClassContent,
			"/defenseclaw.file.body":   observability.FieldClassEvidence,
			"/defenseclaw.key":         observability.FieldClassContent,
			"/defenseclaw.hook.result": observability.FieldClassMetadata,
		},
	}
}

func TestRejectedRecordRedactionIsNeverLessThanTheBucketsLocalProfile(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	keep := true
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, func(source *config.ObservabilityV8Source) {
		source.Local.KeepRejectedRecords = &keep
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {RedactionProfile: "strict"},
		}
	})
	// A production engine holds the correlation key; without it the keyed
	// detect transforms fail every dynamic field closed.
	keyed, err := redaction.NewEngine(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	factory := &rejectedRecordFactory{store: dependencies.store, engine: keyed}
	component, err := factory.Prepare(context.Background(),
		runtimegraph.BuildInput{Config: runtimegraph.ConfigFromPlan(plan, false)}, &runtimegraph.Acquisitions{})
	if err != nil {
		t.Fatal(err)
	}
	writer := component.(*rejectedRecordWriter)

	strict := writer.row(rejectedSecretsRecord(observability.BucketComplianceActivity), time.Now())
	for _, leaked := range []string{"BEGIN PRIVATE KEY", "AAAAAAAAAAAAAAAA", "root:x:0:0", "bluebird"} {
		if bytes.Contains(strict.Payload, []byte(leaked)) {
			t.Fatalf("a strict bucket kept %q: %s", leaked, strict.Payload)
		}
	}
	if !bytes.Contains(strict.Payload, []byte(`"defenseclaw.hook.result":"success"`)) {
		t.Fatalf("metadata lost: %s", strict.Payload)
	}

	// Another bucket keeps its default local profile (none): the store still
	// applies sensitive, so the key is redacted while the prompt text stays.
	var other observability.Bucket
	for _, bucket := range observability.Buckets() {
		if bucket != observability.BucketComplianceActivity {
			other = bucket
			break
		}
	}
	sensitive := writer.row(rejectedSecretsRecord(other), time.Now())
	if bytes.Contains(sensitive.Payload, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(sensitive.Payload, []byte("AAAAAAAAAAAAAAAA")) {
		t.Fatalf("sensitive kept the private key: %s", sensitive.Payload)
	}
	if !bytes.Contains(sensitive.Payload, []byte("bluebird")) {
		t.Fatalf("sensitive is the documented floor; prompt text expected: %s", sensitive.Payload)
	}
	// An unknown bucket is kept at strict.
	unknown := writer.row(rejectedSecretsRecord("not-a-bucket"), time.Now())
	if bytes.Contains(unknown.Payload, []byte("bluebird")) {
		t.Fatalf("an unresolvable bucket was not kept at strict: %s", unknown.Payload)
	}
}

func TestRejectedRecordWriterKeepsMetadataWhenThePayloadCannotBeKept(t *testing.T) {
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := redaction.BuiltInProfile(redaction.ProfileSensitive)
	writer := &rejectedRecordWriter{factory: &rejectedRecordFactory{engine: engine}, sensitive: profile, now: time.Now,
		profiles: map[observability.Bucket]redaction.Profile{}}
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
