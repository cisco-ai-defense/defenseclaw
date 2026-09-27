// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v5"
)

func testSandboxIdentity() SandboxIdentity {
	return SandboxIdentity{
		ID: "0f5b3c2e-9d4a-4f61-8a7e-2c1b0d9e6f33", Name: "dc-claudecode-myapp-7f3a",
		Connector: "claudecode", Runtime: SandboxRuntimeOpenShell, Driver: SandboxDriverDocker,
		ImageDigest:   "sha256:" + strings.Repeat("ab", 32),
		PolicyVersion: 3, Profile: SandboxProfileOpen, Pack: "open",
		Phase: SandboxPhaseReady, WorkdirMode: SandboxWorkdirMount,
	}
}

// sandboxHarness shares one audit store across a test's cases. Opening a
// store runs every audit migration, which dominates this suite under -race;
// each case still binds a fresh capturing runtime and recorder, so records and
// tracked phases never leak between cases.
type sandboxHarness struct {
	logger *Logger
}

func newSandboxHarness(t *testing.T) *sandboxHarness {
	t.Helper()
	return &sandboxHarness{logger: newTestLogger(t)}
}

func (harness *sandboxHarness) bind(t *testing.T, admission router.Admission) (*testRuntimeV8Emitter, *SandboxRecorder) {
	t.Helper()
	runtime := newTestRuntimeV8Emitter(t, harness.logger.store, admission)
	harness.logger.SetRuntimeV8Emitter(runtime)
	return runtime, NewSandboxRecorder(harness.logger)
}

// newSandboxTestRecorder binds a recorder to its own store for cases that
// assert on event-history rows.
func newSandboxTestRecorder(t *testing.T, admission router.Admission) (*Logger, *testRuntimeV8Emitter, *SandboxRecorder) {
	t.Helper()
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, admission)
	return harness.logger, runtime, recorder
}

func onlySandboxRecord(t *testing.T, runtime *testRuntimeV8Emitter) (router.Metadata, observability.Record) {
	t.Helper()
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 {
		t.Fatalf("runtime captured metadata=%d records=%d, want one each", len(metadata), len(records))
	}
	if metadata[0].Identity() != records[0].Identity() {
		t.Fatalf("metadata identity %#v != record identity %#v", metadata[0].Identity(), records[0].Identity())
	}
	return metadata[0], records[0]
}

func assertSandboxCorrelation(t *testing.T, body map[string]any, identity SandboxIdentity) {
	t.Helper()
	want := map[string]any{
		"defenseclaw.sandbox.id":             identity.ID,
		"defenseclaw.sandbox.name":           identity.Name,
		"defenseclaw.sandbox.runtime":        identity.Runtime,
		"defenseclaw.sandbox.driver":         identity.Driver,
		"defenseclaw.sandbox.image.digest":   identity.ImageDigest,
		"defenseclaw.sandbox.policy.version": int64(identity.PolicyVersion),
		"defenseclaw.sandbox.profile":        identity.Profile,
		"defenseclaw.sandbox.pack":           identity.Pack,
		"defenseclaw.sandbox.phase":          string(identity.Phase),
		"defenseclaw.sandbox.workdir.mode":   identity.WorkdirMode,
	}
	for key, value := range want {
		if body[key] != value {
			t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], value, body)
		}
	}
}

// validatedSandboxMetrics holds the record IDs of metric points already
// checked against the runtime contract; tests rescan the growing point list
// after every event, and each point needs checking once.
var validatedSandboxMetrics sync.Map

func sandboxMetrics(t *testing.T, runtime *testRuntimeV8Emitter, instrument string) []observability.Record {
	t.Helper()
	var matched []observability.Record
	for _, record := range runtime.metricSnapshot() {
		if _, seen := validatedSandboxMetrics.LoadOrStore(record.RecordID(), struct{}{}); !seen {
			assertRecordMatchesRuntimeContract(t, record)
		}
		if record.EventName() == observability.EventName(instrument) {
			matched = append(matched, record)
		}
	}
	return matched
}

func metricAttributes(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("metric instrument data is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, _ := data["attributes"].(map[string]any)
	return attributes
}

// sandboxBody returns the log body with JSON numbers as int64 or float64 so
// table expectations can compare them directly.
func sandboxBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	return sandboxNumbers(securityActionBody(t, record))
}

func sandboxNumbers(object map[string]any) map[string]any {
	for key, value := range object {
		if number, ok := value.(json.Number); ok {
			if integer, err := number.Int64(); err == nil {
				object[key] = integer
			} else if floating, err := number.Float64(); err == nil {
				object[key] = floating
			}
		}
	}
	return object
}

func sandboxMetricValue(t *testing.T, record observability.Record) int64 {
	t.Helper()
	number, ok := metricValue(t, record).(json.Number)
	if !ok {
		t.Fatalf("metric value %#v is not a number", metricValue(t, record))
	}
	value, err := number.Int64()
	if err != nil {
		t.Fatalf("metric value %s is not an integer", number)
	}
	return value
}

func TestSandboxLifecycleEmitsTransitionsAndActiveGauge(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	identity := testSandboxIdentity()
	exitCode := int32(0)
	steps := []struct {
		phase    SandboxPhase
		trigger  SandboxLifecycleTrigger
		exitCode *int32
		outcome  observability.Outcome
		active   int64
		previous string
	}{
		{phase: SandboxPhaseCreating, trigger: SandboxTriggerCreate, outcome: observability.OutcomeAttempted},
		{phase: SandboxPhaseProvisioning, trigger: SandboxTriggerWatch, outcome: observability.OutcomeAttempted, active: 1, previous: "creating"},
		{phase: SandboxPhaseReady, trigger: SandboxTriggerWatch, outcome: observability.OutcomeCompleted, active: 1, previous: "provisioning"},
		{phase: SandboxPhaseStopping, trigger: SandboxTriggerStop, outcome: observability.OutcomeAttempted, active: 1, previous: "ready"},
		{phase: SandboxPhaseCompleted, trigger: SandboxTriggerWatch, exitCode: &exitCode, outcome: observability.OutcomeCompleted, previous: "stopping"},
		{phase: SandboxPhaseDeleted, trigger: SandboxTriggerDelete, outcome: observability.OutcomeCompleted, previous: "completed"},
	}
	for index, step := range steps {
		identity.Phase = step.phase
		if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{
			Sandbox: identity, Trigger: step.trigger, ExitCode: step.exitCode,
		}); err != nil {
			t.Fatalf("step %d (%s): %v", index, step.phase, err)
		}
		_, records := runtime.snapshot()
		record := records[len(records)-1]
		assertRecordMatchesRuntimeContract(t, record)
		if record.EventName() != observability.EventName(observability.TelemetryEventSandboxLifecycle) ||
			record.Bucket() != observability.BucketAgentLifecycle || record.Outcome() != step.outcome ||
			record.Mandatory() || record.Connector() != identity.Connector ||
			record.Action() != string(ActionSandboxLifecycle) {
			t.Fatalf("step %d record identity=%#v outcome=%q mandatory=%v connector=%q action=%q",
				index, record.Identity(), record.Outcome(), record.Mandatory(), record.Connector(), record.Action())
		}
		body := sandboxBody(t, record)
		assertSandboxCorrelation(t, body, identity)
		if got, _ := body["defenseclaw.sandbox.phase.previous"].(string); got != step.previous {
			t.Fatalf("step %d previous phase=%q want %q", index, got, step.previous)
		}
		if body["defenseclaw.sandbox.lifecycle.trigger"] != string(step.trigger) {
			t.Fatalf("step %d trigger=%#v", index, body["defenseclaw.sandbox.lifecycle.trigger"])
		}
		_, hasExit := body["defenseclaw.sandbox.exit_code"]
		if hasExit != (step.exitCode != nil) {
			t.Fatalf("step %d exit code presence=%v body=%#v", index, hasExit, body)
		}
		active := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive)
		last := active[len(active)-1]
		if sandboxMetricValue(t, last) != step.active ||
			metricAttributes(t, last)["defenseclaw.connector.source"] != identity.Connector {
			t.Fatalf("step %d active gauge=%d attrs=%#v want %d", index, sandboxMetricValue(t, last), metricAttributes(t, last), step.active)
		}
	}
	transitions := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxTransitions)
	if len(transitions) != len(steps) {
		t.Fatalf("transition metrics=%d want %d", len(transitions), len(steps))
	}
	first := metricAttributes(t, transitions[0])
	if _, hasFrom := first["defenseclaw.sandbox.phase.from"]; hasFrom || first["defenseclaw.sandbox.phase.to"] != "creating" {
		t.Fatalf("first transition attributes=%#v", first)
	}
	ready := metricAttributes(t, transitions[2])
	if ready["defenseclaw.sandbox.phase.from"] != "provisioning" || ready["defenseclaw.sandbox.phase.to"] != "ready" ||
		ready["defenseclaw.connector.source"] != "claudecode" {
		t.Fatalf("ready transition attributes=%#v", ready)
	}
	for _, record := range transitions {
		for key := range metricAttributes(t, record) {
			if strings.HasPrefix(key, "defenseclaw.sandbox.") && !strings.HasPrefix(key, "defenseclaw.sandbox.phase.") {
				t.Fatalf("sandbox identity %q leaked into a metric label", key)
			}
		}
	}
	if len(recorder.phases) != 0 {
		t.Fatalf("deleted sandbox is still tracked: %#v", recorder.phases)
	}
}

func TestSandboxLifecycleConditionOnlyUpdateSkipsTransitionMetric(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	identity := testSandboxIdentity()
	for index, condition := range []*SandboxCondition{
		{Type: "Ready", Status: "True", Reason: "SupervisorReady"},
		{
			Type: "ConfigurationReady", Status: "False", Reason: "not a token!",
			Message: strings.Repeat("é", 1000),
		},
	} {
		previous := SandboxPhase("")
		if index == 0 {
			previous = SandboxPhaseStarting
		}
		if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{
			Sandbox: identity, PreviousPhase: previous, Trigger: SandboxTriggerWatch, Condition: condition,
		}); err != nil {
			t.Fatalf("RecordSandboxLifecycle: %v", err)
		}
	}
	_, records := runtime.snapshot()
	if len(records) != 2 {
		t.Fatalf("records=%d want 2", len(records))
	}
	body := securityActionBody(t, records[1])
	if body["defenseclaw.sandbox.phase.previous"] != "ready" || body["defenseclaw.sandbox.condition.type"] != "ConfigurationReady" ||
		body["defenseclaw.sandbox.condition.status"] != "False" {
		t.Fatalf("condition body=%#v", body)
	}
	if _, kept := body["defenseclaw.sandbox.condition.reason"]; kept {
		t.Fatalf("malformed gateway reason token was kept: %#v", body)
	}
	message, _ := body["defenseclaw.sandbox.condition.message"].(string)
	if len(message) > maxSandboxConditionMessage || !utf8.ValidString(message) || message == "" {
		t.Fatalf("condition message was not bounded on a code point: %d bytes", len(message))
	}
	if transitions := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxTransitions); len(transitions) != 1 {
		t.Fatalf("a phase-preserving update emitted %d transition metrics, want 1", len(transitions))
	}
}

func TestSandboxLifecycleActiveGaugeIsPerConnector(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	record := func(name, connector string, phase SandboxPhase) {
		t.Helper()
		identity := SandboxIdentity{Name: name, Connector: connector, Phase: phase}
		if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity}); err != nil {
			t.Fatalf("RecordSandboxLifecycle(%s): %v", name, err)
		}
	}
	lastGauge := func() map[string]int64 {
		values := map[string]int64{}
		for _, metric := range sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive) {
			connector, _ := metricAttributes(t, metric)["defenseclaw.connector.source"].(string)
			values[connector] = sandboxMetricValue(t, metric)
		}
		return values
	}
	record("dc-claudecode-a-0001", "claudecode", SandboxPhaseReady)
	record("dc-claudecode-b-0002", "claudecode", SandboxPhaseStarting)
	record("dc-codex-a-0003", "codex", SandboxPhaseReady)
	if got := lastGauge(); got["claudecode"] != 2 || got["codex"] != 1 {
		t.Fatalf("active gauges=%#v", got)
	}
	record("dc-claudecode-a-0001", "claudecode", SandboxPhaseError)
	record("dc-claudecode-b-0002", "codex", SandboxPhaseReady)
	if got := lastGauge(); got["claudecode"] != 0 || got["codex"] != 2 {
		t.Fatalf("active gauges after error and connector change=%#v", got)
	}
}

// TestSandboxLifecycleConcurrentGaugeIsOrdered races lifecycle events from
// many sandboxes on two connectors. A gauge keeps the last value written, so
// the points must reach the runtime in the order the phases changed: each
// connector's gauge moves by at most one per point and ends at the true count.
func TestSandboxLifecycleConcurrentGaugeIsOrdered(t *testing.T) {
	harness := newSandboxHarness(t)
	const rounds, sandboxes = 4, 24
	for round := 0; round < rounds; round++ {
		runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
		want := map[string]int64{}
		var group sync.WaitGroup
		errs := make(chan error, sandboxes*4)
		events := 0
		for index := 0; index < sandboxes; index++ {
			connector := "codex"
			if index%3 == 0 {
				connector = "claudecode"
			}
			phases := []SandboxPhase{SandboxPhaseCreating, SandboxPhaseProvisioning, SandboxPhaseReady}
			if index%4 == 0 {
				phases = append(phases, SandboxPhaseStopped)
			} else {
				want[connector]++
			}
			events += len(phases)
			group.Add(1)
			go func(identity SandboxIdentity, phases []SandboxPhase) {
				defer group.Done()
				for _, phase := range phases {
					identity.Phase = phase
					errs <- recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity})
				}
			}(SandboxIdentity{Name: fmt.Sprintf("dc-%s-repo-%04d", connector, index), Connector: connector}, phases)
		}
		group.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if _, records := runtime.snapshot(); len(records) != events {
			t.Fatalf("round %d records=%d want %d", round, len(records), events)
		}
		if transitions := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxTransitions); len(transitions) != events {
			t.Fatalf("round %d transition metrics=%d want %d", round, len(transitions), events)
		}
		last := map[string]int64{}
		for _, metric := range sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive) {
			connector, _ := metricAttributes(t, metric)["defenseclaw.connector.source"].(string)
			value := sandboxMetricValue(t, metric)
			if step := value - last[connector]; step > 1 || step < -1 {
				t.Fatalf("round %d %s gauge jumped %d -> %d: points reached the runtime out of order",
					round, connector, last[connector], value)
			}
			last[connector] = value
		}
		for connector, active := range want {
			if last[connector] != active {
				t.Fatalf("round %d final %s gauge=%d want %d (all=%#v)", round, connector, last[connector], active, last)
			}
		}
	}
}

// rejectingEveryRuntimeV8Emitter rejects every nth log emission before the
// record is built, like a runtime that is reloading. It is safe for
// concurrent use.
type rejectingEveryRuntimeV8Emitter struct {
	*testRuntimeV8Emitter
	every    int64
	calls    atomic.Int64
	rejected atomic.Int64
}

func (emitter *rejectingEveryRuntimeV8Emitter) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	if emitter.calls.Add(1)%emitter.every == 0 {
		emitter.rejected.Add(1)
		return RuntimeV8EmitOutcome{}, fmt.Errorf("runtime reloading")
	}
	return emitter.testRuntimeV8Emitter.EmitRuntimeV8(ctx, metadata, builder)
}

// TestSandboxRecorderConcurrentRetriesAfterRejectedEmits races lifecycle,
// egress, and workspace producers for many sandboxes against a runtime that
// rejects every third emission; each caller retries a rejected event as is.
// No retried event may be lost, skipped, or counted twice: every record fits
// the runtime contract, each sandbox's previous phases chain in order, every
// metric counts exactly the accepted events, and each connector's active
// gauge moves one step at a time and ends at its true count.
func TestSandboxRecorderConcurrentRetriesAfterRejectedEmits(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime := &rejectingEveryRuntimeV8Emitter{
		testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, harness.logger.store, router.AdmissionOrdinary), every: 3,
	}
	harness.logger.SetRuntimeV8Emitter(runtime)
	recorder := NewSandboxRecorder(harness.logger)
	// Rejections follow the global call count, so under contention one caller
	// can draw several in a row; the bound only stops a broken retry path.
	retry := func(record func() error) error {
		var err error
		for attempt := 0; attempt < 64; attempt++ {
			if err = record(); err == nil {
				return nil
			}
		}
		return err
	}
	const sandboxes = 18
	connectors := []string{"claudecode", "codex", "opencode"}
	want := map[string]int64{}
	lifecycleEvents := 0
	var group sync.WaitGroup
	errs := make(chan error, sandboxes*8)
	for index := 0; index < sandboxes; index++ {
		connector := connectors[index%len(connectors)]
		phases := []SandboxPhase{SandboxPhaseCreating, SandboxPhaseProvisioning, SandboxPhaseReady}
		if index%4 == 0 {
			phases = append(phases, SandboxPhaseStopping, SandboxPhaseStopped)
		} else {
			want[connector]++
		}
		lifecycleEvents += len(phases)
		group.Add(1)
		go func(identity SandboxIdentity, phases []SandboxPhase) {
			defer group.Done()
			for _, phase := range phases {
				identity.Phase = phase
				errs <- retry(func() error {
					return recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity})
				})
				if phase != SandboxPhaseReady {
					continue
				}
				errs <- retry(func() error {
					return recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
						Sandbox: identity, Source: SandboxEgressSourceProxy, Host: "registry.npmjs.org", Port: 443,
					})
				})
				errs <- retry(func() error {
					return recorder.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
						Sandbox: identity, Operation: SandboxWorkspaceSnapshot, SnapshotKind: SandboxSnapshotGit,
					})
				})
			}
		}(SandboxIdentity{Name: fmt.Sprintf("dc-%s-repo-%04d", connector, index), Connector: connector}, phases)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a retried event was never accepted: %v", err)
		}
	}
	if runtime.rejected.Load() == 0 {
		t.Fatal("the runtime rejected nothing; the retry paths were not exercised")
	}
	_, records := runtime.snapshot()
	counts := map[string]int{}
	previous := map[string]string{}
	for _, record := range records {
		assertRecordMatchesRuntimeContract(t, record)
		counts[string(record.EventName())]++
		if record.EventName() != observability.EventName(observability.TelemetryEventSandboxLifecycle) {
			continue
		}
		body := sandboxBody(t, record)
		name, _ := body["defenseclaw.sandbox.name"].(string)
		got, _ := body["defenseclaw.sandbox.phase.previous"].(string)
		if got != previous[name] {
			t.Fatalf("%s previous phase=%q want %q: a rejected event moved the tracked phase", name, got, previous[name])
		}
		previous[name], _ = body["defenseclaw.sandbox.phase"].(string)
	}
	for eventName, want := range map[string]int{
		observability.TelemetryEventSandboxLifecycle: lifecycleEvents,
		observability.TelemetryEventEgressAllowed:    sandboxes,
		observability.TelemetryEventSandboxWorkspace: sandboxes,
	} {
		if counts[eventName] != want {
			t.Fatalf("%s records=%d want %d (all=%#v)", eventName, counts[eventName], want, counts)
		}
	}
	if transitions := sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawSandboxTransitions); len(transitions) != lifecycleEvents {
		t.Fatalf("transition metrics=%d want %d", len(transitions), lifecycleEvents)
	}
	if egress := sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawEgressEvents); len(egress) != sandboxes {
		t.Fatalf("egress metrics=%d want %d", len(egress), sandboxes)
	}
	last := map[string]int64{}
	for _, metric := range sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawSandboxActive) {
		connector, _ := metricAttributes(t, metric)["defenseclaw.connector.source"].(string)
		value := sandboxMetricValue(t, metric)
		if step := value - last[connector]; step > 1 || step < -1 {
			t.Fatalf("%s gauge jumped %d -> %d", connector, last[connector], value)
		}
		last[connector] = value
	}
	for _, connector := range connectors {
		if last[connector] != want[connector] {
			t.Fatalf("final %s gauge=%d want %d (all=%#v)", connector, last[connector], want[connector], last)
		}
	}
}

// flakyRuntimeV8Emitter fails the next log emission on demand, standing in for
// a runtime detached during a reload or a rejected emission.
type flakyRuntimeV8Emitter struct {
	*testRuntimeV8Emitter
	failNext bool
}

func (emitter *flakyRuntimeV8Emitter) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	if emitter.failNext {
		emitter.failNext = false
		return RuntimeV8EmitOutcome{}, fmt.Errorf("runtime reloading")
	}
	return emitter.testRuntimeV8Emitter.EmitRuntimeV8(ctx, metadata, builder)
}

// TestSandboxLifecycleTrackingEdges shares one store across the tracked-phase
// edge cases; each case binds a fresh runtime and recorder.
func TestSandboxLifecycleTrackingEdges(t *testing.T) {
	harness := newSandboxHarness(t)
	t.Run("failed emit does not advance the phase", func(t *testing.T) {
		testSandboxLifecycleFailedEmitDoesNotAdvancePhase(t, harness)
	})
	t.Run("unknown previous counts only creation", func(t *testing.T) {
		testSandboxLifecycleUnknownPreviousCountsOnlyCreation(t, harness)
	})
	t.Run("metrics use the identity connector", func(t *testing.T) {
		testSandboxLifecycleMetricsUseIdentityConnector(t, harness)
	})
}

func testSandboxLifecycleFailedEmitDoesNotAdvancePhase(t *testing.T, harness *sandboxHarness) {
	runtime := &flakyRuntimeV8Emitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, harness.logger.store, router.AdmissionOrdinary)}
	harness.logger.SetRuntimeV8Emitter(runtime)
	recorder := NewSandboxRecorder(harness.logger)
	identity := testSandboxIdentity()
	record := func(phase SandboxPhase) error {
		identity.Phase = phase
		return recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity})
	}
	if err := record(SandboxPhaseCreating); err != nil {
		t.Fatalf("creating: %v", err)
	}
	runtime.failNext = true
	if err := record(SandboxPhaseProvisioning); err == nil {
		t.Fatal("a failed emission reported success")
	}
	if tracked := recorder.phases[identity.Name]; tracked.phase != SandboxPhaseCreating {
		t.Fatalf("failed emission advanced the tracked phase to %q", tracked.phase)
	}
	if active := sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawSandboxActive); len(active) != 1 {
		t.Fatalf("failed emission published a gauge point: %d points", len(active))
	}
	if err := record(SandboxPhaseProvisioning); err != nil {
		t.Fatalf("retried provisioning: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != 2 {
		t.Fatalf("records=%d want 2", len(records))
	}
	if previous := securityActionBody(t, records[1])["defenseclaw.sandbox.phase.previous"]; previous != "creating" {
		t.Fatalf("retried record previous phase=%#v want creating", previous)
	}
	transitions := sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawSandboxTransitions)
	if len(transitions) != 2 || metricAttributes(t, transitions[1])["defenseclaw.sandbox.phase.from"] != "creating" {
		t.Fatalf("transitions after retry=%d", len(transitions))
	}
	active := sandboxMetrics(t, runtime.testRuntimeV8Emitter, observability.TelemetryInstrumentDefenseClawSandboxActive)
	if last := active[len(active)-1]; sandboxMetricValue(t, last) != 1 {
		t.Fatalf("active gauge after retry=%d want 1", sandboxMetricValue(t, last))
	}
}

// testSandboxLifecycleUnknownPreviousCountsOnlyCreation covers a restarted
// daemon reconciling a running sandbox and a repeated deleted event: neither
// knows the previous phase, and neither is a new sandbox.
func testSandboxLifecycleUnknownPreviousCountsOnlyCreation(t *testing.T, harness *sandboxHarness) {
	runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
	identity := testSandboxIdentity()
	for _, step := range []struct {
		phase       SandboxPhase
		previous    SandboxPhase
		transitions int
		active      int64
	}{
		{phase: SandboxPhaseReady, transitions: 0, active: 1},
		{phase: SandboxPhaseStopping, transitions: 1, active: 1},
		{phase: SandboxPhaseDeleted, transitions: 2},
		{phase: SandboxPhaseDeleted, transitions: 2},
		{phase: SandboxPhaseStopped, previous: SandboxPhaseStopping, transitions: 3},
	} {
		identity.Phase = step.phase
		if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{
			Sandbox: identity, PreviousPhase: step.previous, Trigger: SandboxTriggerReconcile,
		}); err != nil {
			t.Fatalf("%s: %v", step.phase, err)
		}
		transitions := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxTransitions)
		active := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive)
		if len(transitions) != step.transitions || sandboxMetricValue(t, active[len(active)-1]) != step.active {
			t.Fatalf("%s: transitions=%d want %d, active=%d want %d", step.phase, len(transitions), step.transitions,
				sandboxMetricValue(t, active[len(active)-1]), step.active)
		}
	}
	_, records := runtime.snapshot()
	if _, present := securityActionBody(t, records[3])["defenseclaw.sandbox.phase.previous"]; present {
		t.Fatalf("a repeated deleted event claimed a previous phase")
	}
}

// testSandboxLifecycleMetricsUseIdentityConnector keeps the transition counter
// and the active gauge on the same connector key even when the context
// envelope names a different connector for the record.
func testSandboxLifecycleMetricsUseIdentityConnector(t *testing.T, harness *sandboxHarness) {
	runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
	ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{Connector: "codex"})
	if err := recorder.RecordSandboxLifecycle(ctx, SandboxLifecycleEvent{
		Sandbox: SandboxIdentity{Name: "dc-unbound-repo-0001", Phase: SandboxPhaseCreating},
	}); err != nil {
		t.Fatalf("RecordSandboxLifecycle: %v", err)
	}
	if _, record := onlySandboxRecord(t, runtime); record.Connector() != "codex" {
		t.Fatalf("record connector=%q want the envelope's codex", record.Connector())
	}
	for _, instrument := range []string{
		observability.TelemetryInstrumentDefenseClawSandboxTransitions,
		observability.TelemetryInstrumentDefenseClawSandboxActive,
	} {
		metrics := sandboxMetrics(t, runtime, instrument)
		if len(metrics) != 1 {
			t.Fatalf("%s points=%d want 1", instrument, len(metrics))
		}
		if connector, present := metricAttributes(t, metrics[0])["defenseclaw.connector.source"]; present {
			t.Fatalf("%s took connector %#v from the envelope, not the sandbox identity", instrument, connector)
		}
	}
}

func TestSandboxEgressReusesEgressFamiliesAndMetric(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, test := range []struct {
		name      string
		input     SandboxEgressEvent
		eventName string
		outcome   observability.Outcome
		severity  observability.Severity
		body      map[string]any
		absent    []string
	}{
		{
			name: "proxy allowed",
			input: SandboxEgressEvent{
				Source: SandboxEgressSourceProxy, Host: "Registry.NPMJS.org.", Port: 443, Scheme: "HTTPS",
				Path: "/react?token=secret#frag", ResolvedIP: "104.16.0.35",
				DecisionCode: "SANDBOX_EGRESS_DEFAULT_ALLOW", PolicyOutcome: "allow-by-default",
			},
			eventName: observability.TelemetryEventEgressAllowed, outcome: observability.OutcomeAllowed,
			severity: observability.SeverityInfo,
			body: map[string]any{
				"defenseclaw.network.target_ref": "registry.npmjs.org", "server.address": "registry.npmjs.org",
				"server.port": int64(443), "url.scheme": "https", "defenseclaw.network.target_path": "/react",
				"defenseclaw.network.source": "dc-egress-proxy", "defenseclaw.network.decision": "allow",
				"defenseclaw.network.blocked": false, "defenseclaw.network.resolved_ip": "104.16.0.35",
				"defenseclaw.network.decision_code": "SANDBOX_EGRESS_DEFAULT_ALLOW",
			},
		},
		{
			name: "openshell blocked loopback",
			input: SandboxEgressEvent{
				Source: SandboxEgressSourceOpenShell, Host: "[::1]", Port: 18970, Blocked: true,
				DecisionCode: "SANDBOX_EGRESS_PRIVATE_NETWORK", Reason: "loopback destinations are never reachable",
				Path: "relative-not-kept",
			},
			eventName: observability.TelemetryEventEgressBlocked, outcome: observability.OutcomeBlocked,
			severity: observability.SeverityMedium,
			body: map[string]any{
				"defenseclaw.network.target_ref": "0:0:0:0:0:0:0:1", "defenseclaw.network.source": "openshell",
				"defenseclaw.network.decision": "block", "defenseclaw.network.blocked": true,
				"defenseclaw.network.reason": "loopback destinations are never reachable",
			},
			absent: []string{"defenseclaw.network.target_path", "url.scheme", "defenseclaw.network.resolved_ip"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			identity := testSandboxIdentity()
			test.input.Sandbox = identity
			ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{
				SessionID: "session-sandbox-1", AgentID: "agent-sandbox-1", RunID: "run-sandbox-1",
			})
			if err := recorder.RecordSandboxEgress(ctx, test.input); err != nil {
				t.Fatalf("RecordSandboxEgress: %v", err)
			}
			metadata, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			severity, _ := record.Severity()
			if record.EventName() != observability.EventName(test.eventName) || record.Outcome() != test.outcome ||
				record.Mandatory() != test.input.Blocked || metadata.Source() != observability.SourceGateway ||
				metadata.Action() != observability.ProducerKey(ActionSandboxEgress) ||
				severity != test.severity || record.Bucket() != observability.BucketNetworkEgress ||
				record.Correlation().SessionID != "session-sandbox-1" {
				t.Fatalf("record identity=%#v outcome=%q mandatory=%v severity=%q correlation=%#v",
					record.Identity(), record.Outcome(), record.Mandatory(), severity, record.Correlation())
			}
			body := sandboxBody(t, record)
			assertSandboxCorrelation(t, body, identity)
			for key, want := range test.body {
				if body[key] != want {
					t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], want, body)
				}
			}
			for _, key := range test.absent {
				if _, present := body[key]; present {
					t.Fatalf("body unexpectedly carries %q: %#v", key, body)
				}
			}
			if body["gen_ai.conversation.id"] != "session-sandbox-1" || body["gen_ai.agent.id"] != "agent-sandbox-1" {
				t.Fatalf("agent correlation missing: %#v", body)
			}
			encoded, _ := json.Marshal(body)
			if bytes.Contains(encoded, []byte("token=secret")) || bytes.Contains(encoded, []byte("frag")) {
				t.Fatalf("egress body kept the query or fragment: %s", encoded)
			}
			events := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawEgressEvents)
			if len(events) != 1 {
				t.Fatalf("egress metrics=%d want 1", len(events))
			}
			attributes := metricAttributes(t, events[0])
			if attributes["defenseclaw.metric.source"] != string(test.input.Source) ||
				attributes["defenseclaw.metric.decision"] != test.body["defenseclaw.network.decision"] {
				t.Fatalf("egress metric attributes=%#v", attributes)
			}
			if audits := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawAuditEventsTotal); len(audits) != 1 ||
				metricAttributes(t, audits[0])["defenseclaw.metric.action"] != string(ActionSandboxEgress) {
				t.Fatalf("audit event metric missing or mislabeled")
			}
		})
	}
}

func TestSandboxEgressAdmissionPaths(t *testing.T) {
	t.Run("blocked floor is content free", func(t *testing.T) {
		const canary = "sandbox-egress-canary-3e1f"
		logger, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionFloor)
		if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
			Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: "webhook.site", Blocked: true,
			Reason: canary, PolicyOutcome: canary,
		}); err != nil {
			t.Fatalf("RecordSandboxEgress: %v", err)
		}
		_, record := onlySandboxRecord(t, runtime)
		if !record.IsFloorOnly() || !record.Mandatory() {
			t.Fatalf("blocked egress under floor admission: floor=%v mandatory=%v", record.IsFloorOnly(), record.Mandatory())
		}
		encoded, err := record.MarshalJSON()
		if err != nil || bytes.Contains(encoded, []byte(canary)) || bytes.Contains(encoded, []byte("webhook.site")) {
			t.Fatalf("floor record leaked content: err=%v record=%s", err, encoded)
		}
		rows, err := logger.store.ListEvents(10)
		if err != nil || len(rows) != 1 {
			t.Fatalf("floor rows=%d err=%v", len(rows), err)
		}
		assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
	})
	// The remaining cases never persist a row, so they share one store; the
	// drop case still proves it stays empty.
	harness := newSandboxHarness(t)
	t.Run("allowed floor has no path", func(t *testing.T) {
		runtime, recorder := harness.bind(t, router.AdmissionFloor)
		if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
			Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: "example.org",
		}); err == nil {
			t.Fatal("a non-mandatory egress accepted a mandatory-floor admission")
		}
		if _, records := runtime.snapshot(); len(records) != 0 {
			t.Fatalf("records=%d want 0", len(records))
		}
	})
	t.Run("collection drop still counts the decision", func(t *testing.T) {
		runtime, recorder := harness.bind(t, router.AdmissionDrop)
		if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
			Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: "example.org",
		}); err != nil {
			t.Fatalf("RecordSandboxEgress: %v", err)
		}
		rows, err := harness.logger.store.ListEvents(10)
		if _, records := runtime.snapshot(); err != nil || len(rows) != 0 || len(records) != 0 {
			t.Fatalf("dropped egress persisted rows=%d records=%d err=%v", len(rows), len(records), err)
		}
		if events := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawEgressEvents); len(events) != 1 {
			t.Fatalf("egress metrics=%d want 1", len(events))
		}
		if audits := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawAuditEventsTotal); len(audits) != 0 {
			t.Fatalf("a dropped occurrence was counted as a persisted audit event")
		}
	})
	t.Run("blocked drop is rejected", func(t *testing.T) {
		_, recorder := harness.bind(t, router.AdmissionDrop)
		if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
			Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceOpenShell, Host: "pastebin.com", Blocked: true,
		}); err == nil {
			t.Fatal("a mandatory blocked egress accepted a drop admission")
		}
	})
}

func TestSandboxApprovalFamilies(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, test := range []struct {
		name      string
		input     SandboxApprovalEvent
		eventName string
		outcome   observability.Outcome
		mandatory bool
		body      map[string]any
	}{
		{
			name: "network rule requested",
			input: SandboxApprovalEvent{
				Stage: SandboxApprovalRequested, ApprovalID: "draft-7", Kind: SandboxApprovalNetworkRule,
				Host: "10.0.0.8", Port: 5432, Risky: true, Reason: "private network reach",
			},
			eventName: observability.TelemetryEventApprovalRequested, outcome: observability.OutcomeAttempted,
			body: map[string]any{
				"defenseclaw.approval.id": "draft-7", "defenseclaw.sandbox.approval.kind": "network_rule",
				"server.address": "10.0.0.8", "server.port": int64(5432), "defenseclaw.approval.dangerous": true,
				"defenseclaw.guardrail.reason": "private network reach",
			},
		},
		{
			name: "host port approved always",
			input: SandboxApprovalEvent{
				Stage: SandboxApprovalResolved, ApprovalID: "host-port-5432", Kind: SandboxApprovalHostPort,
				Port: 5432, Result: SandboxApprovalApproved, ActorType: SandboxApprovalByOperator,
				Scope: SandboxApprovalScopeAlways,
			},
			eventName: observability.TelemetryEventApprovalResolved, outcome: observability.OutcomeApproved, mandatory: true,
			body: map[string]any{
				"defenseclaw.approval.result": "approved", "defenseclaw.approval.actor_type": "operator",
				"defenseclaw.sandbox.approval.scope": "always", "defenseclaw.sandbox.approval.kind": "host_port",
				"defenseclaw.approval.dangerous": false,
			},
		},
		{
			name: "triage expiry",
			input: SandboxApprovalEvent{
				Stage: SandboxApprovalResolved, ApprovalID: "draft-9", Kind: SandboxApprovalNetworkRule,
				Result: SandboxApprovalExpired, ActorType: SandboxApprovalByAutomatic,
			},
			eventName: observability.TelemetryEventApprovalResolved, outcome: observability.OutcomeTimedOut, mandatory: true,
			body: map[string]any{"defenseclaw.approval.result": "expired", "defenseclaw.approval.actor_type": "automatic"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			test.input.Sandbox = testSandboxIdentity()
			if err := recorder.RecordSandboxApproval(context.Background(), test.input); err != nil {
				t.Fatalf("RecordSandboxApproval: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if record.EventName() != observability.EventName(test.eventName) || record.Outcome() != test.outcome ||
				record.Mandatory() != test.mandatory || record.Bucket() != observability.BucketComplianceActivity {
				t.Fatalf("record identity=%#v outcome=%q mandatory=%v", record.Identity(), record.Outcome(), record.Mandatory())
			}
			body := sandboxBody(t, record)
			assertSandboxCorrelation(t, body, test.input.Sandbox)
			for key, want := range test.body {
				if body[key] != want {
					t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], want, body)
				}
			}
		})
	}
}

// TestSandboxRecorderEmitsTrimmedIdentifiers covers identifiers the producers
// validate after trimming: the record carries the trimmed value, so padding
// can neither fail the registered pattern nor cost a mandatory record.
func TestSandboxRecorderEmitsTrimmedIdentifiers(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, test := range []struct {
		name      string
		record    func(*SandboxRecorder) error
		mandatory bool
		field     string
		want      string
	}{
		{
			name: "requested approval id",
			record: func(r *SandboxRecorder) error {
				return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{
					Sandbox: testSandboxIdentity(), Stage: SandboxApprovalRequested, ApprovalID: " draft-7",
					Kind: SandboxApprovalNetworkRule,
				})
			},
			field: "defenseclaw.approval.id", want: "draft-7",
		},
		{
			name: "resolved approval id",
			record: func(r *SandboxRecorder) error {
				return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{
					Sandbox: testSandboxIdentity(), Stage: SandboxApprovalResolved, ApprovalID: "draft-7 \t",
					Kind: SandboxApprovalNetworkRule, Result: SandboxApprovalApproved, ActorType: SandboxApprovalByOperator,
				})
			},
			mandatory: true, field: "defenseclaw.approval.id", want: "draft-7",
		},
		{
			name: "workspace initiator",
			record: func(r *SandboxRecorder) error {
				return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
					Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceSnapshot, Initiator: "operator ",
				})
			},
			field: "defenseclaw.enforcement.initiator", want: "operator",
		},
		{
			name: "egress decision code",
			record: func(r *SandboxRecorder) error {
				return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
					Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: "pastebin.com", Blocked: true,
					DecisionCode: " SANDBOX_EGRESS_BLOCKLIST\n",
				})
			},
			mandatory: true, field: "defenseclaw.network.decision_code", want: "SANDBOX_EGRESS_BLOCKLIST",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := test.record(recorder); err != nil {
				t.Fatalf("a padded identifier cost the record: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if record.Mandatory() != test.mandatory {
				t.Fatalf("mandatory=%v want %v", record.Mandatory(), test.mandatory)
			}
			if got := sandboxBody(t, record)[test.field]; got != test.want {
				t.Fatalf("%s=%#v want %q", test.field, got, test.want)
			}
		})
	}
}

func TestSandboxPolicyUpdateIsMandatoryControlPlaneRecord(t *testing.T) {
	harness := newSandboxHarness(t)
	runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
	identity := testSandboxIdentity()
	identity.PolicyVersion = 4
	hash := strings.Repeat("0f", 32)
	if err := recorder.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{
		Sandbox: identity, Operation: SandboxEgressUnblock, PreviousVersion: 3, PolicyHash: hash,
		Actor: "cli:alice", Origin: "cli", Target: "webhook.site", Reason: "operator_unblock", ChangeCount: 1,
	}); err != nil {
		t.Fatalf("RecordSandboxPolicy: %v", err)
	}
	_, record := onlySandboxRecord(t, runtime)
	assertRecordMatchesRuntimeContract(t, record)
	if record.EventName() != observability.EventName(observability.TelemetryEventPolicyUpdated) ||
		!record.Mandatory() || record.Outcome() != observability.OutcomeApplied {
		t.Fatalf("policy record identity=%#v mandatory=%v outcome=%q", record.Identity(), record.Mandatory(), record.Outcome())
	}
	body := sandboxBody(t, record)
	assertSandboxCorrelation(t, body, identity)
	for key, want := range map[string]any{
		"defenseclaw.admin.operation": "sandbox.egress.unblock", "defenseclaw.admin.principal_ref": "cli:alice",
		"defenseclaw.admin.actor_ref": "cli:alice", "defenseclaw.admin.origin": "cli",
		"defenseclaw.admin.target_ref": "webhook.site", "defenseclaw.admin.revision": "v4",
		"defenseclaw.admin.current_revision": "v3", "defenseclaw.admin.after_summary": "sha256:" + hash,
		"defenseclaw.admin.reason": "operator_unblock", "defenseclaw.admin.change_count": int64(1),
	} {
		if body[key] != want {
			t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], want, body)
		}
	}

	runtime, recorder = harness.bind(t, router.AdmissionFloor)
	if err := recorder.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{
		Sandbox: identity, Operation: SandboxPolicyApply, NoChange: true,
	}); err != nil {
		t.Fatalf("RecordSandboxPolicy floor: %v", err)
	}
	if _, floor := onlySandboxRecord(t, runtime); !floor.IsFloorOnly() || floor.Outcome() != observability.OutcomeNoChange {
		t.Fatalf("policy floor=%v outcome=%q", floor.IsFloorOnly(), floor.Outcome())
	}
}

// TestSandboxPolicyTargetRecordsEgressPatterns pins the target_ref of egress
// rule changes. The decider accepts host patterns that cannot start an
// identifier, and a mandatory record that opens *.pastebin.com or ::/0 must
// still say so: those two forms are rewritten, never dropped.
func TestSandboxPolicyTargetRecordsEgressPatterns(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, test := range []struct {
		name      string
		operation SandboxPolicyOperation
		target    string
		want      string
	}{
		{"exact host", SandboxEgressUnblock, "webhook.site", "webhook.site"},
		{"wildcard host", SandboxEgressUnblock, "*.pastebin.com", "suffix:pastebin.com"},
		{"padded wildcard host", SandboxEgressBlock, " *.example.com\t", "suffix:example.com"},
		{"IPv6 default route", SandboxEgressUnblock, "::/0", "0::/0"},
		{"IPv6 loopback", SandboxEgressBlock, "::1", "0::1"},
		{"IPv6 prefix", SandboxEgressUnblock, "fe80::/10", "fe80::/10"},
		{"IPv4 prefix", SandboxEgressUnblock, "10.0.0.0/8", "10.0.0.0/8"},
		{"IPv4 default route", SandboxEgressUnblock, "0.0.0.0/0", "0.0.0.0/0"},
		{"no target", SandboxPolicyApply, "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{
				Sandbox: testSandboxIdentity(), Operation: test.operation, Actor: "cli:alice", Origin: "cli",
				Target: test.target, ChangeCount: 1,
			}); err != nil {
				t.Fatalf("RecordSandboxPolicy: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if !record.Mandatory() {
				t.Fatal("a policy change must be mandatory")
			}
			got, present := sandboxBody(t, record)["defenseclaw.admin.target_ref"]
			if present != (test.want != "") || (present && got != test.want) {
				t.Fatalf("target_ref=%#v present=%v want %q", got, present, test.want)
			}
			if test.want == "" {
				return
			}
			// A rewritten address still parses to the prefix it replaced.
			if prefix, err := netip.ParsePrefix(test.target); err == nil {
				if again, err := netip.ParsePrefix(test.want); err != nil || again != prefix {
					t.Fatalf("target_ref %q does not name %v", test.want, prefix)
				}
			}
			if addr, err := netip.ParseAddr(test.target); err == nil {
				if again, err := netip.ParseAddr(test.want); err != nil || again != addr {
					t.Fatalf("target_ref %q does not name %v", test.want, addr)
				}
			}
		})
	}
}

func TestSandboxHealthStatesMapToSubsystemFamilies(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, test := range []struct {
		state     SandboxHealthState
		eventName string
		health    string
		outcome   observability.Outcome
		severity  observability.Severity
	}{
		{SandboxHealthStarting, observability.TelemetryEventSubsystemLifecycle, "starting", observability.OutcomeAttempted, observability.SeverityInfo},
		{SandboxHealthStopped, observability.TelemetryEventSubsystemLifecycle, "stopped", observability.OutcomeCompleted, observability.SeverityInfo},
		{SandboxHealthReady, observability.TelemetryEventSubsystemReady, "ready", observability.OutcomeCompleted, observability.SeverityInfo},
		{SandboxHealthRestored, observability.TelemetryEventSubsystemRestored, "restored", observability.OutcomeCompleted, observability.SeverityInfo},
		{SandboxHealthDegraded, observability.TelemetryEventSubsystemDegraded, "degraded", observability.OutcomeFailed, observability.SeverityHigh},
		{SandboxHealthFailed, observability.TelemetryEventSubsystemDegraded, "failed", observability.OutcomeFailed, observability.SeverityHigh},
	} {
		t.Run(string(test.state), func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			input := SandboxHealthEvent{State: test.state, ErrorCode: "openshell_watch_lost", ErrorSummary: "stream reset"}
			if test.state == SandboxHealthDegraded {
				input.Sandbox = testSandboxIdentity()
			}
			if err := recorder.RecordSandboxHealth(context.Background(), input); err != nil {
				t.Fatalf("RecordSandboxHealth: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			severity, _ := record.Severity()
			if record.EventName() != observability.EventName(test.eventName) || record.Outcome() != test.outcome ||
				!record.Mandatory() || severity != test.severity {
				t.Fatalf("record identity=%#v outcome=%q mandatory=%v severity=%q",
					record.Identity(), record.Outcome(), record.Mandatory(), severity)
			}
			body := sandboxBody(t, record)
			if body["defenseclaw.health.subsystem"] != "openshell" || body["defenseclaw.health.state"] != test.health ||
				body["defenseclaw.schema.error_code"] != "openshell_watch_lost" {
				t.Fatalf("health body=%#v", body)
			}
			_, hasSandbox := body["defenseclaw.sandbox.name"]
			if hasSandbox != (test.state == SandboxHealthDegraded) {
				t.Fatalf("sandbox correlation presence=%v body=%#v", hasSandbox, body)
			}
		})
	}
}

func TestSandboxFindingKinds(t *testing.T) {
	harness := newSandboxHarness(t)
	for _, kind := range []SandboxFindingKind{
		SandboxFindingOCSF, SandboxFindingBinaryDrift, SandboxFindingTamperAttempt,
		SandboxFindingHookSilence, SandboxFindingHookTamper, SandboxFindingLargeUpload, SandboxFindingNestedRepo,
	} {
		t.Run(string(kind), func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxFinding(context.Background(), SandboxFindingEvent{
				Sandbox: testSandboxIdentity(), Kind: kind, Severity: "high", Title: "sandbox observation",
				Evidence: "uploaded 30 MiB to a first-seen host", TargetRef: "files.example", Confidence: 0.9,
			}); err != nil {
				t.Fatalf("RecordSandboxFinding: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			body := sandboxBody(t, record)
			wantRule := "SANDBOX-" + strings.ToUpper(strings.ReplaceAll(string(kind), "_", "-"))
			findingID, _ := body["defenseclaw.finding.id"].(string)
			if record.EventName() != observability.EventName(observability.TelemetryEventFindingObserved) ||
				body["defenseclaw.finding.rule_id"] != wantRule || body["defenseclaw.finding.category"] != "sandbox."+string(kind) ||
				body["defenseclaw.security.severity"] != "HIGH" || findingID == "" ||
				record.Correlation().FindingOccurrenceID != findingID || body["defenseclaw.finding.confidence"] != 0.9 {
				t.Fatalf("finding record identity=%#v body=%#v correlation=%#v", record.Identity(), body, record.Correlation())
			}
			assertSandboxCorrelation(t, body, testSandboxIdentity())
		})
	}
	_, recorder := harness.bind(t, router.AdmissionOrdinary)
	if err := recorder.RecordSandboxFinding(context.Background(), SandboxFindingEvent{
		Sandbox: testSandboxIdentity(), Kind: SandboxFindingTamperAttempt,
	}); err == nil {
		t.Fatal("a finding without severity was accepted")
	}
}

func TestSandboxWorkspaceOperations(t *testing.T) {
	harness := newSandboxHarness(t)
	count := func(value int64) *int64 { return &value }
	for _, test := range []struct {
		name      string
		input     SandboxWorkspaceEvent
		outcome   observability.Outcome
		severity  observability.Severity
		mandatory bool
		body      map[string]any
	}{
		{
			name: "snapshot before the session",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspaceSnapshot, SnapshotKind: SandboxSnapshotGit,
				SnapshotRef: "refs/defenseclaw/pre/dc-claudecode-myapp-7f3a",
			},
			outcome: observability.OutcomeCompleted, severity: observability.SeverityInfo,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.operation": "snapshot", "defenseclaw.sandbox.workspace.snapshot.kind": "git",
			},
		},
		{
			name: "review flags host-executable changes",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspaceReview, FileCount: count(8), LinesAdded: count(212), LinesRemoved: count(37),
				FlaggedCount: count(2), Paths: []string{"package.json", ".envrc"},
			},
			outcome: observability.OutcomeCompleted, severity: observability.SeverityMedium, mandatory: true,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.operation": "review", "defenseclaw.sandbox.workspace.file_count": int64(8),
				"defenseclaw.sandbox.workspace.flagged_count": int64(2), "defenseclaw.sandbox.workspace.lines_added": int64(212),
				"defenseclaw.enforcement.effective_action": "review",
			},
		},
		{
			name: "undo restores the git snapshot",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspaceUndo, SnapshotKind: SandboxSnapshotGit, Initiator: "operator",
				SnapshotRef: "refs/defenseclaw/pre/dc-claudecode-myapp-7f3a", FileCount: count(0),
			},
			outcome: observability.OutcomeApplied, severity: observability.SeverityInfo, mandatory: true,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.snapshot.kind": "git", "defenseclaw.enforcement.initiator": "operator",
				"defenseclaw.sandbox.workspace.snapshot.ref": "refs/defenseclaw/pre/dc-claudecode-myapp-7f3a",
				"defenseclaw.sandbox.workspace.file_count":   int64(0),
			},
		},
		{
			name: "quarantine of a nested repository",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspaceQuarantine, Initiator: "defenseclaw", FileCount: count(1), FlaggedCount: count(1),
				Paths: []string{"vendor/evil/.git"}, Severity: "HIGH",
			},
			outcome: observability.OutcomeApplied, severity: observability.SeverityHigh, mandatory: true,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.operation": "quarantine", "defenseclaw.sandbox.workspace.file_count": int64(1),
				"defenseclaw.enforcement.initiator": "defenseclaw",
			},
		},
		{
			name: "failed pull",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspacePull, PullMode: SandboxPullApply, Result: SandboxWorkspaceFailed,
				FailureClass: "merge_conflict", ByteCount: count(4096),
			},
			outcome: observability.OutcomeFailed, severity: observability.SeverityHigh, mandatory: true,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.pull.mode": "apply", "defenseclaw.enforcement.failure_class": "merge_conflict",
				"defenseclaw.sandbox.workspace.byte_count": int64(4096),
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			test.input.Sandbox = testSandboxIdentity()
			if err := recorder.RecordSandboxWorkspace(context.Background(), test.input); err != nil {
				t.Fatalf("RecordSandboxWorkspace: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			severity, _ := record.Severity()
			if record.EventName() != observability.EventName(observability.TelemetryEventSandboxWorkspace) ||
				record.Bucket() != observability.BucketEnforcementAction || record.Outcome() != test.outcome ||
				severity != test.severity || record.Mandatory() != test.mandatory {
				t.Fatalf("workspace record identity=%#v outcome=%q severity=%q mandatory=%v",
					record.Identity(), record.Outcome(), severity, record.Mandatory())
			}
			body := sandboxBody(t, record)
			assertSandboxCorrelation(t, body, test.input.Sandbox)
			for key, want := range test.body {
				if body[key] != want {
					t.Fatalf("body[%q]=%#v want %#v; body=%#v", key, body[key], want, body)
				}
			}
			if _, present := body["defenseclaw.sandbox.workspace.lines_removed"]; present != (test.input.LinesRemoved != nil) {
				t.Fatalf("nil count was not omitted: %#v", body)
			}
		})
	}
	t.Run("paths are bounded", func(t *testing.T) {
		runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
		paths := make([]string, 0, 100)
		for index := 0; index < 100; index++ {
			paths = append(paths, fmt.Sprintf("secrets/%03d.env", index))
		}
		if err := recorder.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
			Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceMask, Paths: paths, FileCount: count(100),
		}); err != nil {
			t.Fatalf("RecordSandboxWorkspace: %v", err)
		}
		_, record := onlySandboxRecord(t, runtime)
		assertRecordMatchesRuntimeContract(t, record)
		kept, _ := sandboxBody(t, record)["defenseclaw.sandbox.workspace.paths"].([]any)
		if len(kept) != maxSandboxWorkspacePaths {
			t.Fatalf("paths kept=%d want %d", len(kept), maxSandboxWorkspacePaths)
		}
	})
}

// TestSandboxWorkspaceMandatoryFloor pins which workspace records no route
// can drop: operations that change the host workspace or what the sandbox
// can read (enforcement_state_change) unless they changed nothing, and
// records that flag host-executable changes (enforced_outcome). A mandatory
// record keeps a content-free floor record and refuses a drop; any other
// record takes neither path.
func TestSandboxWorkspaceMandatoryFloor(t *testing.T) {
	harness := newSandboxHarness(t)
	count := func(value int64) *int64 { return &value }
	for _, test := range []struct {
		name      string
		input     SandboxWorkspaceEvent
		mandatory bool
	}{
		{"undo applied", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUndo}, true},
		{"undo partial", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUndo, Result: SandboxWorkspacePartial}, true},
		{"undo failed", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUndo, Result: SandboxWorkspaceFailed, FailureClass: "checkout_failed"}, true},
		{"undo with nothing to restore", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUndo, Result: SandboxWorkspaceNoChange}, false},
		{"undo skipped", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUndo, Result: SandboxWorkspaceSkipped}, false},
		{"mask applied", SandboxWorkspaceEvent{Operation: SandboxWorkspaceMask, FileCount: count(2)}, true},
		{"pull applied", SandboxWorkspaceEvent{Operation: SandboxWorkspacePull, PullMode: SandboxPullApply}, true},
		{"pull to a branch", SandboxWorkspaceEvent{Operation: SandboxWorkspacePull, PullMode: SandboxPullBranch}, true},
		{"pull to a patch file", SandboxWorkspaceEvent{Operation: SandboxWorkspacePull, PullMode: SandboxPullPatch}, false},
		{"pull without a mode", SandboxWorkspaceEvent{Operation: SandboxWorkspacePull}, false},
		{"flagged patch pull", SandboxWorkspaceEvent{Operation: SandboxWorkspacePull, PullMode: SandboxPullPatch, FlaggedCount: count(1)}, true},
		{"review with flags", SandboxWorkspaceEvent{Operation: SandboxWorkspaceReview, FlaggedCount: count(1)}, true},
		{"review without flags", SandboxWorkspaceEvent{Operation: SandboxWorkspaceReview, FlaggedCount: count(0)}, false},
		{"snapshot", SandboxWorkspaceEvent{Operation: SandboxWorkspaceSnapshot}, false},
		{"quarantine applied", SandboxWorkspaceEvent{Operation: SandboxWorkspaceQuarantine, FileCount: count(1)}, true},
		{"quarantine failed", SandboxWorkspaceEvent{Operation: SandboxWorkspaceQuarantine, Result: SandboxWorkspaceFailed, FailureClass: "rename_failed"}, true},
		{"upload", SandboxWorkspaceEvent{Operation: SandboxWorkspaceUpload, ByteCount: count(1 << 20)}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.input.Sandbox = testSandboxIdentity()
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxWorkspace(context.Background(), test.input); err != nil {
				t.Fatalf("ordinary: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if record.Mandatory() != test.mandatory {
				t.Fatalf("mandatory=%v want %v", record.Mandatory(), test.mandatory)
			}

			runtime, recorder = harness.bind(t, router.AdmissionFloor)
			err := recorder.RecordSandboxWorkspace(context.Background(), test.input)
			if !test.mandatory {
				if err == nil {
					t.Fatal("an ordinary workspace record took the mandatory floor")
				}
			} else {
				if err != nil {
					t.Fatalf("floor: %v", err)
				}
				_, floor := onlySandboxRecord(t, runtime)
				if !floor.IsFloorOnly() || !floor.Mandatory() || floor.Bucket() != observability.BucketEnforcementAction {
					t.Fatalf("floor record floor=%v mandatory=%v bucket=%q", floor.IsFloorOnly(), floor.Mandatory(), floor.Bucket())
				}
			}

			_, recorder = harness.bind(t, router.AdmissionDrop)
			if err := recorder.RecordSandboxWorkspace(context.Background(), test.input); (err != nil) != test.mandatory {
				t.Fatalf("drop admission err=%v, want an error only for a mandatory record", err)
			}
		})
	}
}

func TestSandboxRecorderRejectsInvalidInputBeforeEmission(t *testing.T) {
	valid := testSandboxIdentity()
	mutate := func(change func(*SandboxIdentity)) SandboxIdentity {
		identity := valid
		change(&identity)
		return identity
	}
	count := int64(-1)
	for _, test := range []struct {
		name   string
		record func(*SandboxRecorder) error
	}{
		{"missing name", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Name = "" })})
		}},
		{"name with spaces", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Name = "my sandbox" })})
		}},
		{"missing phase", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Phase = "" })})
		}},
		{"unknown phase", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Phase = "running" })})
		}},
		{"unknown previous phase", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: valid, PreviousPhase: "booting"})
		}},
		{"unknown trigger", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: valid, Trigger: "cron"})
		}},
		{"bad severity", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: valid, Severity: "SEVERE"})
		}},
		{"unknown driver", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Driver = "firecracker" })})
		}},
		{"unknown profile", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Profile = "yolo" })})
		}},
		{"unknown workdir mode", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.WorkdirMode = "overlay" })})
		}},
		{"unknown runtime", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Runtime = "qcontrol" })})
		}},
		{"bad image digest", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.ImageDigest = "sha256:ABC" })})
		}},
		{"connector not a token", func(r *SandboxRecorder) error {
			return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: mutate(func(i *SandboxIdentity) { i.Connector = "Claude Code" })})
		}},
		{"egress without source", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Host: "example.org"})
		}},
		{"egress bad resolved ip", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Source: SandboxEgressSourceProxy, Host: "example.org", ResolvedIP: "not-an-ip"})
		}},
		{"approval without id", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, Kind: SandboxApprovalNetworkRule})
		}},
		{"approval blank id", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, ApprovalID: " \t", Kind: SandboxApprovalNetworkRule})
		}},
		{"approval id with spaces", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, ApprovalID: "draft 7", Kind: SandboxApprovalNetworkRule})
		}},
		{"approval unknown kind", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, ApprovalID: "a1", Kind: "mount"})
		}},
		{"approval unknown stage", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: "pending", ApprovalID: "a1", Kind: SandboxApprovalHostPort})
		}},
		{"requested approval with result", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, ApprovalID: "a1", Kind: SandboxApprovalHostPort, Result: SandboxApprovalApproved})
		}},
		{"resolved approval without result", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalResolved, ApprovalID: "a1", Kind: SandboxApprovalHostPort})
		}},
		{"denied approval with scope", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalResolved, ApprovalID: "a1", Kind: SandboxApprovalHostPort, Result: SandboxApprovalDenied, Scope: SandboxApprovalScopeAlways})
		}},
		{"approval unknown actor", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalResolved, ApprovalID: "a1", Kind: SandboxApprovalHostPort, Result: SandboxApprovalDenied, ActorType: "robot"})
		}},
		{"policy unknown operation", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: "sandbox.policy.nuke"})
		}},
		{"policy bad hash", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxPolicyApply, PolicyHash: "XYZ"})
		}},
		{"policy unknown origin", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxPolicyApply, Origin: "email"})
		}},
		{"policy negative count", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxPolicyApply, ChangeCount: -1})
		}},
		{"policy free-text reason", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxPolicyApply, Reason: "because I said so"})
		}},
		{"policy free-text target", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxPolicyRuleAdd, Target: "the pastebin rule"})
		}},
		{"policy bare wildcard target", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxEgressUnblock, Target: "*."})
		}},
		{"policy nested wildcard target", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxEgressUnblock, Target: "*.*.example.com"})
		}},
		{"policy colon target that is not an address", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxEgressBlock, Target: "::not-an-ip"})
		}},
		{"policy oversized target", func(r *SandboxRecorder) error {
			return r.RecordSandboxPolicy(context.Background(), SandboxPolicyEvent{Sandbox: valid, Operation: SandboxEgressBlock, Target: strings.Repeat("t", maxSandboxPolicyTargetBytes+1)})
		}},
		{"health unknown state", func(r *SandboxRecorder) error {
			return r.RecordSandboxHealth(context.Background(), SandboxHealthEvent{State: "sleepy"})
		}},
		{"health bad error code", func(r *SandboxRecorder) error {
			return r.RecordSandboxHealth(context.Background(), SandboxHealthEvent{State: SandboxHealthDegraded, ErrorCode: "Watch Lost"})
		}},
		{"finding unknown kind", func(r *SandboxRecorder) error {
			return r.RecordSandboxFinding(context.Background(), SandboxFindingEvent{Sandbox: valid, Kind: "vibes", Severity: "HIGH"})
		}},
		{"finding bad confidence", func(r *SandboxRecorder) error {
			return r.RecordSandboxFinding(context.Background(), SandboxFindingEvent{Sandbox: valid, Kind: SandboxFindingHookSilence, Severity: "HIGH", Confidence: 1.5})
		}},
		{"finding bad id", func(r *SandboxRecorder) error {
			return r.RecordSandboxFinding(context.Background(), SandboxFindingEvent{Sandbox: valid, Kind: SandboxFindingHookSilence, Severity: "HIGH", FindingID: "has spaces"})
		}},
		{"workspace unknown operation", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: "shred"})
		}},
		{"workspace unknown result", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspaceUndo, Result: "maybe"})
		}},
		{"workspace negative count", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspaceReview, FileCount: &count})
		}},
		{"workspace unknown pull mode", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspacePull, PullMode: "rsync"})
		}},
		{"workspace initiator with spaces", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspaceUndo, Initiator: "the operator"})
		}},
		{"workspace unknown snapshot kind", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspaceSnapshot, SnapshotKind: "zfs"})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			logger := NewLogger(nil)
			runtime := &countingRuntimeV8Emitter{}
			logger.SetRuntimeV8Emitter(runtime)
			if err := test.record(NewSandboxRecorder(logger)); err == nil {
				t.Fatal("invalid sandbox input was accepted")
			}
			if runtime.logs != 0 || runtime.metrics != 0 {
				t.Fatalf("invalid input reached the runtime: logs=%d metrics=%d", runtime.logs, runtime.metrics)
			}
		})
	}
}

// countingRuntimeV8Emitter admits and persists every occurrence without a
// store and counts the calls that reached it.
type countingRuntimeV8Emitter struct {
	mu      sync.Mutex
	logs    int
	metrics int
}

func (emitter *countingRuntimeV8Emitter) EmitRuntimeV8(
	context.Context,
	router.Metadata,
	RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	emitter.mu.Lock()
	emitter.logs++
	emitter.mu.Unlock()
	return RuntimeV8EmitOutcome{Admission: router.AdmissionOrdinary, LocalPersisted: true}, nil
}

func (emitter *countingRuntimeV8Emitter) RecordRuntimeV8GeneratedMetricBatch(
	context.Context,
	[]RuntimeV8GeneratedMetric,
) error {
	emitter.mu.Lock()
	emitter.metrics++
	emitter.mu.Unlock()
	return nil
}

func TestSandboxRecorderFailsClosedWithoutRuntime(t *testing.T) {
	identity := testSandboxIdentity()
	for _, test := range []struct {
		name     string
		recorder *SandboxRecorder
	}{
		{"nil recorder", nil},
		{"nil logger", NewSandboxRecorder(nil)},
		{"never bound", NewSandboxRecorder(NewLogger(nil))},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity}); err == nil {
				t.Fatal("lifecycle recorded without a runtime")
			}
			if err := test.recorder.RecordSandboxHealth(context.Background(), SandboxHealthEvent{State: SandboxHealthReady}); err == nil {
				t.Fatal("health recorded without a runtime")
			}
		})
	}
	logger := NewLogger(nil)
	detached := &countingRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(detached)
	logger.SetRuntimeV8Emitter(nil)
	if err := NewSandboxRecorder(logger).RecordSandboxEgress(context.Background(), SandboxEgressEvent{
		Sandbox: identity, Source: SandboxEgressSourceProxy, Host: "example.org",
	}); err == nil {
		t.Fatal("egress recorded after the runtime detached")
	}
	if detached.logs != 0 || detached.metrics != 0 {
		t.Fatalf("a detached runtime was still called: logs=%d metrics=%d", detached.logs, detached.metrics)
	}
}

func TestSandboxRecorderReportsRuntimeRejection(t *testing.T) {
	logger := NewLogger(nil)
	rejecting := &rejectingRuntimeV8Emitter{err: fmt.Errorf("runtime closed")}
	logger.SetRuntimeV8Emitter(rejecting)
	err := NewSandboxRecorder(logger).RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
		Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceSnapshot,
	})
	if err == nil || rejecting.calls != 1 {
		t.Fatalf("runtime rejection err=%v calls=%d", err, rejecting.calls)
	}
	unpersisted := &rejectingRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(unpersisted)
	if err := NewSandboxRecorder(logger).RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
		Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceSnapshot,
	}); err == nil {
		t.Fatal("an admitted occurrence that was not persisted was reported as success")
	}
}

func TestSandboxRecordsPersistToEventHistory(t *testing.T) {
	logger, _, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	identity := testSandboxIdentity()
	if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity}); err != nil {
		t.Fatalf("RecordSandboxLifecycle: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("event history rows=%d err=%v", len(rows), err)
	}
	if rows[0].Action != string(ActionSandboxLifecycle) || rows[0].Structured["defenseclaw.sandbox.name"] != identity.Name {
		t.Fatalf("event history row=%#v", rows[0])
	}
}

// TestSandboxActionsRequireTypedFamilies proves the sandbox producer keys are
// usable only through SandboxRecorder: a bare LogAction cannot guess a family.
func TestSandboxActionsRequireTypedFamilies(t *testing.T) {
	logger, runtime, _ := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	for _, action := range []Action{
		ActionSandboxLifecycle, ActionSandboxWorkspace, ActionSandboxEgress, ActionSandboxApproval,
		ActionSandboxPolicy, ActionSandboxHealth, ActionSandboxFinding,
	} {
		if !IsKnownAction(string(action)) {
			t.Fatalf("%s is not a registered audit action", action)
		}
		classification, ok := observability.AuditActionClassification(observability.ProducerKey(action))
		if !ok || !classification.RequiresContext() {
			t.Fatalf("%s classification=%#v ok=%v, want a context-required producer", action, classification, ok)
		}
		if err := logger.LogAction(string(action), "dc-claudecode-myapp-7f3a", "untyped"); err == nil {
			t.Fatalf("LogAction(%s) guessed a family", action)
		}
	}
	if _, records := runtime.snapshot(); len(records) != 0 {
		t.Fatalf("untyped sandbox actions produced %d records", len(records))
	}
}

func TestSandboxHostCanonicalization(t *testing.T) {
	for _, test := range []struct {
		in, want string
		port     int
		ok       bool
	}{
		{"Example.ORG", "example.org", 0, true},
		{"example.org.", "example.org", 0, true},
		{" example.org ", "example.org", 0, true},
		{"[2001:db8::1]", "2001:db8::1", 0, true},
		{"::1", "0:0:0:0:0:0:0:1", 0, true},
		{"::ffff:10.0.0.1", "10.0.0.1", 0, true},
		{"169.254.169.254", "169.254.169.254", 0, true},
		{"fe80::1%eth0", "fe80::1", 0, true},
		{"[fe80::1%25eth0]:443", "fe80::1", 443, true},
		{"example.com:443", "example.com", 443, true},
		{"10.0.0.8:5432", "10.0.0.8", 5432, true},
		{"[::1]:18970", "0:0:0:0:0:0:0:1", 18970, true},
		{"Bücher.Example", "xn--bcher-kva.example", 0, true},
		{"bücher.example:8443", "xn--bcher-kva.example", 8443, true},
		{"r3---sn-abc.example", "r3---sn-abc.example", 0, true},
		{"my_service.internal", "my_service.internal", 0, true},
		{"", "", 0, false},
		{"exa mple.org", "", 0, false},
		{"-bad.example", "", 0, false},
		{"a/b", "", 0, false},
		{"example.com:", "", 0, false},
		{"example.com:0", "", 0, false},
		{"example.com:99999", "", 0, false},
		{"example.com:https", "", 0, false},
		{"user@example.com", "", 0, false},
		{"user:pw@example.com", "", 0, false},
		{"*.example.com", "", 0, false},
		{"100%.example", "", 0, false},
		{"a:b:c", "", 0, false},
		{"bad\xffhost", "", 0, false},
		{"b\u00fccher/evil.example", "", 0, false},
		{strings.Repeat("a", 254), "", 0, false},
		{strings.Repeat("a", 2048), "", 0, false},
	} {
		got, port, ok := canonicalSandboxAuthority(test.in)
		if got != test.want || port != test.port || ok != test.ok {
			t.Errorf("canonicalSandboxAuthority(%q)=(%q,%d,%v) want (%q,%d,%v)",
				test.in, got, port, ok, test.want, test.port, test.ok)
		}
	}
}

// TestSandboxRecorderToleratesAgentChosenValues covers values the sandboxed
// agent picks (destinations, file names, finding targets): they are
// canonicalized, sanitized, bounded, or omitted, never allowed to cost the
// occurrence its record. The cases share one store.
func TestSandboxRecorderToleratesAgentChosenValues(t *testing.T) {
	harness := newSandboxHarness(t)
	t.Run("egress hosts", func(t *testing.T) { testSandboxEgressHostileHostsAreStillRecorded(t, harness) })
	t.Run("approval hosts", func(t *testing.T) { testSandboxApprovalHostileHostIsOmitted(t, harness) })
	t.Run("workspace paths", func(t *testing.T) { testSandboxWorkspacePathsAreSanitizedNotRejected(t, harness) })
	t.Run("workspace path encoding", func(t *testing.T) { testSandboxWorkspacePathsFitTheirEncodedBound(t, harness) })
	t.Run("finding target ref", func(t *testing.T) { testSandboxFindingTargetRefIsBoundedNotDropped(t, harness) })
	t.Run("free text", func(t *testing.T) { testSandboxFreeTextIsBoundedNotRejected(t, harness) })
	t.Run("session and agent ids", func(t *testing.T) { testSandboxAgentCorrelationIsIdentifierChecked(t, harness) })
}

// testSandboxAgentCorrelationIsIdentifierChecked feeds session and agent IDs
// that are not registered identifiers into every egress and approval family.
// They come from the correlation envelope, which the agent fills through its
// session header and hook payload, so gen_ai.conversation.id and
// gen_ai.agent.id are omitted, never allowed to fail the record. A padded
// identifier is trimmed.
func testSandboxAgentCorrelationIsIdentifierChecked(t *testing.T, harness *sandboxHarness) {
	producers := []struct {
		name      string
		mandatory bool
		record    func(context.Context, *SandboxRecorder) error
	}{
		{"egress allowed", false, func(ctx context.Context, r *SandboxRecorder) error {
			return r.RecordSandboxEgress(ctx, SandboxEgressEvent{
				Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: "registry.npmjs.org",
			})
		}},
		{"egress blocked", true, func(ctx context.Context, r *SandboxRecorder) error {
			return r.RecordSandboxEgress(ctx, SandboxEgressEvent{
				Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceOpenShell, Host: "pastebin.com", Blocked: true,
			})
		}},
		{"approval requested", false, func(ctx context.Context, r *SandboxRecorder) error {
			return r.RecordSandboxApproval(ctx, SandboxApprovalEvent{
				Sandbox: testSandboxIdentity(), Stage: SandboxApprovalRequested, ApprovalID: "draft-9",
				Kind: SandboxApprovalNetworkRule,
			})
		}},
		{"approval resolved", true, func(ctx context.Context, r *SandboxRecorder) error {
			return r.RecordSandboxApproval(ctx, SandboxApprovalEvent{
				Sandbox: testSandboxIdentity(), Stage: SandboxApprovalResolved, ApprovalID: "draft-9",
				Kind: SandboxApprovalNetworkRule, Result: SandboxApprovalDenied, ActorType: SandboxApprovalByOperator,
			})
		}},
	}
	for _, ids := range []struct {
		name, session, agent string
		wantSession          string
		wantAgent            string
	}{
		{name: "space", session: "my session", agent: "my agent"},
		{name: "leading underscore", session: "_abc", agent: "_agent"},
		{name: "at sign", session: "abc@def", agent: "agent@host"},
		{name: "over 256 bytes", session: strings.Repeat("s", 257), agent: strings.Repeat("a", 257)},
		{name: "padded", session: " session-9\t", agent: "agent-9 ", wantSession: "session-9", wantAgent: "agent-9"},
	} {
		for _, producer := range producers {
			t.Run(ids.name+"/"+producer.name, func(t *testing.T) {
				runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
				ctx := ContextWithEnvelope(context.Background(), CorrelationEnvelope{
					SessionID: ids.session, AgentID: ids.agent,
				})
				if err := producer.record(ctx, recorder); err != nil {
					t.Fatalf("an agent-chosen session or agent id cost the record: %v", err)
				}
				_, record := onlySandboxRecord(t, runtime)
				assertRecordMatchesRuntimeCatalog(t, record)
				// The record's correlation keeps the envelope's IDs unchanged,
				// as every producer's does, so the schema check covers the
				// whole record except those two join keys.
				wire := decodeRecordWire(t, record)
				if correlation, ok := wire["correlation"].(map[string]any); ok {
					delete(correlation, "session_id")
					delete(correlation, "agent_id")
				}
				if err := runtimeSchemaViolation(t, wire); err != nil {
					t.Fatal(err)
				}
				if record.Mandatory() != producer.mandatory {
					t.Fatalf("mandatory=%v want %v", record.Mandatory(), producer.mandatory)
				}
				body := sandboxBody(t, record)
				for key, want := range map[string]string{
					"gen_ai.conversation.id": ids.wantSession, "gen_ai.agent.id": ids.wantAgent,
				} {
					got, present := body[key]
					if present != (want != "") || (present && got != want) {
						t.Fatalf("%s=%#v present=%v want %q", key, got, present, want)
					}
				}
			})
		}
	}
}

// testSandboxFreeTextIsBoundedNotRejected feeds hostile text into every
// free-text field a sandbox producer carries. Reasons, OpenShell condition
// messages, and finding text can quote what the agent did, so each value is
// bounded on a code point, dropped when it is not UTF-8 or blank, and never
// allowed to cost the occurrence (mandatory or not) its record.
func testSandboxFreeTextIsBoundedNotRejected(t *testing.T, harness *sandboxHarness) {
	hostile := map[string]string{
		"invalid utf-8":      "dc\xff\xfemarker",
		"control characters": "\x1b[2J\r\nline two\x00after nul\u2028",
		"blank":              " \t\r\n ",
		"oversize":           strings.Repeat("\u00e9", 70000),
	}
	for _, test := range []struct {
		name      string
		mandatory bool
		fields    []string
		record    func(*SandboxRecorder, string) error
	}{
		{
			name: "egress", mandatory: true,
			fields: []string{"defenseclaw.network.reason", "defenseclaw.network.policy_outcome"},
			record: func(r *SandboxRecorder, text string) error {
				return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
					Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceOpenShell, Host: "pastebin.com",
					Blocked: true, Reason: text, PolicyOutcome: text,
				})
			},
		},
		{
			name: "approval", mandatory: true, fields: []string{"defenseclaw.guardrail.reason"},
			record: func(r *SandboxRecorder, text string) error {
				return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{
					Sandbox: testSandboxIdentity(), Stage: SandboxApprovalResolved, ApprovalID: "draft-12",
					Kind: SandboxApprovalNetworkRule, Result: SandboxApprovalDenied, Reason: text,
				})
			},
		},
		{
			name: "lifecycle", fields: []string{"defenseclaw.sandbox.condition.message"},
			record: func(r *SandboxRecorder, text string) error {
				return r.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{
					Sandbox: testSandboxIdentity(), Condition: &SandboxCondition{Type: "Ready", Status: "False", Message: text},
				})
			},
		},
		{
			name: "health", mandatory: true, fields: []string{"defenseclaw.health.error_summary"},
			record: func(r *SandboxRecorder, text string) error {
				return r.RecordSandboxHealth(context.Background(), SandboxHealthEvent{
					Sandbox: testSandboxIdentity(), State: SandboxHealthDegraded, ErrorSummary: text,
				})
			},
		},
		{
			name: "finding",
			fields: []string{
				"defenseclaw.finding.title", "defenseclaw.finding.description",
				"defenseclaw.guardrail.evidence_summary", "defenseclaw.finding.remediation",
			},
			record: func(r *SandboxRecorder, text string) error {
				return r.RecordSandboxFinding(context.Background(), SandboxFindingEvent{
					Sandbox: testSandboxIdentity(), Kind: SandboxFindingLargeUpload, Severity: "HIGH",
					Title: text, Description: text, Evidence: text, Remediation: text,
				})
			},
		},
	} {
		for label, text := range hostile {
			t.Run(test.name+"/"+label, func(t *testing.T) {
				runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
				if err := test.record(recorder, text); err != nil {
					t.Fatalf("hostile text cost the record: %v", err)
				}
				_, record := onlySandboxRecord(t, runtime)
				assertRecordMatchesRuntimeContract(t, record)
				if record.Mandatory() != test.mandatory {
					t.Fatalf("mandatory=%v want %v", record.Mandatory(), test.mandatory)
				}
				body := sandboxBody(t, record)
				for _, field := range test.fields {
					value, present := body[field].(string)
					if present != (label == "control characters" || label == "oversize") {
						t.Fatalf("%s present=%v for %s text", field, present, label)
					}
					if present && (!utf8.ValidString(value) || strings.TrimSpace(value) != value || len(value) > len(text)) {
						t.Fatalf("%s=%q was not trimmed and bounded", field, value)
					}
				}
			})
		}
	}
}

// testSandboxEgressHostileHostsAreStillRecorded feeds agent-chosen
// destinations into a blocked decision. Each must still produce the mandatory
// record, on both the ordinary and the floor path, without the raw host text.
func testSandboxEgressHostileHostsAreStillRecorded(t *testing.T, harness *sandboxHarness) {
	for _, test := range []struct {
		name, host string
		port       int
		target     string
		address    string // empty when server.address must be absent
		wantPort   int64  // zero when server.port must be absent
		leak       string
	}{
		{name: "idn name", host: "Bücher.example", target: "xn--bcher-kva.example", address: "xn--bcher-kva.example"},
		{name: "host with port", host: "Example.com:8443", target: "example.com", address: "example.com", wantPort: 8443},
		{name: "explicit port wins", host: "example.com:8443", port: 443, target: "example.com", address: "example.com", wantPort: 443},
		{name: "bracketed ipv6 authority", host: "[2001:db8::1]:443", target: "2001:db8::1", address: "2001:db8::1", wantPort: 443},
		{name: "ipv6 zone", host: "fe80::1%eth0", target: "fe80::1", address: "fe80::1", leak: "eth0"},
		{name: "explicit port out of range", host: "example.org", port: 70000, target: "example.org", address: "example.org"},
		{name: "userinfo", host: "dcuser:dcsecret@example.org", target: sandboxInvalidHost, leak: "dcsecret"},
		{name: "path", host: "example.org/dcpathmarker", target: sandboxInvalidHost, leak: "dcpathmarker"},
		{name: "percent", host: "dc%41marker.example", target: sandboxInvalidHost, leak: "%41marker"},
		{name: "wildcard", host: "*.dcwildcard.example", target: sandboxInvalidHost, leak: "dcwildcard"},
		{name: "space", host: "dc space.example", target: sandboxInvalidHost, leak: "dc space"},
		{name: "too long", host: strings.Repeat("a", 254), target: sandboxInvalidHost, leak: strings.Repeat("a", 254)},
		{name: "port out of range", host: "dcport.example:99999", target: sandboxInvalidHost, leak: "dcport"},
		{name: "invalid utf-8", host: "dcbad\xffhost.example", target: sandboxInvalidHost, leak: "dcbad"},
		{name: "empty", host: "", target: sandboxInvalidHost},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, admission := range []router.Admission{router.AdmissionOrdinary, router.AdmissionFloor} {
				runtime, recorder := harness.bind(t, admission)
				if err := recorder.RecordSandboxEgress(context.Background(), SandboxEgressEvent{
					Sandbox: testSandboxIdentity(), Source: SandboxEgressSourceProxy, Host: test.host, Port: test.port,
					Blocked: true, DecisionCode: "SANDBOX_EGRESS_BLOCKLIST",
				}); err != nil {
					t.Fatalf("admission %v: the host cost the blocked decision its record: %v", admission, err)
				}
				_, record := onlySandboxRecord(t, runtime)
				encoded, err := record.MarshalJSON()
				if err != nil || !record.Mandatory() || record.IsFloorOnly() != (admission == router.AdmissionFloor) {
					t.Fatalf("admission %v: err=%v mandatory=%v floor=%v", admission, err, record.Mandatory(), record.IsFloorOnly())
				}
				if test.leak != "" && bytes.Contains(encoded, []byte(test.leak)) {
					t.Fatalf("admission %v: record kept the raw host text %q: %s", admission, test.leak, encoded)
				}
				if admission == router.AdmissionFloor {
					continue
				}
				assertRecordMatchesRuntimeContract(t, record)
				body := sandboxBody(t, record)
				if body["defenseclaw.network.target_ref"] != test.target {
					t.Fatalf("target_ref=%#v want %q", body["defenseclaw.network.target_ref"], test.target)
				}
				if address, present := body["server.address"]; present != (test.address != "") || (present && address != test.address) {
					t.Fatalf("server.address=%#v present=%v want %q", address, present, test.address)
				}
				if port, present := body["server.port"]; present != (test.wantPort != 0) || (present && port != test.wantPort) {
					t.Fatalf("server.port=%#v present=%v want %d", port, present, test.wantPort)
				}
				if events := sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawEgressEvents); len(events) != 1 {
					t.Fatalf("egress metrics=%d want 1", len(events))
				}
			}
		})
	}
}

func testSandboxApprovalHostileHostIsOmitted(t *testing.T, harness *sandboxHarness) {
	for _, test := range []struct {
		name, host string
		port       int
		address    string
		wantPort   int64
	}{
		{name: "userinfo", host: "dcuser:dcsecret@example.org"},
		{name: "idn authority", host: "Bücher.example:8443", address: "xn--bcher-kva.example", wantPort: 8443},
		{name: "port out of range", host: "10.0.0.8", port: 70000, address: "10.0.0.8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{
				Sandbox: testSandboxIdentity(), Stage: SandboxApprovalResolved, ApprovalID: "draft-11",
				Kind: SandboxApprovalNetworkRule, Host: test.host, Port: test.port, Result: SandboxApprovalDenied,
			}); err != nil {
				t.Fatalf("the host cost the approval its record: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			encoded, _ := record.MarshalJSON()
			if bytes.Contains(encoded, []byte("dcsecret")) {
				t.Fatalf("approval kept userinfo: %s", encoded)
			}
			body := sandboxBody(t, record)
			if address, present := body["server.address"]; present != (test.address != "") || (present && address != test.address) {
				t.Fatalf("server.address=%#v present=%v want %q", address, present, test.address)
			}
			if port, present := body["server.port"]; present != (test.wantPort != 0) || (present && port != test.wantPort) {
				t.Fatalf("server.port=%#v present=%v want %d", port, present, test.wantPort)
			}
		})
	}
}

func testSandboxWorkspacePathsAreSanitizedNotRejected(t *testing.T, harness *sandboxHarness) {
	count := func(value int64) *int64 { return &value }
	for _, test := range []struct {
		name  string
		paths []string
		want  []string
	}{
		{
			name: "hostile names",
			paths: []string{
				"bin/run\xff\xfe.sh", "hooks/pre\x00commit", "/etc/cron.d/job", "C:\\Users\\me\\run.bat",
				"c:relative.bat", "\\\\server\\share\\x", "../outside.sh", "a/../../escape.sh", "./scripts//build.sh",
				"", "\x00", ".", "..",
			},
			want: []string{"bin/run\uFFFD.sh", "hooks/precommit", "scripts/build.sh"},
		},
		{name: "nothing survives", paths: []string{"/abs", "../up", "\x00"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
				Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceReview,
				FileCount: count(int64(len(test.paths))), FlaggedCount: count(int64(len(test.paths))), Paths: test.paths,
			}); err != nil {
				t.Fatalf("a hostile file name cost the review its record: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			body := sandboxBody(t, record)
			if body["defenseclaw.sandbox.workspace.flagged_count"] != int64(len(test.paths)) {
				t.Fatalf("flagged count=%#v want %d", body["defenseclaw.sandbox.workspace.flagged_count"], len(test.paths))
			}
			kept, present := body["defenseclaw.sandbox.workspace.paths"].([]any)
			if present != (len(test.want) > 0) || len(kept) != len(test.want) {
				t.Fatalf("paths=%#v want %q", body["defenseclaw.sandbox.workspace.paths"], test.want)
			}
			for index, want := range test.want {
				if kept[index] != want {
					t.Fatalf("paths[%d]=%q want %q", index, kept[index], want)
				}
			}
		})
	}
}

// testSandboxWorkspacePathsFitTheirEncodedBound pins the path list to the
// registered 16 KiB bound on its JSON encoding. Sixteen 1024-byte paths are
// exactly 16 KiB raw but not once quoted and comma-separated, and quotes,
// backslashes, and control bytes in agent-chosen names grow when escaped. A
// list cut by raw length alone fails the builder and costs the flagged,
// mandatory record.
func testSandboxWorkspacePathsFitTheirEncodedBound(t *testing.T, harness *sandboxHarness) {
	count := func(value int64) *int64 { return &value }
	repeated := func(n int, format, body string, repeat int) []string {
		paths := make([]string, n)
		for index := range paths {
			paths[index] = fmt.Sprintf(format, index) + strings.Repeat(body, repeat)
		}
		return paths
	}
	for _, test := range []struct {
		name  string
		paths []string
		want  int
	}{
		// Each item encodes to 1026 bytes: 2+15*1026+14 fits, a 16th does not.
		{"full-length paths", repeated(16, "big/%02d/", "a", maxSandboxWorkspacePathBytes-len("big/00/")), 15},
		// Each 204-byte name encodes to 806 bytes: 2+20*806+19 fits, 21 do not.
		{"quotes and control bytes", repeated(64, "q%02d/", "\"\x01\x1f\\", 50), 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, candidate := range test.paths {
				if len(candidate) > maxSandboxWorkspacePathBytes {
					t.Fatalf("fixture path is %d bytes, over the item bound", len(candidate))
				}
			}
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
				Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceReview,
				FileCount: count(int64(len(test.paths))), FlaggedCount: count(1), Paths: test.paths,
			}); err != nil {
				t.Fatalf("the path list cost the flagged review its record: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			if !record.Mandatory() {
				t.Fatal("a flagged review must be mandatory")
			}
			kept, _ := sandboxBody(t, record)["defenseclaw.sandbox.workspace.paths"].([]any)
			if len(kept) != test.want {
				t.Fatalf("paths kept=%d want %d", len(kept), test.want)
			}
			for index, value := range kept {
				if value != test.paths[index] {
					t.Fatalf("paths[%d]=%q want %q", index, value, test.paths[index])
				}
			}
			var encoded bytes.Buffer
			encoder := json.NewEncoder(&encoded)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(kept); err != nil {
				t.Fatal(err)
			}
			if size := encoded.Len() - 1; size > maxSandboxWorkspacePathTotal {
				t.Fatalf("encoded paths are %d bytes, over %d", size, maxSandboxWorkspacePathTotal)
			}
		})
	}
}

func testSandboxFindingTargetRefIsBoundedNotDropped(t *testing.T, harness *sandboxHarness) {
	overLimit := "binary:" + strings.Repeat("b", 250)
	for _, test := range []struct{ name, in, want string }{
		{"at the limit", strings.Repeat("t", 256), strings.Repeat("t", 256)},
		{"one byte over", overLimit, overLimit[:256]},
		{"probe length", strings.Repeat("x", 304), strings.Repeat("x", 256)},
		{"admin target bound", strings.Repeat("y", 1024), strings.Repeat("y", 256)},
		{"not an identifier", "/usr/local/bin/claude", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, recorder := harness.bind(t, router.AdmissionOrdinary)
			if err := recorder.RecordSandboxFinding(context.Background(), SandboxFindingEvent{
				Sandbox: testSandboxIdentity(), Kind: SandboxFindingBinaryDrift, Severity: "HIGH", TargetRef: test.in,
			}); err != nil {
				t.Fatalf("the target reference cost the finding its record: %v", err)
			}
			_, record := onlySandboxRecord(t, runtime)
			assertRecordMatchesRuntimeContract(t, record)
			got, present := sandboxBody(t, record)["defenseclaw.finding.target_ref"]
			if present != (test.want != "") || (present && got != test.want) {
				t.Fatalf("target_ref=%#v present=%v want %q", got, present, test.want)
			}
		})
	}
}

// TestRuntimeSchemaValidationRejectsContractViolations proves the schema
// check the sandbox tests rely on is not vacuous: a real workspace record
// passes, and each single-field violation of the envelope, correlation,
// provenance, or body fails.
func TestRuntimeSchemaValidationRejectsContractViolations(t *testing.T) {
	runtime, recorder := newSandboxHarness(t).bind(t, router.AdmissionOrdinary)
	flagged := int64(2)
	if err := recorder.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{
		Sandbox: testSandboxIdentity(), Operation: SandboxWorkspaceReview, FlaggedCount: &flagged,
		Paths: []string{"package.json"},
	}); err != nil {
		t.Fatalf("RecordSandboxWorkspace: %v", err)
	}
	_, record := onlySandboxRecord(t, runtime)
	if err := runtimeSchemaViolation(t, decodeRecordWire(t, record)); err != nil {
		t.Fatalf("the unmodified record fails the schema: %v", err)
	}
	nested := func(wire map[string]any, key string) map[string]any {
		object, _ := wire[key].(map[string]any)
		return object
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"unregistered body field", func(w map[string]any) { nested(w, "body")["defenseclaw.sandbox.nickname"] = "x" }},
		{"unregistered sandbox phase", func(w map[string]any) { nested(w, "body")["defenseclaw.sandbox.phase"] = "running" }},
		{"missing workspace operation", func(w map[string]any) { delete(nested(w, "body"), "defenseclaw.sandbox.workspace.operation") }},
		{"count as a string", func(w map[string]any) { nested(w, "body")["defenseclaw.sandbox.workspace.flagged_count"] = "2" }},
		{"image digest pattern", func(w map[string]any) { nested(w, "body")["defenseclaw.sandbox.image.digest"] = "sha256:XYZ" }},
		{"outcome outside the family", func(w map[string]any) { w["outcome"] = "blocked" }},
		{"another family's bucket", func(w map[string]any) { w["bucket"] = "network.egress" }},
		{"mandatory not a boolean", func(w map[string]any) { w["mandatory"] = "yes" }},
		{"missing provenance", func(w map[string]any) { delete(w, "provenance") }},
		{"unknown provenance member", func(w map[string]any) { nested(w, "provenance")["hostname"] = "build-01" }},
		{"unknown correlation member", func(w map[string]any) { nested(w, "correlation")["sandbox_name"] = "dc-x" }},
		{"unknown envelope member", func(w map[string]any) { w["sandbox"] = map[string]any{} }},
		{"timestamp not a date-time", func(w map[string]any) { w["timestamp"] = "yesterday" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := decodeRecordWire(t, record)
			test.mutate(wire)
			if err := runtimeSchemaViolation(t, wire); err == nil {
				t.Fatal("the runtime schema accepted a contract violation")
			}
		})
	}
}

// runtimeCatalog is the subset of the embedded generated runtime catalog
// (schemas/telemetry/runtime/catalog.json.gz) the sandbox tests validate
// emitted records against.
type runtimeCatalog struct {
	families   map[string]runtimeCatalogFamily
	attributes map[string]runtimeCatalogAttribute
}

type runtimeCatalogFamily struct {
	ID        string `json:"id"`
	Signal    string `json:"signal"`
	Bucket    string `json:"bucket"`
	EventName string `json:"event_name"`
	Outcome   *struct {
		Allowed     []string `json:"allowed"`
		Requirement string   `json:"requirement"`
	} `json:"outcome"`
	RequiredAttributes []string `json:"required_attributes"`
	Fields             []struct {
		Ref        string `json:"ref"`
		Type       string `json:"type"`
		FieldClass string `json:"field_class"`
	} `json:"fields"`
}

type runtimeCatalogAttribute struct {
	ID            string `json:"id"`
	Normalization struct {
		EffectiveConstraints map[string]any `json:"effective_constraints"`
	} `json:"normalization"`
}

var (
	runtimeCatalogOnce  sync.Once
	runtimeCatalogValue runtimeCatalog
	runtimeCatalogErr   error
)

func loadRuntimeCatalog(t *testing.T) runtimeCatalog {
	t.Helper()
	runtimeCatalogOnce.Do(func() {
		var document struct {
			Families   []runtimeCatalogFamily    `json:"families"`
			Attributes []runtimeCatalogAttribute `json:"attributes"`
		}
		if runtimeCatalogErr = json.Unmarshal(publicschemas.TelemetryV8Catalog(), &document); runtimeCatalogErr != nil {
			return
		}
		runtimeCatalogValue = runtimeCatalog{
			families:   make(map[string]runtimeCatalogFamily, len(document.Families)),
			attributes: make(map[string]runtimeCatalogAttribute, len(document.Attributes)),
		}
		for _, family := range document.Families {
			runtimeCatalogValue.families[family.Signal+"\x00"+family.EventName] = family
		}
		for _, attribute := range document.Attributes {
			runtimeCatalogValue.attributes[attribute.ID] = attribute
		}
	})
	if runtimeCatalogErr != nil {
		t.Fatalf("decode embedded runtime catalog: %v", runtimeCatalogErr)
	}
	return runtimeCatalogValue
}

// runtimeSchema is the embedded generated runtime schema
// (schemas/telemetry/runtime/telemetry.schema.json.gz). Each family is
// compiled on demand from its own document: the family definition plus every
// definition it references, verbatim. The root is a oneOf over all ~300
// families; compiling only what a record's family reaches keeps the check
// fast under -race and limits the RE2 rewrite below to patterns sandbox
// records can meet.
type runtimeSchema struct {
	definitions map[string]any
	mu          sync.Mutex
	families    map[string]*jsonschema.Schema
}

const runtimeSchemaDefinitionRef = "#/$defs/"

var (
	runtimeSchemaOnce  sync.Once
	runtimeSchemaValue *runtimeSchema
	runtimeSchemaErr   error

	schemaUnicodeEscape = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)
)

func loadRuntimeSchema(t *testing.T) *runtimeSchema {
	t.Helper()
	runtimeSchemaOnce.Do(func() {
		decoder := json.NewDecoder(bytes.NewReader(publicschemas.TelemetryV8Schema()))
		decoder.UseNumber()
		var document struct {
			Schema      string         `json:"$schema"`
			Definitions map[string]any `json:"$defs"`
		}
		if runtimeSchemaErr = decoder.Decode(&document); runtimeSchemaErr != nil {
			return
		}
		if document.Schema != "https://json-schema.org/draft/2020-12/schema" || len(document.Definitions) == 0 {
			runtimeSchemaErr = fmt.Errorf("unexpected runtime schema dialect %q with %d definitions",
				document.Schema, len(document.Definitions))
			return
		}
		runtimeSchemaValue = &runtimeSchema{
			definitions: document.Definitions, families: make(map[string]*jsonschema.Schema),
		}
	})
	if runtimeSchemaErr != nil {
		t.Fatalf("decode embedded runtime schema: %v", runtimeSchemaErr)
	}
	return runtimeSchemaValue
}

func (schema *runtimeSchema) family(id string) (*jsonschema.Schema, error) {
	schema.mu.Lock()
	defer schema.mu.Unlock()
	if compiled, ok := schema.families[id]; ok {
		return compiled, nil
	}
	root := "family:" + id
	reached := map[string]any{}
	pending := []string{root}
	for len(pending) > 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, done := reached[name]; done {
			continue
		}
		definition, ok := schema.definitions[name]
		if !ok {
			return nil, fmt.Errorf("runtime schema has no definition %q", name)
		}
		// A deep copy, so the RE2 rewrite never touches the shared document.
		encoded, err := json.Marshal(definition)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var copied any
		if err := decoder.Decode(&copied); err != nil {
			return nil, err
		}
		if err := rewriteSchemaPatternsForRE2(copied); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		reached[name] = copied
		pending = append(pending, schemaDefinitionRefs(copied)...)
	}
	document, err := json.Marshal(map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$defs":   reached,
		"$ref":    runtimeSchemaDefinitionRef + root,
	})
	if err != nil {
		return nil, err
	}
	url := "memory://defenseclaw/telemetry/" + id + ".schema.json"
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	if err := compiler.AddResource(url, bytes.NewReader(document)); err != nil {
		return nil, err
	}
	compiled, err := compiler.Compile(url)
	if err != nil {
		return nil, err
	}
	schema.families[id] = compiled
	return compiled, nil
}

// schemaDefinitionRefs lists the $defs names a definition references. Every
// reference in the generated schema has the form #/$defs/<name>.
func schemaDefinitionRefs(node any) []string {
	var names []string
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if ref, ok := child.(string); ok && key == "$ref" && strings.HasPrefix(ref, runtimeSchemaDefinitionRef) {
				names = append(names, strings.TrimPrefix(ref, runtimeSchemaDefinitionRef))
				continue
			}
			names = append(names, schemaDefinitionRefs(child)...)
		}
	case []any:
		for _, child := range value {
			names = append(names, schemaDefinitionRefs(child)...)
		}
	}
	return names
}

// rewriteSchemaPatternsForRE2 makes a definition's regular expressions
// compile with Go's RE2 engine, which the validator uses. The generator
// anchors each portable pattern as ^(?:P)$(?![\s\S]) so that engines whose $
// also matches before a final newline still full-match; RE2's $ already
// means end of text, so the guard is dropped, and \uXXXX escapes become
// \x{XXXX}. A pattern that still does not compile (lookaround) is an error,
// never skipped. Extension keywords and literal values are left alone.
func rewriteSchemaPatternsForRE2(node any) error {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			switch {
			case key == "const" || key == "enum" || key == "default" || key == "examples" || strings.HasPrefix(key, "x-"):
				continue
			case key == "pattern":
				if pattern, ok := child.(string); ok {
					rewritten, err := re2SchemaPattern(pattern)
					if err != nil {
						return err
					}
					value[key] = rewritten
					continue
				}
			case key == "patternProperties":
				if properties, ok := child.(map[string]any); ok {
					rewritten := make(map[string]any, len(properties))
					for pattern, subschema := range properties {
						if err := rewriteSchemaPatternsForRE2(subschema); err != nil {
							return err
						}
						key, err := re2SchemaPattern(pattern)
						if err != nil {
							return err
						}
						rewritten[key] = subschema
					}
					value[key] = rewritten
					continue
				}
			}
			if err := rewriteSchemaPatternsForRE2(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := rewriteSchemaPatternsForRE2(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func re2SchemaPattern(pattern string) (string, error) {
	rewritten := strings.TrimSuffix(pattern, `(?![\s\S])`)
	rewritten = schemaUnicodeEscape.ReplaceAllString(rewritten, `\x{$1}`)
	if _, err := regexp.Compile(rewritten); err != nil {
		return "", fmt.Errorf("schema pattern %q has no RE2 equivalent: %w", pattern, err)
	}
	return rewritten, nil
}

// decodeRecordWire returns a record's canonical wire form with JSON numbers
// kept exact.
func decodeRecordWire(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	encoded, err := record.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return wire
}

// assertRecordMatchesRuntimeSchema validates an ordinary record's canonical
// wire form (envelope, correlation, provenance, body or instrument data, and
// field classes) against its family in the generated runtime schema. A
// floor-only record is a content-free runtime projection the public schema
// does not describe; the floor tests check it separately.
func assertRecordMatchesRuntimeSchema(t *testing.T, record observability.Record) {
	t.Helper()
	if err := runtimeSchemaViolation(t, decodeRecordWire(t, record)); err != nil {
		encoded, _ := record.MarshalJSON()
		t.Fatalf("%v\nrecord: %s", err, encoded)
	}
}

// runtimeSchemaViolation validates one wire-form record against the runtime
// schema family its signal and event name select.
func runtimeSchemaViolation(t *testing.T, wire map[string]any) error {
	t.Helper()
	signal, _ := wire["signal"].(string)
	eventName, _ := wire["event_name"].(string)
	family, ok := loadRuntimeCatalog(t).families[signal+"\x00"+eventName]
	if !ok {
		return fmt.Errorf("record %s/%s has no generated family", signal, eventName)
	}
	compiled, err := loadRuntimeSchema(t).family(family.ID)
	if err != nil {
		t.Fatalf("compile %s from the runtime schema: %v", family.ID, err)
	}
	if err := compiled.Validate(wire); err != nil {
		return fmt.Errorf("%s record violates the generated runtime schema: %w", family.ID, err)
	}
	return nil
}

// assertRecordMatchesRuntimeContract validates an ordinary record against
// the generated runtime schema, then checks what JSON Schema cannot express
// against the generated catalog: the exact byte bounds and patterns of each
// registered field, the closed field set, and per-leaf field classes.
func assertRecordMatchesRuntimeContract(t *testing.T, record observability.Record) {
	t.Helper()
	assertRecordMatchesRuntimeSchema(t, record)
	assertRecordMatchesRuntimeCatalog(t, record)
}

// assertRecordMatchesRuntimeCatalog is the catalog half of
// assertRecordMatchesRuntimeContract.
func assertRecordMatchesRuntimeCatalog(t *testing.T, record observability.Record) {
	t.Helper()
	wire := decodeRecordWire(t, record)
	catalog := loadRuntimeCatalog(t)
	signal, _ := wire["signal"].(string)
	eventName, _ := wire["event_name"].(string)
	family, ok := catalog.families[signal+"\x00"+eventName]
	if !ok {
		t.Fatalf("record %s/%s has no generated family", signal, eventName)
	}
	if wire["bucket"] != family.Bucket {
		t.Fatalf("%s bucket=%v want %s", family.ID, wire["bucket"], family.Bucket)
	}
	outcome, hasOutcome := wire["outcome"].(string)
	if family.Outcome != nil {
		switch family.Outcome.Requirement {
		case "required":
			if !hasOutcome || !containsSandboxValue(family.Outcome.Allowed, outcome) {
				t.Fatalf("%s outcome=%q not in %v", family.ID, outcome, family.Outcome.Allowed)
			}
		case "forbidden":
			if hasOutcome {
				t.Fatalf("%s carries a forbidden outcome %q", family.ID, outcome)
			}
		}
	}
	var fields map[string]any
	switch signal {
	case "logs":
		fields, _ = wire["body"].(map[string]any)
	case "metrics":
		instrument, _ := wire["instrument_data"].(map[string]any)
		fields, _ = instrument["attributes"].(map[string]any)
		if fields == nil {
			fields = map[string]any{}
		}
	default:
		t.Fatalf("unexpected signal %q", signal)
	}
	if fields == nil {
		t.Fatalf("%s record has no body", family.ID)
	}
	registered := make(map[string]string, len(family.Fields))
	classes := make(map[string]string, len(family.Fields))
	for _, field := range family.Fields {
		registered[field.Ref] = field.Type
		classes[field.Ref] = field.FieldClass
	}
	for _, required := range family.RequiredAttributes {
		if _, present := fields[required]; !present {
			t.Fatalf("%s is missing required field %s", family.ID, required)
		}
	}
	fieldClasses, _ := wire["field_classes"].(map[string]any)
	prefix := "/"
	if signal == "metrics" {
		prefix = "/attributes/"
	}
	for key, value := range fields {
		fieldType, ok := registered[key]
		if !ok {
			t.Fatalf("%s carries unregistered field %s", family.ID, key)
		}
		assertCatalogValue(t, family.ID, key, fieldType, value, catalog.attributes[key].Normalization.EffectiveConstraints)
		if items, isList := value.([]any); isList {
			for index := range items {
				if got := fieldClasses[fmt.Sprintf("%s%s/%d", prefix, key, index)]; got != classes[key] {
					t.Fatalf("%s %s[%d] field class=%v want %s", family.ID, key, index, got, classes[key])
				}
			}
		} else if got := fieldClasses[prefix+key]; got != classes[key] {
			t.Fatalf("%s %s field class=%v want %s", family.ID, key, got, classes[key])
		}
	}
}

func assertCatalogValue(t *testing.T, family, key, fieldType string, value any, constraints map[string]any) {
	t.Helper()
	checkString := func(text string) {
		if limit, ok := constraints["max_utf8_bytes"].(float64); ok && fieldType == "string" && float64(len(text)) > limit {
			t.Fatalf("%s %s exceeds %v bytes", family, key, limit)
		}
		if limit, ok := constraints["max_item_utf8_bytes"].(float64); ok && fieldType == "string[]" && float64(len(text)) > limit {
			t.Fatalf("%s %s item exceeds %v bytes", family, key, limit)
		}
		if pattern, ok := constraints["pattern"].(string); ok {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatalf("%s %s pattern %q does not compile: %v", family, key, pattern, err)
			}
			if !compiled.MatchString(text) {
				t.Fatalf("%s %s=%q violates pattern %s", family, key, text, pattern)
			}
		}
		if enum, ok := constraints["enum"].([]any); ok {
			matched := false
			for _, member := range enum {
				matched = matched || member == text
			}
			if !matched {
				t.Fatalf("%s %s=%q not in enum %v", family, key, text, enum)
			}
		}
	}
	switch fieldType {
	case "string":
		text, ok := value.(string)
		if !ok {
			t.Fatalf("%s %s=%#v is not a string", family, key, value)
		}
		checkString(text)
	case "string[]":
		items, ok := value.([]any)
		if !ok {
			t.Fatalf("%s %s=%#v is not a list", family, key, value)
		}
		if limit, ok := constraints["max_items"].(float64); ok && float64(len(items)) > limit {
			t.Fatalf("%s %s has %d items, limit %v", family, key, len(items), limit)
		}
		for _, item := range items {
			text, ok := item.(string)
			if !ok {
				t.Fatalf("%s %s item %#v is not a string", family, key, item)
			}
			checkString(text)
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			t.Fatalf("%s %s=%#v is not a boolean", family, key, value)
		}
	case "int64", "double":
		number, ok := value.(json.Number)
		if !ok {
			t.Fatalf("%s %s=%#v is not a number", family, key, value)
		}
		parsed, err := number.Float64()
		if err != nil || (fieldType == "int64" && strings.ContainsAny(number.String(), ".eE")) {
			t.Fatalf("%s %s=%s is not a %s", family, key, number, fieldType)
		}
		if minimum, ok := constraints["min"].(float64); ok && parsed < minimum {
			t.Fatalf("%s %s=%v below %v", family, key, parsed, minimum)
		}
		if maximum, ok := constraints["max"].(float64); ok && parsed > maximum {
			t.Fatalf("%s %s=%v above %v", family, key, parsed, maximum)
		}
	default:
		t.Fatalf("%s %s has unsupported catalog type %s", family, key, fieldType)
	}
}

func TestSandboxEventTimestampIsPreserved(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	at := time.Date(2026, 9, 26, 12, 0, 0, 0, time.FixedZone("EDT", -4*3600))
	if err := recorder.RecordSandboxHealth(context.Background(), SandboxHealthEvent{State: SandboxHealthReady, Timestamp: at}); err != nil {
		t.Fatalf("RecordSandboxHealth: %v", err)
	}
	if _, record := onlySandboxRecord(t, runtime); !record.Timestamp().Equal(at.UTC()) {
		t.Fatalf("timestamp=%v want %v", record.Timestamp(), at.UTC())
	}
}
