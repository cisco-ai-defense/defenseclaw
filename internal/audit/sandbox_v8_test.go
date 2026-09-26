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
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
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

func sandboxMetrics(t *testing.T, runtime *testRuntimeV8Emitter, instrument string) []observability.Record {
	t.Helper()
	var matched []observability.Record
	for _, record := range runtime.metricSnapshot() {
		assertRecordMatchesRuntimeCatalog(t, record)
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
		assertRecordMatchesRuntimeCatalog(t, record)
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
	for _, condition := range []*SandboxCondition{
		{Type: "Ready", Status: "True", Reason: "SupervisorReady"},
		{
			Type: "ConfigurationReady", Status: "False", Reason: "not a token!",
			Message: strings.Repeat("é", 1000),
		},
	} {
		if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{
			Sandbox: identity, Trigger: SandboxTriggerWatch, Condition: condition,
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

func TestSandboxLifecycleConcurrentRecordsAreConsistent(t *testing.T) {
	_, runtime, recorder := newSandboxTestRecorder(t, router.AdmissionOrdinary)
	const sandboxes = 16
	var group sync.WaitGroup
	errs := make(chan error, sandboxes*2)
	for index := 0; index < sandboxes; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			identity := SandboxIdentity{Name: fmt.Sprintf("dc-codex-repo-%04d", index), Connector: "codex"}
			for _, phase := range []SandboxPhase{SandboxPhaseProvisioning, SandboxPhaseReady} {
				identity.Phase = phase
				errs <- recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity})
			}
		}(index)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, records := runtime.snapshot(); len(records) != sandboxes*2 {
		t.Fatalf("records=%d want %d", len(records), sandboxes*2)
	}
	var maximum int64
	for _, metric := range sandboxMetrics(t, runtime, observability.TelemetryInstrumentDefenseClawSandboxActive) {
		if value := sandboxMetricValue(t, metric); value > maximum {
			maximum = value
		}
	}
	if maximum != sandboxes {
		t.Fatalf("maximum active gauge=%d want %d", maximum, sandboxes)
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
			assertRecordMatchesRuntimeCatalog(t, record)
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
			assertRecordMatchesRuntimeCatalog(t, record)
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
	assertRecordMatchesRuntimeCatalog(t, record)
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
			assertRecordMatchesRuntimeCatalog(t, record)
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
		SandboxFindingHookSilence, SandboxFindingLargeUpload,
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
			assertRecordMatchesRuntimeCatalog(t, record)
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
		name     string
		input    SandboxWorkspaceEvent
		outcome  observability.Outcome
		severity observability.Severity
		body     map[string]any
	}{
		{
			name: "review flags host-executable changes",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspaceReview, FileCount: count(8), LinesAdded: count(212), LinesRemoved: count(37),
				FlaggedCount: count(2), Paths: []string{"package.json", ".envrc"},
			},
			outcome: observability.OutcomeCompleted, severity: observability.SeverityMedium,
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
			outcome: observability.OutcomeApplied, severity: observability.SeverityInfo,
			body: map[string]any{
				"defenseclaw.sandbox.workspace.snapshot.kind": "git", "defenseclaw.enforcement.initiator": "operator",
				"defenseclaw.sandbox.workspace.snapshot.ref": "refs/defenseclaw/pre/dc-claudecode-myapp-7f3a",
				"defenseclaw.sandbox.workspace.file_count":   int64(0),
			},
		},
		{
			name: "failed pull",
			input: SandboxWorkspaceEvent{
				Operation: SandboxWorkspacePull, PullMode: SandboxPullApply, Result: SandboxWorkspaceFailed,
				FailureClass: "merge_conflict", ByteCount: count(4096),
			},
			outcome: observability.OutcomeFailed, severity: observability.SeverityHigh,
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
			assertRecordMatchesRuntimeCatalog(t, record)
			severity, _ := record.Severity()
			if record.EventName() != observability.EventName(observability.TelemetryEventSandboxWorkspace) ||
				record.Bucket() != observability.BucketEnforcementAction || record.Outcome() != test.outcome ||
				severity != test.severity || record.Mandatory() {
				t.Fatalf("workspace record identity=%#v outcome=%q severity=%q", record.Identity(), record.Outcome(), severity)
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
		assertRecordMatchesRuntimeCatalog(t, record)
		kept, _ := sandboxBody(t, record)["defenseclaw.sandbox.workspace.paths"].([]any)
		if len(kept) != maxSandboxWorkspacePaths {
			t.Fatalf("paths kept=%d want %d", len(kept), maxSandboxWorkspacePaths)
		}
	})
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
		{"egress bad host", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Source: SandboxEgressSourceProxy, Host: "user:pw@example.org"})
		}},
		{"egress empty host", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Source: SandboxEgressSourceProxy})
		}},
		{"egress bad port", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Source: SandboxEgressSourceProxy, Host: "example.org", Port: 70000})
		}},
		{"egress bad resolved ip", func(r *SandboxRecorder) error {
			return r.RecordSandboxEgress(context.Background(), SandboxEgressEvent{Sandbox: valid, Source: SandboxEgressSourceProxy, Host: "example.org", ResolvedIP: "not-an-ip"})
		}},
		{"approval without id", func(r *SandboxRecorder) error {
			return r.RecordSandboxApproval(context.Background(), SandboxApprovalEvent{Sandbox: valid, Stage: SandboxApprovalRequested, Kind: SandboxApprovalNetworkRule})
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
		{"workspace absolute path", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspaceMask, Paths: []string{"/home/me/.ssh/id_rsa"}})
		}},
		{"workspace unknown pull mode", func(r *SandboxRecorder) error {
			return r.RecordSandboxWorkspace(context.Background(), SandboxWorkspaceEvent{Sandbox: valid, Operation: SandboxWorkspacePull, PullMode: "rsync"})
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
		ok       bool
	}{
		{"Example.ORG", "example.org", true},
		{"example.org.", "example.org", true},
		{"[2001:db8::1]", "2001:db8::1", true},
		{"::1", "0:0:0:0:0:0:0:1", true},
		{"::ffff:10.0.0.1", "10.0.0.1", true},
		{"169.254.169.254", "169.254.169.254", true},
		{"", "", false},
		{"exa mple.org", "", false},
		{"-bad.example", "", false},
		{strings.Repeat("a", 254), "", false},
	} {
		got, ok := canonicalSandboxHost(test.in)
		if got != test.want || ok != test.ok {
			t.Errorf("canonicalSandboxHost(%q)=(%q,%v) want (%q,%v)", test.in, got, ok, test.want, test.ok)
		}
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

// assertRecordMatchesRuntimeCatalog validates the canonical wire form of an
// ordinary record against its generated family: bucket, outcome contract,
// required fields, the closed field set, per-field types and registered
// constraints, and field classes.
func assertRecordMatchesRuntimeCatalog(t *testing.T, record observability.Record) {
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
