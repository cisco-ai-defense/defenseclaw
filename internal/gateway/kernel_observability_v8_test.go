// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

// kernelTestEmitter captures records under a chosen admission so both the
// ordinary and the mandatory-floor build paths run.
type kernelTestEmitter struct {
	mu        sync.Mutex
	admission router.Admission
	records   []observability.Record
	errs      []error
}

func (emitter *kernelTestEmitter) Emit(
	_ context.Context, _ router.Metadata, build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, emitter.admission)
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	if err != nil {
		emitter.errs = append(emitter.errs, err)
		return pipeline.LocalLogOutcome{}, err
	}
	emitter.records = append(emitter.records, record)
	return pipeline.LocalLogOutcome{}, nil
}

func newKernelTestAdapter(admission router.Admission) (*aiRuntimeV8Adapter, *kernelTestEmitter) {
	emitter := &kernelTestEmitter{admission: admission}
	return &aiRuntimeV8Adapter{runtime: emitter, kernelCursor: &kernelChangeCursor{}}, emitter
}

func kernelRecordBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatalf("record %s has no body", record.EventName())
	}
	object, err := body.Object()
	if err != nil {
		t.Fatalf("record %s body: %v", record.EventName(), err)
	}
	return object
}

func recordsNamed(records []observability.Record, name string) []observability.Record {
	var out []observability.Record
	for _, record := range records {
		if string(record.EventName()) == name {
			out = append(out, record)
		}
	}
	return out
}

func TestPlaneHealthCarriesMechanismBackendLossAndContainerEvents(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	snapshot := sensor.Snapshot{
		Degraded: true,
		Planes: []sensor.PlaneHealth{
			{
				Plane: platform.PlaneC, Available: true, Running: true,
				Mechanism: "Tetragon 1.7.1 (unix socket); fanotify",
				Reason:    "fanotify: 1 path unreadable",
				Backend: &plane.Backend{
					Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "observe",
					EventsLost: 3, LossKnown: true,
				},
				ContainerEvents: 12,
			},
			{Plane: platform.PlaneA, Available: true, Running: true, Mechanism: "ps(1)"},
			// Plane C off the managed Linux helper: no backend, nothing routed.
			{Plane: platform.PlaneC, Available: true, Running: true, Mechanism: "endpoint security"},
		},
	}
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	records := recordsNamed(emitter.records, "ai.runtime.plane_health")
	if len(records) != 3 {
		t.Fatalf("emitted %d plane_health records, want 3", len(records))
	}

	managed := kernelRecordBody(t, records[0])
	for key, want := range map[string]any{
		"defenseclaw.ai.runtime.plane_mechanism": "Tetragon 1.7.1 (unix socket); fanotify",
		// The reason keeps its own field: the mechanism survives a partial cycle.
		"defenseclaw.ai.runtime.plane_reason":     "fanotify: 1 path unreadable",
		"defenseclaw.ai.runtime.plane_backend":    "tetragon",
		"defenseclaw.ai.runtime.loss_known":       true,
		"defenseclaw.ai.runtime.events_lost":      float64(3),
		"defenseclaw.ai.runtime.container_events": float64(12),
	} {
		if got := managed[key]; !sameJSONValue(got, want) {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}

	otherPlane := kernelRecordBody(t, records[1])
	for _, key := range []string{
		"defenseclaw.ai.runtime.plane_backend", "defenseclaw.ai.runtime.events_lost",
		"defenseclaw.ai.runtime.loss_known", "defenseclaw.ai.runtime.container_events",
	} {
		if _, present := otherPlane[key]; present {
			t.Errorf("plane a carries %s", key)
		}
	}
	if otherPlane["defenseclaw.ai.runtime.plane_mechanism"] != "ps(1)" {
		t.Errorf("plane a mechanism = %v", otherPlane["defenseclaw.ai.runtime.plane_mechanism"])
	}

	native := kernelRecordBody(t, records[2])
	for _, key := range []string{
		"defenseclaw.ai.runtime.plane_backend", "defenseclaw.ai.runtime.events_lost",
		"defenseclaw.ai.runtime.loss_known", "defenseclaw.ai.runtime.container_events",
	} {
		if _, present := native[key]; present {
			t.Errorf("a plane c without a managed backend carries %s", key)
		}
	}
}

// sameJSONValue compares a decoded body value with an expected one; the body
// reports numbers as float64 or int64 depending on the path.
func sameJSONValue(got, want any) bool {
	switch wanted := want.(type) {
	case float64:
		switch value := got.(type) {
		case json.Number:
			number, err := value.Float64()
			return err == nil && number == wanted
		case float64:
			return value == wanted
		case int64:
			return float64(value) == wanted
		case int:
			return float64(value) == wanted
		}
		return false
	default:
		return got == want
	}
}

func TestBackendCountersAreClampedIntoTheRegistryRange(t *testing.T) {
	t.Parallel()
	health := sensor.PlaneHealth{
		Plane:           platform.PlaneC,
		Backend:         &plane.Backend{Kind: plane.BackendNative, EventsLost: -5},
		ContainerEvents: 5_000_000_000,
	}
	if got, _ := runtimePlaneEventsLost(health).Get(); got != 0 {
		t.Fatalf("negative loss = %d, want 0", got)
	}
	if got, _ := runtimePlaneContainerEvents(health).Get(); got != runtimeContainerMax {
		t.Fatalf("container events = %d, want the %d cap", got, runtimeContainerMax)
	}
	health.Backend.Kind = "something-new"
	if runtimePlaneBackend(health).IsPresent() {
		t.Fatal("an unknown backend kind must be omitted, not sent")
	}
	if got := runtimeBoundedText(strings.Repeat("é", 200), 256); got.IsPresent() {
		value, _ := got.Get()
		if len(value) > 256 || !strings.HasPrefix(value, "é") {
			t.Fatalf("bounded text = %d bytes", len(value))
		}
	}
}

func hostFinding() sensor.Finding {
	return sensor.Finding{
		FindingID: "run-0123456789abcdef",
		PID:       4242,
		Process:   "cat",
		User:      "alice",
		AgentName: "claude",
		Score:     40,
		Severity:  scoring.SeverityMedium,
		Signals: []scoring.Signal{
			{ID: "agent_credential_access", Weight: 25},
			{ID: "agent_persistence", Weight: 15},
		},
		Correlation: correlate.Result{
			Verdict: correlate.VerdictAccounted,
			Reason:  "discovery independently observed the same subject",
		},
		UID:       intPtr(1000),
		Connector: "claudecode",
		Activities: []sensor.RuntimeActivity{
			{
				Tactic: tactics.CredentialAccess, Source: plane.SourceTetragon,
				UID: intPtr(1000), User: "alice",
				Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read",
				Hook: &sensor.HookJoin{
					Seen: true, Confidence: sensor.HookJoinExact, Connector: "claudecode",
					SessionID: "sess-1", ToolInvocationID: "tool-1",
				},
			},
			{
				Tactic: tactics.Persistence, Source: plane.SourceFanotify,
				UID: intPtr(0), AUID: intPtr(1000), User: "root",
				Outcome: plane.OutcomeWouldBlock, Control: "kernel.persistence_write",
				Hook: &sensor.HookJoin{Seen: false},
			},
		},
	}
}

func TestActivityAndFindingCarryIdentitySourceKernelOutcomeAndHookJoin(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	snapshot := sensor.Snapshot{Findings: []sensor.Finding{hostFinding()}}
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	activities := recordsNamed(emitter.records, "ai.runtime.activity")
	if len(activities) != 2 {
		t.Fatalf("emitted %d activity records, want 2", len(activities))
	}
	byTactic := map[string]observability.Record{}
	for _, record := range activities {
		byTactic[kernelRecordBody(t, record)["defenseclaw.ai.runtime.tactic"].(string)] = record
	}

	credential := byTactic["credential_access"]
	body := kernelRecordBody(t, credential)
	for key, want := range map[string]any{
		"user.id":                               "1000",
		"defenseclaw.user.id_kind":              "posix_uid",
		"defenseclaw.user.name":                 "alice",
		"defenseclaw.ai.runtime.event_source":   "tetragon",
		"defenseclaw.ai.runtime.kernel.outcome": "blocked",
		"defenseclaw.ai.runtime.kernel.control": "kernel.ssh_private_key_read",
		"defenseclaw.ai.runtime.hook_seen":      true,
		"defenseclaw.ai.runtime.hook_join":      "exact",
		"defenseclaw.ai.runtime.agent":          "claude",
		"defenseclaw.ai.runtime.technique":      "T1552",
	} {
		if got := body[key]; got != want {
			t.Errorf("credential_access %s = %v, want %v", key, got, want)
		}
	}
	if _, present := body["defenseclaw.user.login_id"]; present {
		t.Error("a non-root process carries a login id")
	}
	// The joined decision's ids travel in the envelope correlation.
	if got := credential.Correlation(); got.SessionID != "sess-1" || got.ToolInvocationID != "tool-1" {
		t.Errorf("correlation = %+v, want the joined session and tool ids", got)
	}

	persistence := kernelRecordBody(t, byTactic["persistence"])
	for key, want := range map[string]any{
		// user.id is the kernel uid, never replaced by the login uid.
		"user.id":                               "0",
		"defenseclaw.user.login_id":             "1000",
		"defenseclaw.ai.runtime.event_source":   "fanotify",
		"defenseclaw.ai.runtime.kernel.outcome": "would_block",
		"defenseclaw.ai.runtime.hook_seen":      false,
	} {
		if got := persistence[key]; got != want {
			t.Errorf("persistence %s = %v, want %v", key, got, want)
		}
	}
	if _, present := persistence["defenseclaw.ai.runtime.hook_join"]; present {
		t.Error("an unjoined activity carries a hook_join")
	}
	if got := byTactic["persistence"].Correlation(); got.SessionID != "" || got.ToolInvocationID != "" {
		t.Errorf("an unjoined activity carries hook ids: %+v", got)
	}

	findings := recordsNamed(emitter.records, "ai.runtime.finding")
	if len(findings) != 1 {
		t.Fatalf("emitted %d finding records, want 1", len(findings))
	}
	finding := kernelRecordBody(t, findings[0])
	for key, want := range map[string]any{
		"user.id":                               "1000",
		"defenseclaw.ai.runtime.event_source":   "fanotify",
		"defenseclaw.ai.runtime.kernel.outcome": "blocked",
		"defenseclaw.ai.runtime.kernel.control": "kernel.ssh_private_key_read",
	} {
		if got := finding[key]; got != want {
			t.Errorf("finding %s = %v, want %v", key, got, want)
		}
	}
}

func TestRecordsWithoutHostPlaneDetailCarryNoNewFields(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	finding := hostFinding()
	finding.UID, finding.Connector, finding.User, finding.Activities = nil, "", "", nil
	if err := adapter.EmitSnapshot(t.Context(), sensor.Snapshot{Findings: []sensor.Finding{finding}}); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	for _, name := range []string{"ai.runtime.activity", "ai.runtime.finding"} {
		records := recordsNamed(emitter.records, name)
		if len(records) == 0 {
			t.Fatalf("no %s records", name)
		}
		for _, record := range records {
			body := kernelRecordBody(t, record)
			for _, key := range []string{
				"user.id", "defenseclaw.user.login_id", "defenseclaw.ai.runtime.event_source",
				"defenseclaw.ai.runtime.kernel.outcome", "defenseclaw.ai.runtime.kernel.control",
				"defenseclaw.ai.runtime.hook_seen", "defenseclaw.ai.runtime.hook_join",
				"defenseclaw.agent.identity.id",
			} {
				if _, present := body[key]; present {
					t.Errorf("%s carries %s without host-plane detail", name, key)
				}
			}
		}
	}
}

func kernelBlockedEvent() sensor.KernelEvent {
	return sensor.KernelEvent{
		At:      time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Outcome: plane.OutcomeBlocked,
		Control: "kernel.ssh_private_key_read",
		RuleID:  "PATH-SSH-KEY",
		Policy:  "defenseclaw-controls-1a2b3c4d",
		Path:    "/home/alice/.ssh/dccert-block-marker-key",
		PID:     4321, ExecID: "exec-1", Process: "cat", Exe: "/usr/bin/cat",
		UID: intPtr(1000), User: "alice", AgentName: "claude", Connector: "claudecode",
		Hook: &sensor.HookJoin{Seen: true, Confidence: sensor.HookJoinExact, SessionID: "sess-1", ToolInvocationID: "tool-1"},
	}
}

func kernelTestStatus() *sensor.KernelState {
	return &sensor.KernelState{
		Status:    acquire.KernelStatus{Available: true, Mode: "enforce", KernelPolicy: "sha256:3f9c2a7d41b0", Applied: true},
		FetchedAt: time.Now(), Reachable: true,
	}
}

func TestKernelDenialIsAnEnforcementBlockAppliedRecord(t *testing.T) {
	for _, admission := range []router.Admission{router.AdmissionOrdinary, router.AdmissionFloor} {
		t.Run(admission.String(), func(t *testing.T) {
			adapter, emitter := newKernelTestAdapter(admission)
			would := kernelBlockedEvent()
			would.Outcome = plane.OutcomeWouldBlock
			snapshot := sensor.Snapshot{
				KernelEvents: []sensor.KernelEvent{kernelBlockedEvent(), would},
				Kernel:       kernelTestStatus(),
			}
			if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
				t.Fatalf("EmitSnapshot() error = %v; build errors %v", err, emitter.errs)
			}
			records := recordsNamed(emitter.records, "enforcement.block.applied")
			if len(records) != 1 {
				t.Fatalf("emitted %d block.applied records, want 1 (a would-block is not an enforcement)", len(records))
			}
			record := records[0]
			if record.Outcome() != observability.OutcomeBlocked || !record.Mandatory() {
				t.Fatalf("outcome = %s, mandatory = %t; want blocked and mandatory", record.Outcome(), record.Mandatory())
			}
			if record.Connector() != "claudecode" {
				t.Errorf("connector = %q", record.Connector())
			}
			if admission == router.AdmissionFloor {
				// The floor form is minimal and content free.
				if !record.IsFloorOnly() {
					t.Fatal("floor admission did not build the floor form")
				}
				return
			}
			raw, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			for _, leaked := range []string{"dccert-block-marker-key", "/home/alice", "exec-1"} {
				if strings.Contains(string(raw), leaked) {
					t.Errorf("record leaks %q: %s", leaked, raw)
				}
			}
			body := kernelRecordBody(t, record)
			for key, want := range map[string]any{
				"defenseclaw.policy.id":                    "defenseclaw-controls-1a2b3c4d",
				"defenseclaw.policy.version":               "sha256:3f9c2a7d41b0",
				"defenseclaw.guardrail.rule_id":            "PATH-SSH-KEY",
				"defenseclaw.enforcement.initiator":        "kernel",
				"defenseclaw.enforcement.effective_action": "block",
				"defenseclaw.ai.runtime.kernel.control":    "kernel.ssh_private_key_read",
				"user.id":                                  "1000",
				"defenseclaw.user.name":                    "alice",
			} {
				if got := body[key]; got != want {
					t.Errorf("%s = %v, want %v", key, got, want)
				}
			}
			if id, _ := body["defenseclaw.enforcement.id"].(string); !strings.HasPrefix(id, "kernel-") {
				t.Errorf("enforcement id = %v", body["defenseclaw.enforcement.id"])
			}
			// No generation is installed: the effective digest and generation
			// are unknown and omitted.
			for _, key := range []string{"defenseclaw.policy.effective_digest", "defenseclaw.policy.generation"} {
				if _, present := body[key]; present {
					t.Errorf("%s present without a matching generation", key)
				}
			}
			correlation := record.Correlation()
			if correlation.SessionID != "sess-1" || correlation.ToolInvocationID != "tool-1" ||
				correlation.PolicyID != "defenseclaw-controls-1a2b3c4d" {
				t.Errorf("correlation = %+v", correlation)
			}
		})
	}
}

// The effective digest and generation are stamped only when the live
// generation was built against the control set the helper applied.
func TestKernelDenialStampsTheGenerationOnlyWhenItsKernelPolicyMatches(t *testing.T) {
	previous := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(previous) })
	digest := "sha256:" + strings.Repeat("ab", 32)

	for _, test := range []struct {
		name      string
		component string
		want      bool
	}{
		{"full digest with the helper's prefix", "sha256:3f9c2a7d41b0" + strings.Repeat("0", 52), true},
		{"identical short digest", "sha256:3f9c2a7d41b0", true},
		{"another control set", "sha256:aaaaaaaaaaaa" + strings.Repeat("0", 52), false},
		{"no component", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			components := map[string]string{"config": "sha256:x"}
			if test.component != "" {
				components["kernel_policy"] = test.component
			}
			liveGeneration.Store(&Generation{
				N: 7, Config: &config.Config{}, Digest: digest, Components: components,
			})
			adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
			snapshot := sensor.Snapshot{
				KernelEvents: []sensor.KernelEvent{kernelBlockedEvent()}, Kernel: kernelTestStatus(),
			}
			if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
				t.Fatalf("EmitSnapshot() error = %v; %v", err, emitter.errs)
			}
			records := recordsNamed(emitter.records, "enforcement.block.applied")
			if len(records) != 1 {
				t.Fatalf("emitted %d records", len(records))
			}
			body := kernelRecordBody(t, records[0])
			_, hasDigest := body["defenseclaw.policy.effective_digest"]
			_, hasGeneration := body["defenseclaw.policy.generation"]
			if hasDigest != test.want || hasGeneration != test.want {
				t.Fatalf("digest present = %t, generation present = %t, want %t", hasDigest, hasGeneration, test.want)
			}
			if test.want && (body["defenseclaw.policy.effective_digest"] != digest ||
				!sameJSONValue(body["defenseclaw.policy.generation"], float64(7))) {
				t.Fatalf("stamped %v / %v", body["defenseclaw.policy.effective_digest"], body["defenseclaw.policy.generation"])
			}
		})
	}
}

func TestKernelPolicyChangesEmitOncePerChange(t *testing.T) {
	t.Parallel()
	now := time.Now()
	at := func(offset time.Duration) int64 { return now.Add(offset).UnixNano() }
	changes := []acquire.KernelChange{
		{Seq: 1, AtUnixNano: at(-time.Hour), Event: "loaded", Policy: "defenseclaw-observe-aaaaaaaa", Family: "observe", Mode: "monitor", State: "TP_STATE_ENABLED"},
		{Seq: 2, AtUnixNano: at(-time.Minute), Event: "loaded", Policy: "defenseclaw-controls-1a2b3c4d", Family: "controls", Mode: "monitor", State: "TP_STATE_ENABLED"},
		{Seq: 3, AtUnixNano: at(-30 * time.Second), Event: "uid_ready", UID: intPtr(1000), Reason: "burn_in_complete"},
		{Seq: 4, AtUnixNano: at(-20 * time.Second), Event: "mode_changed", Policy: "defenseclaw-controls-1a2b3c4d", Family: "controls", Mode: "enforce"},
		{Seq: 5, AtUnixNano: at(-10 * time.Second), Event: "reconcile_failed", Reason: "kernel_reconcile_failed"},
		{Seq: 6, AtUnixNano: at(-5 * time.Second), Event: "invented_by_a_newer_helper"},
	}
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	snapshot := sensor.Snapshot{Kernel: &sensor.KernelState{
		Status: acquire.KernelStatus{Available: true, Mode: "enforce", KernelPolicy: "sha256:3f9c2a7d41b0", Changes: changes},
	}}
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v; %v", err, emitter.errs)
	}
	records := recordsNamed(emitter.records, "ai.runtime.kernel_policy")
	// First sight reports only the recent changes (seq 1 is an hour old) and
	// drops the one no registry enum knows.
	if len(records) != 4 {
		t.Fatalf("first emission reported %d kernel_policy records, want 4", len(records))
	}
	loaded := kernelRecordBody(t, records[0])
	for key, want := range map[string]any{
		"defenseclaw.ai.runtime.kernel.event":  "loaded",
		"defenseclaw.policy.id":                "defenseclaw-controls-1a2b3c4d",
		"defenseclaw.ai.runtime.kernel.family": "controls",
		"defenseclaw.ai.runtime.kernel.mode":   "monitor",
		"defenseclaw.ai.runtime.kernel.state":  "TP_STATE_ENABLED",
		"defenseclaw.policy.version":           "sha256:3f9c2a7d41b0",
	} {
		if got := loaded[key]; got != want {
			t.Errorf("loaded %s = %v, want %v", key, got, want)
		}
	}
	if _, present := loaded["user.id"]; present {
		t.Error("a policy load carries a user")
	}
	ready := kernelRecordBody(t, records[1])
	if ready["user.id"] != "1000" || ready["defenseclaw.user.id_kind"] != "posix_uid" ||
		ready["defenseclaw.ai.runtime.kernel.reason"] != "burn_in_complete" {
		t.Errorf("uid_ready body = %v", ready)
	}
	if records[3].Outcome() != observability.OutcomeFailed {
		t.Errorf("reconcile_failed outcome = %s, want failed", records[3].Outcome())
	}
	if at, ok := records[1].ObservedAt(); !ok || at.UnixNano() != changes[2].AtUnixNano {
		t.Errorf("observed_at = %v, %t; want the change's own time", at, ok)
	}

	// A second poll over the same ring reports nothing; a new change reports once.
	before := len(emitter.records)
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if len(emitter.records) != before {
		t.Fatalf("the same changes were reported again: %d new records", len(emitter.records)-before)
	}
	snapshot.Kernel.Status.Changes = append(append([]acquire.KernelChange(nil), changes...),
		acquire.KernelChange{Seq: 7, AtUnixNano: at(-time.Second), Event: "paused", Reason: "break glass"})
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	if got := recordsNamed(emitter.records, "ai.runtime.kernel_policy"); len(got) != 5 {
		t.Fatalf("kernel_policy records = %d after one new change, want 5", len(got))
	}
}

func TestKernelChangeCursorHandlesARestartedSequence(t *testing.T) {
	t.Parallel()
	cursor := &kernelChangeCursor{}
	now := time.Now()
	recent := now.Add(-time.Second).UnixNano()
	if got := cursor.take([]acquire.KernelChange{{Seq: 40, AtUnixNano: recent, Event: "loaded"}}, now); len(got) != 1 {
		t.Fatalf("first sight returned %d, want 1", len(got))
	}
	if got := cursor.take([]acquire.KernelChange{{Seq: 40, AtUnixNano: recent, Event: "loaded"}}, now); len(got) != 0 {
		t.Fatalf("a repeat returned %d, want 0", len(got))
	}
	// The helper's state was removed and its sequence restarted below the cursor.
	if got := cursor.take([]acquire.KernelChange{{Seq: 2, AtUnixNano: recent, Event: "loaded"}}, now); len(got) != 1 {
		t.Fatalf("a restarted sequence returned %d, want its recent change", len(got))
	}
	if got := cursor.take(nil, now); got != nil {
		t.Fatalf("no changes returned %v", got)
	}
}

func TestKernelPolicyMatchesGenerationNeedsBothDigests(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		helper, component string
		want              bool
	}{
		{"sha256:3f9c2a7d41b0", "sha256:3f9c2a7d41b0", true},
		{"sha256:3f9c2a7d41b0", "sha256:3f9c2a7d41b0ffff", true},
		{"sha256:3f9c2a7d41b0", "sha256:4f9c2a7d41b0", false},
		{"", "sha256:3f9c2a7d41b0", false},
		{"sha256:3f9c2a7d41b0", "", false},
	} {
		if got := kernelPolicyMatchesGeneration(test.helper, test.component); got != test.want {
			t.Errorf("match(%q, %q) = %t, want %t", test.helper, test.component, got, test.want)
		}
	}
}

// Every control the registry names maps to a guardrail rule id, so a denial
// always joins the hook record of the same intent.
func TestEveryKernelControlHasAGuardrailRuleID(t *testing.T) {
	t.Parallel()
	for _, control := range kernelControls {
		if sensor.KernelControlRuleID(control) == "" {
			t.Errorf("control %q has no guardrail rule id", control)
		}
	}
}
