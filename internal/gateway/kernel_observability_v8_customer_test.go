// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// kernelMetricEmitter is kernelTestEmitter that also records generated
// metrics.
type kernelMetricEmitter struct {
	kernelTestEmitter
	metricsMu sync.Mutex
	metrics   []observability.Record
}

func (emitter *kernelMetricEmitter) RecordGeneratedMetric(
	_ context.Context, _ observability.EventName, build observabilityruntime.GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	record, err := build(observabilityruntime.EmitContext{})
	if err != nil {
		return telemetry.V8MetricRecordResult{}, err
	}
	emitter.metricsMu.Lock()
	emitter.metrics = append(emitter.metrics, record)
	emitter.metricsMu.Unlock()
	return telemetry.V8MetricRecordResult{}, nil
}

const customerTestMarker = "/home/dev/tg2work/dccert-block-marker"

func customerTestEvents() []sensor.CustomerKernelEvent {
	return []sensor.CustomerKernelEvent{{
		At: time.Date(2026, 10, 7, 11, 59, 0, 0, time.UTC), Policy: "10-file-sensitive", HookType: "lsm",
		Function: "file_open", Action: "override", PolicyMode: "enforce", Outcome: plane.OutcomeBlocked,
		Target: customerTestMarker, Tags: []string{"files", "sensitive"}, Message: "sensitive file access", Count: 3,
		PID: 1303, ExecID: "cat", Process: "cat", Exe: "/usr/bin/cat", Cmdline: "/usr/bin/cat " + customerTestMarker,
		UID: runtimeIntp(1001), User: "dev", AgentName: "claude", Connector: "claudecode", RootPID: 1300, ToolPID: 1302,
		Hook: &sensor.HookJoin{Seen: true, Confidence: sensor.HookJoinExact, SessionID: "sess-1", ToolInvocationID: "tool-1",
			Action: "alert", RuleIDs: []string{"R-1"}},
	}, {
		At: time.Date(2026, 10, 7, 11, 59, 1, 0, time.UTC), Policy: "20-net-connect", HookType: "kprobe",
		Function: "tcp_connect", Action: "post", PolicyMode: "monitor", Outcome: plane.OutcomeObserved,
		Target: "203.0.113.10:443", Count: 1, PID: 1300, Process: "2.1.292", UID: runtimeIntp(1001), AgentName: "claude",
	}}
}

// TestKernelEventRecordsCarryTheCustomersPolicyEvents: one kernel_event
// record per attributed event, with the policy, hook, action, mode, outcome,
// target, tags, message, count, agent, user and hook join.
func TestKernelEventRecordsCarryTheCustomersPolicyEvents(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	if err := adapter.EmitSnapshot(t.Context(), sensor.Snapshot{CustomerKernelEvents: customerTestEvents()}); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	records := recordsNamed(emitter.records, "ai.runtime.kernel_event")
	if len(records) != 2 {
		t.Fatalf("%d kernel_event records", len(records))
	}
	body := kernelRecordBody(t, records[0])
	for key, want := range map[string]any{
		"defenseclaw.ai.runtime.kernel.policy_owner": "customer",
		"defenseclaw.ai.runtime.kernel.policy_name":  "10-file-sensitive",
		"defenseclaw.ai.runtime.kernel.hook_type":    "lsm",
		"defenseclaw.ai.runtime.kernel.function":     "file_open",
		"defenseclaw.ai.runtime.kernel.action":       "override",
		"defenseclaw.ai.runtime.kernel.policy_mode":  "enforce",
		"defenseclaw.ai.runtime.kernel.outcome":      "blocked",
		"defenseclaw.ai.runtime.kernel.target":       customerTestMarker,
		"defenseclaw.ai.runtime.kernel.message":      "sensitive file access",
		"defenseclaw.ai.runtime.kernel.count":        float64(3),
		"defenseclaw.ai.runtime.agent":               "claude",
		"defenseclaw.ai.runtime.process":             "cat",
		"defenseclaw.ai.runtime.event_source":        "tetragon",
		"defenseclaw.ai.runtime.hook_seen":           true,
		"defenseclaw.ai.runtime.hook_join":           "exact",
		"defenseclaw.ai.runtime.hook_action":         "alert",
		"user.id":                                    "1001",
	} {
		if got := body[key]; !sameJSONValue(got, want) {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}
	if tags, _ := body["defenseclaw.ai.runtime.kernel.tags"].([]any); len(tags) != 2 {
		t.Errorf("tags %v", body["defenseclaw.ai.runtime.kernel.tags"])
	}
	if correlation := records[0].Correlation(); correlation.SessionID != "sess-1" || correlation.ToolInvocationID != "tool-1" {
		t.Errorf("correlation %+v", correlation)
	}
	if severity, _ := records[0].Severity(); severity != observability.SeverityMedium {
		t.Errorf("a blocked event's severity %v", severity)
	}
	second := kernelRecordBody(t, records[1])
	if _, ok := second["defenseclaw.ai.runtime.hook_seen"]; ok {
		t.Errorf("the agent's own connect carries hook_seen: %v", second)
	}
	if second["defenseclaw.ai.runtime.kernel.target"] != "203.0.113.10:443" {
		t.Errorf("connect target %v", second["defenseclaw.ai.runtime.kernel.target"])
	}
	for key := range second {
		if strings.Contains(key, "cmdline") {
			t.Errorf("a kernel_event record carries %s", key)
		}
	}
}

// TestASyscallKprobeEventBecomesARecord: a customer kprobe on a syscall
// (`call: sys_openat`, `syscall: true`) reports the architecture's entry
// symbol, __x64_sys_openat. Its leading underscores once failed the record
// build, so none of that policy's events reached Loki (GAP-0037).
func TestASyscallKprobeEventBecomesARecord(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	event := sensor.CustomerKernelEvent{
		At: time.Date(2026, 10, 8, 2, 35, 0, 0, time.UTC), Policy: "11-file-denied", HookType: "kprobe",
		Function: "__x64_sys_openat", Action: "post", PolicyMode: "monitor", Outcome: plane.OutcomeObserved,
		Target: customerTestMarker, Count: 1, PID: 1310, Process: "cat", UID: runtimeIntp(1001), AgentName: "claude",
	}
	if err := adapter.EmitSnapshot(t.Context(), sensor.Snapshot{CustomerKernelEvents: []sensor.CustomerKernelEvent{event}}); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	records := recordsNamed(emitter.records, "ai.runtime.kernel_event")
	if len(records) != 1 {
		t.Fatalf("%d kernel_event records, want 1", len(records))
	}
	if got := kernelRecordBody(t, records[0])["defenseclaw.ai.runtime.kernel.function"]; got != "__x64_sys_openat" {
		t.Fatalf("kernel.function = %v", got)
	}
}

// TestARecordNeverCarriesAPathOutsideTheTarget: of every kernel_event and
// kernel block.applied field, only kernel.target names the file; a denial
// names it relative to the user's home.
func TestARecordNeverCarriesAPathOutsideTheTarget(t *testing.T) {
	saved := kernelUserHome
	kernelUserHome = func(*int, string) string { return "/home/dev" }
	defer func() { kernelUserHome = saved }()

	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	snapshot := sensor.Snapshot{
		CustomerKernelEvents: customerTestEvents()[:1],
		KernelEvents: []sensor.KernelEvent{{
			At: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC), Outcome: plane.OutcomeBlocked,
			Control: "kernel.ssh_private_key_read", RuleID: "PATH-SSH-KEY", Policy: "defenseclaw-controls-0a1b2c3d",
			Kind: plane.KindFileRead, Path: "/home/dev/.ssh/id_ed25519", PID: 1303, ExecID: "cat", Process: "cat",
			Exe: "/usr/bin/cat", UID: runtimeIntp(1001), User: "dev", AgentName: "claude", Connector: "claudecode",
		}},
	}
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	for _, check := range []struct {
		name, path, want string
	}{
		{"ai.runtime.kernel_event", customerTestMarker, customerTestMarker},
		{"enforcement.block.applied", "/home/dev/.ssh/id_ed25519", "~/.ssh/id_ed25519"},
	} {
		records := recordsNamed(emitter.records, check.name)
		if len(records) != 1 {
			t.Fatalf("%d %s records", len(records), check.name)
		}
		body := kernelRecordBody(t, records[0])
		if body["defenseclaw.ai.runtime.kernel.target"] != check.want {
			t.Fatalf("%s target %v, want %v", check.name, body["defenseclaw.ai.runtime.kernel.target"], check.want)
		}
		if check.name == "enforcement.block.applied" && body["defenseclaw.ai.runtime.process"] != "cat" {
			t.Fatalf("denial process %v", body["defenseclaw.ai.runtime.process"])
		}
		delete(body, "defenseclaw.ai.runtime.kernel.target")
		raw, _ := json.Marshal(body)
		whole, _ := records[0].MarshalJSON()
		if strings.Contains(string(raw), "dccert-block-marker") || strings.Contains(string(raw), ".ssh/") ||
			strings.Count(string(whole), check.path) > 0 && check.path != check.want {
			t.Fatalf("%s carries the path outside kernel.target: %s", check.name, whole)
		}
	}
}

func fleetSnapshot(would, blocked, seen int64) sensor.Snapshot {
	installed := true
	return sensor.Snapshot{
		Planes: []sensor.PlaneHealth{{Plane: platform.PlaneC, Available: true, Running: true, Mechanism: "Tetragon v1.7.1 (gRPC)",
			Backend: &plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "observe"}}},
		Kernel: &sensor.KernelState{FetchedAt: time.Now(), Reachable: true, Status: acquire.KernelStatus{
			Available: true, Mode: "observe", IntentMode: "enforce", Approval: "stale", KernelPolicy: "sha256:08b71155b713",
			Tetragon: &acquire.KernelTetragon{Version: "v1.7.1", Connected: true, Installed: &installed},
			Users: []acquire.KernelUserStatus{
				{UID: 1001, Mode: "enforce", Ready: true},
				{UID: 1002, Mode: "monitor", CoveredSeconds: 3600, BurnInSeconds: 604800},
				{UID: 1003, Mode: "observe_only", Reason: "guardrail_observe"},
			},
			Pause:          &acquire.KernelPause{UntilUnixNano: time.Now().Add(time.Hour).UnixNano()},
			Counters:       map[string]int64{"would_block_total": would, "blocked_total": blocked},
			CustomerEvents: &acquire.KernelCustomerEvents{Seen: seen},
		}},
	}
}

// TestPlaneHealthCarriesTheFleetFields: plane c says what the host's kernel
// controls do, and the growth of the helper's counters per cycle (the first
// cycle is a baseline; a helper restart counts from zero).
func TestPlaneHealthCarriesTheFleetFields(t *testing.T) {
	t.Parallel()
	cursor := &kernelDeltaCursor{}
	emit := func(snapshot sensor.Snapshot) map[string]any {
		t.Helper()
		adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
		adapter.kernelDeltas = cursor
		if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
			t.Fatalf("EmitSnapshot() error = %v", err)
		}
		records := recordsNamed(emitter.records, "ai.runtime.plane_health")
		if len(records) != 1 {
			t.Fatalf("%d plane_health records", len(records))
		}
		return kernelRecordBody(t, records[0])
	}
	first := emit(fleetSnapshot(5, 1, 40))
	for key, want := range map[string]any{
		"defenseclaw.ai.runtime.kernel.helper_mode":           "enforce",
		"defenseclaw.ai.runtime.kernel.approval":              "stale",
		"defenseclaw.policy.version":                          "sha256:08b71155b713",
		"defenseclaw.ai.runtime.kernel.users_enrolled":        float64(3),
		"defenseclaw.ai.runtime.kernel.users_enforced":        float64(1),
		"defenseclaw.ai.runtime.kernel.users_burn_in":         float64(1),
		"defenseclaw.ai.runtime.kernel.paused":                true,
		"defenseclaw.ai.runtime.tetragon.version":             "v1.7.1",
		"defenseclaw.ai.runtime.tetragon.installed":           true,
		"defenseclaw.ai.runtime.kernel.would_block_delta":     float64(0),
		"defenseclaw.ai.runtime.kernel.blocked_delta":         float64(0),
		"defenseclaw.ai.runtime.kernel.customer_events_delta": float64(0),
	} {
		if got := first[key]; !sameJSONValue(got, want) {
			t.Errorf("%s = %v (%T), want %v", key, got, got, want)
		}
	}
	second := emit(fleetSnapshot(9, 3, 52))
	if !sameJSONValue(second["defenseclaw.ai.runtime.kernel.would_block_delta"], float64(4)) ||
		!sameJSONValue(second["defenseclaw.ai.runtime.kernel.blocked_delta"], float64(2)) ||
		!sameJSONValue(second["defenseclaw.ai.runtime.kernel.customer_events_delta"], float64(12)) {
		t.Fatalf("growth %v", second)
	}
	restarted := emit(fleetSnapshot(2, 0, 7))
	if !sameJSONValue(restarted["defenseclaw.ai.runtime.kernel.would_block_delta"], float64(2)) ||
		!sameJSONValue(restarted["defenseclaw.ai.runtime.kernel.customer_events_delta"], float64(7)) {
		t.Fatalf("after a helper restart %v", restarted)
	}
	// No kernel_status: no fleet fields.
	plain := fleetSnapshot(0, 0, 0)
	plain.Kernel = nil
	for key := range emit(plain) {
		if strings.HasPrefix(key, "defenseclaw.ai.runtime.kernel.") || strings.HasPrefix(key, "defenseclaw.ai.runtime.tetragon.") {
			t.Fatalf("fleet field %s without kernel_status", key)
		}
	}
}

func TestKernelPolicyRecordsCarryBurnInProgress(t *testing.T) {
	t.Parallel()
	adapter, emitter := newKernelTestAdapter(router.AdmissionOrdinary)
	uid := 1002
	snapshot := sensor.Snapshot{Kernel: &sensor.KernelState{FetchedAt: time.Now(), Status: acquire.KernelStatus{
		Changes: []acquire.KernelChange{
			{Seq: 1, AtUnixNano: time.Now().UnixNano(), Event: "uid_progress", UID: &uid, CoveredSeconds: 145800, NeededSeconds: 604800},
			{Seq: 2, AtUnixNano: time.Now().UnixNano(), Event: "loaded", Policy: "defenseclaw-observe-89abcdef"},
		},
	}}}
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	records := recordsNamed(emitter.records, "ai.runtime.kernel_policy")
	if len(records) != 2 {
		t.Fatalf("%d kernel_policy records", len(records))
	}
	progress := kernelRecordBody(t, records[0])
	if progress["defenseclaw.ai.runtime.kernel.event"] != "uid_progress" ||
		!sameJSONValue(progress["defenseclaw.ai.runtime.kernel.covered_hours"], 40.5) ||
		!sameJSONValue(progress["defenseclaw.ai.runtime.kernel.needed_hours"], float64(168)) || progress["user.id"] != "1002" {
		t.Fatalf("uid_progress %v", progress)
	}
	if _, ok := kernelRecordBody(t, records[1])["defenseclaw.ai.runtime.kernel.covered_hours"]; ok {
		t.Fatal("a policy change carries burn-in hours")
	}
}

// TestKernelMetrics: the events counter by owner, outcome and control
// (customer for the host's own policies, by the events a record stands
// for), and the state gauge's labels.
func TestKernelMetrics(t *testing.T) {
	t.Parallel()
	emitter := &kernelMetricEmitter{kernelTestEmitter: kernelTestEmitter{admission: router.AdmissionOrdinary}}
	adapter := &aiRuntimeV8Adapter{runtime: emitter, kernelCursor: &kernelChangeCursor{}, kernelDeltas: &kernelDeltaCursor{},
		kernelState: &kernelStateCursor{}}
	snapshot := fleetSnapshot(1, 1, 1)
	snapshot.KernelEvents = []sensor.KernelEvent{
		{Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read", Policy: "defenseclaw-controls-0a1b2c3d"},
		{Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read", Policy: "defenseclaw-controls-0a1b2c3d"},
		{Outcome: plane.OutcomeWouldBlock, Control: "kernel.persistence_write", Policy: "defenseclaw-controls-burnin-4e5f6a7b"},
	}
	snapshot.CustomerKernelEvents = customerTestEvents()
	if err := adapter.EmitSnapshot(t.Context(), snapshot); err != nil {
		t.Fatalf("EmitSnapshot() error = %v", err)
	}
	type series struct{ name, owner, outcome, control, value string }
	var got []series
	var state map[string]any
	for _, record := range emitter.metrics {
		data, ok := record.InstrumentData()
		if !ok {
			t.Fatalf("metric %s has no data", record.EventName())
		}
		object, err := data.Object()
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(object)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		attrs, _ := decoded["attributes"].(map[string]any)
		if record.EventName() == observability.EventName(observability.TelemetryInstrumentDefenseClawKernelState) {
			state = attrs
			continue
		}
		got = append(got, series{string(record.EventName()),
			stringOf(attrs["defenseclaw.ai.runtime.kernel.policy_owner"]), stringOf(attrs["defenseclaw.ai.runtime.kernel.outcome"]),
			stringOf(attrs["defenseclaw.metric.kernel_control"]), stringOf(decoded["value"])})
	}
	want := []series{
		{"defenseclaw.kernel.events", "customer", "blocked", "customer", "3"},
		{"defenseclaw.kernel.events", "customer", "observed", "customer", "1"},
		{"defenseclaw.kernel.events", "defenseclaw", "blocked", "kernel.ssh_private_key_read", "2"},
		{"defenseclaw.kernel.events", "defenseclaw", "would_block", "kernel.persistence_write", "1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events series\n got %v\nwant %v", got, want)
	}
	for key, want := range map[string]any{
		"defenseclaw.ai.runtime.kernel.helper_mode": "enforce", "defenseclaw.ai.runtime.kernel.approval": "stale",
		"defenseclaw.ai.runtime.kernel.paused": true, "defenseclaw.ai.runtime.plane_backend": "tetragon",
		"defenseclaw.ai.runtime.tetragon.installed": true,
	} {
		if !sameJSONValue(state[key], want) {
			t.Errorf("state %s = %v, want %v (%v)", key, state[key], want, state)
		}
	}
}

// TestKernelStateGaugeZeroesTheSeriesItLeaves: when the state changes the
// previous label set is recorded at 0, so an alert on the old state stops.
func TestKernelStateGaugeZeroesTheSeriesItLeaves(t *testing.T) {
	t.Parallel()
	cursor := &kernelStateCursor{}
	stale := &observability.MetricDefenseClawKernelStateInput{Value: 1, DefenseClawAIRuntimeKernelApproval: observability.Present("stale")}
	approved := &observability.MetricDefenseClawKernelStateInput{Value: 1, DefenseClawAIRuntimeKernelApproval: observability.Present("approved")}
	if got := cursor.next(stale); len(got) != 1 || got[0].Value != 1 {
		t.Fatalf("first %+v", got)
	}
	if got := cursor.next(stale); len(got) != 1 || got[0].Value != 1 {
		t.Fatalf("unchanged %+v", got)
	}
	got := cursor.next(approved)
	if len(got) != 2 || got[0].Value != 0 || got[1].Value != 1 {
		t.Fatalf("changed %+v", got)
	}
	if approval, _ := got[0].DefenseClawAIRuntimeKernelApproval.Get(); approval != "stale" {
		t.Fatalf("zeroed %q", approval)
	}
	if got := cursor.next(nil); len(got) != 1 || got[0].Value != 0 {
		t.Fatalf("gone %+v", got)
	}
	if got := cursor.next(nil); len(got) != 0 {
		t.Fatalf("still gone %+v", got)
	}
}

func stringOf(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

func TestKernelActionsMatchTheHelpersNames(t *testing.T) {
	t.Parallel()
	if !reflect.DeepEqual(runtimeKernelActions, tetragon.CustomerActionNames()) {
		t.Fatalf("gateway %v, helper %v", runtimeKernelActions, tetragon.CustomerActionNames())
	}
}
