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
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

func runtimeIntp(value int) *int { return &value }

func decodeJSONMap(t *testing.T, value interface{}) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func sortedKeys(object map[string]interface{}) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func enforcingKernelState() *sensor.KernelState {
	return &sensor.KernelState{
		Reachable: true, FetchedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Status: acquire.KernelStatus{
			Available: true, Mode: "enforce", KernelPolicy: "sha256:3f9c2a7d41b0", Applied: true,
			Users: []acquire.KernelUserStatus{
				{UID: 4242, Mode: "enforce", Ready: true, Connectors: []string{"claudecode", "codex"}},
				{UID: 4243, Mode: "burnin", Connectors: []string{"claudecode"}},
				{UID: 4244, Mode: "observe_only", Reason: "guardrail_observe", Connectors: []string{"codex"}},
			},
			Pause: &acquire.KernelPause{UntilUnixNano: time.Date(2026, 10, 7, 14, 5, 0, 0, time.UTC).UnixNano(), SetByUID: 0},
		},
	}
}

// TestRenderCarriesTheTetragonBackendOnPlaneC pins the backend contract the
// CLI, the doctor row and the TUI decode: snake_case keys, loss always
// stated, and the kernel floor while the helper's reconciler runs.
func TestRenderCarriesTheTetragonBackendOnPlaneC(t *testing.T) {
	t.Parallel()
	rendered := renderAIRuntimeSnapshot(sensor.Snapshot{
		ScannedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Planes: []sensor.PlaneHealth{
			{Plane: platform.PlaneA, Available: true, Running: true, Mechanism: "helper"},
			{Plane: platform.PlaneC, Available: true, Running: true,
				Mechanism: "Tetragon v1.7.1 (gRPC) + fanotify (via the sensor helper)",
				Backend: &plane.Backend{
					Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "enforce",
					Socket: "/var/run/tetragon/tetragon.sock", EventsLost: 3, LossKnown: true,
					Policies: []plane.BackendPolicy{
						{Name: "defenseclaw-controls-1a2b3c4d", Mode: "enforce", State: "enabled"},
						{Name: "defenseclaw-observe-0a1b2c3d", Mode: "monitor", State: "load_error", Error: "lsm not available"},
					},
				}},
		},
		HostPlaneContainerEvents: 7,
		Kernel:                   enforcingKernelState(),
	})
	body := decodeJSONMap(t, rendered)
	if body["host_plane_container_events"] != float64(7) {
		t.Fatalf("host_plane_container_events = %v", body["host_plane_container_events"])
	}
	planes := body["planes"].([]interface{})
	if _, ok := planes[0].(map[string]interface{})["backend"]; ok {
		t.Fatal("plane a carried a backend")
	}
	backend := planes[1].(map[string]interface{})["backend"].(map[string]interface{})
	if got, want := sortedKeys(backend), []string{"events_lost", "kernel_floor", "kind", "loss_known", "mode", "policies", "socket", "version"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("backend keys = %v, want %v", got, want)
	}
	if backend["kind"] != "tetragon" || backend["version"] != "v1.7.1" || backend["events_lost"] != float64(3) || backend["loss_known"] != true {
		t.Fatalf("backend = %v", backend)
	}
	policies := backend["policies"].([]interface{})
	if len(policies) != 2 || policies[1].(map[string]interface{})["error"] != "lsm not available" {
		t.Fatalf("policies = %v", policies)
	}
	floor := backend["kernel_floor"].(map[string]interface{})
	if floor["mode"] != "enforce" || floor["enrolled_users"] != float64(3) || floor["enforced_users"] != float64(1) ||
		floor["burn_in_users"] != float64(1) || floor["paused_until"] != "2026-10-07T14:05:00Z" {
		t.Fatalf("kernel_floor = %v", floor)
	}
}

// TestRenderWithoutABackendKeepsThePlaneShape pins that every gateway but a
// managed Linux one renders exactly what it did before the backend existed.
func TestRenderWithoutABackendKeepsThePlaneShape(t *testing.T) {
	t.Parallel()
	rendered := renderAIRuntimeSnapshot(sensor.Snapshot{
		Planes: []sensor.PlaneHealth{{Plane: platform.PlaneC, Available: true, Running: true, Mechanism: "Endpoint Security"}},
		Findings: []sensor.Finding{{FindingID: "run-1", PID: 9, Process: "python3", Score: 40,
			Severity: scoring.SeverityMedium}},
	})
	body := decodeJSONMap(t, rendered)
	planeEntry := body["planes"].([]interface{})[0].(map[string]interface{})
	if got, want := sortedKeys(planeEntry), []string{"available", "mechanism", "name", "plane", "running"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("plane keys = %v, want %v", got, want)
	}
	for _, key := range []string{"host_plane_container_events", "host_plane_hook_unexpected"} {
		if _, ok := body[key]; ok {
			t.Fatalf("%s rendered on a host without a container count", key)
		}
	}
	finding := body["findings"].([]interface{})[0].(map[string]interface{})
	for _, key := range []string{"exe", "user_id", "login_id", "connector", "agent_identity_id", "identity_verified", "not_enforced_reason", "activities"} {
		if _, ok := finding[key]; ok {
			t.Fatalf("a plane A finding rendered %s", key)
		}
	}
	// A fallback backend says why Tetragon is not used, with no floor.
	fallback := renderAIRuntimeBackend(&plane.Backend{Kind: plane.BackendNative, Mode: "consume",
		FallbackReason: "tetragon_unavailable: no /var/run/tetragon/tetragon-info.json"}, nil)
	if fallback == nil || fallback.KernelFloor != nil || fallback.FallbackReason == "" {
		t.Fatalf("fallback backend = %+v", fallback)
	}
	consume := enforcingKernelState()
	consume.Status.Mode = "consume"
	if renderKernelFloor(consume) != nil {
		t.Fatal("a consume-mode helper rendered a kernel floor")
	}
}

// TestRenderCarriesRuntimeIdentityAndActivities pins 12.1 and 9.3 on the
// API: the kernel uid, the login uid only under root, the connector, the
// observe-only reason, and each activity's source, kernel outcome and hook
// join (absent where the join does not apply).
func TestRenderCarriesRuntimeIdentityAndActivities(t *testing.T) {
	t.Parallel()
	rendered := renderAIRuntimeSnapshot(sensor.Snapshot{
		Kernel: enforcingKernelState(),
		Findings: []sensor.Finding{{
			FindingID: "chain-1", PID: 100, Process: "claude", AgentName: "claude", Score: 90,
			Severity: scoring.SeverityCritical, Exe: "/home/dev/.local/share/claude/versions/2.1.292",
			UID: runtimeIntp(0), AUID: runtimeIntp(4242), User: "root", Connector: "claudecode",
			Activities: []sensor.RuntimeActivity{
				{Tactic: tactics.CredentialAccess, Source: plane.SourceTetragon, UID: runtimeIntp(4242),
					Outcome: plane.OutcomeBlocked, Control: "kernel.ssh_private_key_read",
					Hook: &sensor.HookJoin{Seen: true, Confidence: sensor.HookJoinExact, SessionID: "sess-1", ToolInvocationID: "tool-1"}},
				{Tactic: tactics.Exfiltration, Source: plane.SourceTetragon, Hook: &sensor.HookJoin{}},
				{Tactic: tactics.Persistence, Source: plane.SourceFanotify},
			},
		}, {
			FindingID: "chain-2", PID: 200, Process: "tmux", AgentName: "tmux", Score: 60,
			Severity: scoring.SeverityHigh, UID: runtimeIntp(4242), NotEnforcedReason: tactics.RootHeuristic,
		}, {
			FindingID: "chain-3", PID: 300, Process: "codex", AgentName: "codex", Score: 60,
			Severity: scoring.SeverityHigh, UID: runtimeIntp(4999), Connector: "codex",
		}, {
			FindingID: "chain-4", PID: 400, Process: "codex", AgentName: "codex", Score: 60,
			Severity: scoring.SeverityHigh, UID: runtimeIntp(4244), Connector: "codex",
		}},
	})
	root := rendered.Findings[0]
	if root.UserID != "0" || root.LoginID != "4242" || root.Connector != "claudecode" || root.Exe == "" || root.NotEnforcedReason != "not_enrolled" {
		t.Fatalf("root finding = %+v", root)
	}
	if len(root.Activities) != 3 {
		t.Fatalf("activities = %+v", root.Activities)
	}
	credential := root.Activities[0]
	if credential.EventSource != "tetragon" || credential.UserID != "4242" || credential.LoginID != "" ||
		credential.KernelOutcome != "blocked" || credential.KernelControl != "kernel.ssh_private_key_read" ||
		credential.HookSeen == nil || !*credential.HookSeen || credential.HookJoin != "exact" || credential.ToolInvocationID != "tool-1" {
		t.Fatalf("credential activity = %+v", credential)
	}
	if exfil := root.Activities[1]; exfil.HookSeen == nil || *exfil.HookSeen || exfil.HookJoin != "" || exfil.UserID != "0" || exfil.LoginID != "4242" {
		t.Fatalf("unjoined activity = %+v, want hook_seen=false with the root's identity", exfil)
	}
	if persistence := decodeJSONMap(t, root.Activities[2]); persistence["hook_seen"] != nil {
		t.Fatalf("an activity without a join rendered hook_seen: %v", persistence)
	}
	if heuristic := rendered.Findings[1]; heuristic.NotEnforcedReason != tactics.RootHeuristic || heuristic.Connector != "" || heuristic.AgentIdentityID != "" {
		t.Fatalf("heuristic root = %+v", heuristic)
	}
	if unenrolled := rendered.Findings[2]; unenrolled.NotEnforcedReason != "not_enrolled" || unenrolled.IdentityVerified {
		t.Fatalf("unenrolled root = %+v", unenrolled)
	}
	if observeOnly := rendered.Findings[3]; observeOnly.NotEnforcedReason != "guardrail_observe" || !observeOnly.IdentityVerified {
		t.Fatalf("observe-only user = %+v", observeOnly)
	}
}

// TestKernelPolicyHealthIsOmittedUnlessItApplies pins policy.kernel's
// presence rules and its fields.
func TestKernelPolicyHealthIsOmittedUnlessItApplies(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 12, 0, 30, 0, time.UTC)
	if kernelPolicyHealth(nil, now) != nil {
		t.Fatal("no helper state rendered policy.kernel")
	}
	if kernelPolicyHealth(&sensor.KernelState{Reachable: false}, now) != nil {
		t.Fatal("a helper that never answered rendered policy.kernel")
	}
	consume := &sensor.KernelState{Reachable: true, FetchedAt: now, Status: acquire.KernelStatus{Mode: "consume", Reason: "no reconciler in consume"}}
	if kernelPolicyHealth(consume, now) != nil {
		t.Fatal("a consume-mode helper with nothing loaded rendered policy.kernel")
	}

	state := enforcingKernelState()
	state.Status.Overrides = []string{"controls"}
	state.Status.Warnings = []string{"kernel_policy_operator_override:controls", "kernel_enforce_paused"}
	section := kernelPolicyHealth(state, now)
	if section["kernel_policy"] != "sha256:3f9c2a7d41b0" || section["applied"] != true || section["mode"] != "enforce" ||
		section["paused_until"] != "2026-10-07T14:05:00Z" || section["helper_reachable"] != true {
		t.Fatalf("policy.kernel = %v", section)
	}
	if counts := section["mode_by_uid_count"].(map[string]int); counts["enforce"] != 1 || counts["burnin"] != 1 || counts["observe_only"] != 1 {
		t.Fatalf("mode_by_uid_count = %v", counts)
	}
	if !reflect.DeepEqual(section["overrides"], []string{"controls"}) {
		t.Fatalf("overrides = %v", section["overrides"])
	}
	if _, ok := section["orphaned"]; ok {
		t.Fatal("an enforcing helper reported orphans")
	}
	state.Status.Pause = &acquire.KernelPause{UntilReboot: true}
	if kernelPolicyHealth(state, now)["paused_until"] != "reboot" {
		t.Fatal("an until-reboot pause was not rendered")
	}
}

// TestKernelOrphansFollowSpec78 pins the orphan rules doctor fails on.
func TestKernelOrphansFollowSpec78(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	policies := []acquire.KernelPolicyStatus{
		{Name: "defenseclaw-controls-1a2b3c4d", Recorded: true, State: "enabled"},
		{Name: "defenseclaw-observe-0a1b2c3d", Recorded: true, State: "unloading"},
		{Name: "defenseclaw-foo-00000000", Recorded: false, State: "enabled"},
	}
	// Recorded names still loaded after the retire step in consume.
	consume := &sensor.KernelState{Reachable: true, FetchedAt: now,
		Status: acquire.KernelStatus{Mode: "consume", Policies: policies}}
	if got := kernelPolicyHealth(consume, now)["orphaned"]; !reflect.DeepEqual(got, []string{"defenseclaw-controls-1a2b3c4d", "defenseclaw-observe-0a1b2c3d"}) {
		t.Fatalf("consume orphans = %v", got)
	}
	// A reconciling helper owns its policies.
	observe := &sensor.KernelState{Reachable: true, FetchedAt: now,
		Status: acquire.KernelStatus{Available: true, Mode: "observe", Policies: policies}}
	if got := kernelOrphans(observe, now); got != nil {
		t.Fatalf("observe orphans = %v", got)
	}
	// The helper went away: a restart's seconds are not an orphan, a minute is.
	gone := &sensor.KernelState{Reachable: false, FetchedAt: now, UnreachableSince: now,
		Status: acquire.KernelStatus{Available: true, Mode: "observe", Policies: policies}}
	if got := kernelOrphans(gone, now.Add(10*time.Second)); got != nil {
		t.Fatalf("orphans during a restart = %v", got)
	}
	if got := kernelOrphans(gone, now.Add(2*time.Minute)); !reflect.DeepEqual(got, []string{"defenseclaw-controls-1a2b3c4d"}) {
		t.Fatalf("orphans of a stopped helper = %v", got)
	}
}

// TestPolicyHealthBodyWithoutTheRuntimeIsUnchanged pins that /health's
// policy object is the generation's own when nothing reports kernel policy.
func TestPolicyHealthBodyWithoutTheRuntimeIsUnchanged(t *testing.T) {
	t.Parallel()
	policy := PolicyHealth{EffectiveDigest: "sha256:abc", Generation: 3}
	if got := (&APIServer{}).policyHealthBody(policy); !reflect.DeepEqual(got, policy) {
		t.Fatalf("policyHealthBody = %#v, want the PolicyHealth unchanged", got)
	}
}
