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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
)

func customerSnapshot() sensor.Snapshot {
	kernel := enforcingKernelState()
	kernel.Status.Approval = "stale"
	kernel.Status.Users = append(kernel.Status.Users,
		acquire.KernelUserStatus{UID: 4245, Mode: "burnin", CoveredSeconds: 40 * 3600, BurnInSeconds: 168 * 3600},
		acquire.KernelUserStatus{UID: 4246, Mode: "burnin", CoveredSeconds: 160*3600 + 1800, BurnInSeconds: 168 * 3600})
	return sensor.Snapshot{
		ScannedAt: time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC),
		Planes: []sensor.PlaneHealth{{Plane: platform.PlaneC, Available: true, Running: true,
			Mechanism: "Tetragon v1.7.1 (gRPC) + fanotify (via the sensor helper)",
			Backend: &plane.Backend{Kind: plane.BackendTetragon, Version: "v1.7.1", Mode: "enforce",
				CustomerPolicies: []plane.CustomerPolicy{{Name: "10-file-sensitive", Mode: "enforce", State: "enabled",
					CustomerEvents: plane.CustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2, Attributed: 7, Gated: 2}}},
				CustomerEvents: plane.CustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2, Attributed: 7, Gated: 2},
			}}},
		Kernel: kernel,
		RecentCustomerKernelEvents: []sensor.CustomerKernelEvent{{
			At: time.Date(2026, 10, 7, 11, 59, 0, 0, time.UTC), Policy: "10-file-sensitive", HookType: "lsm",
			Function: "file_open", Action: "override", PolicyMode: "enforce", Outcome: plane.OutcomeBlocked,
			Target: "/home/dev/tg2work/dccert-block-marker", Tags: []string{"files"}, Count: 2, PID: 1303, Process: "cat",
			Exe: "/usr/bin/cat", UID: runtimeIntp(4242), User: "dev", AgentName: "claude", Connector: "claudecode",
			RootPID: 1300, SessionRootPID: 1300, ToolPID: 1302,
			Hook: &sensor.HookJoin{Seen: true, Confidence: sensor.HookJoinExact, SessionID: "sess-1", ToolInvocationID: "tool-1",
				Action: "alert", RuleIDs: []string{"R-1"}},
		}},
	}
}

// TestRenderCarriesTheCustomerPolicies: the runtime API serves the customer
// policies' counts on the backend and the latest attributed events, each with
// its agent, user and hook decision; /health carries the counts only.
func TestRenderCarriesTheCustomerPolicies(t *testing.T) {
	t.Parallel()
	body := decodeJSONMap(t, renderAIRuntimeSnapshot(customerSnapshot()))
	backend := body["planes"].([]interface{})[0].(map[string]interface{})["backend"].(map[string]interface{})
	policies := backend["customer_policies"].([]interface{})
	if got, want := sortedKeys(policies[0].(map[string]interface{})),
		[]string{"attributed", "container", "dropped", "forwarded", "gated", "mode", "name", "seen", "state"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("customer policy keys %v", got)
	}
	if events := backend["customer_events"].(map[string]interface{}); events["attributed"] != float64(7) || events["seen"] != float64(12) {
		t.Fatalf("customer events %v", events)
	}
	floor := backend["kernel_floor"].(map[string]interface{})
	if floor["approval"] != "stale" || floor["next_ready_hours"] != 7.5 {
		t.Fatalf("kernel floor %v", floor)
	}
	events := body["customer_kernel_events"].([]interface{})
	event := events[0].(map[string]interface{})
	for key, want := range map[string]interface{}{
		"policy": "10-file-sensitive", "hook_type": "lsm", "function": "file_open", "action": "override",
		"policy_mode": "enforce", "outcome": "blocked", "target": "/home/dev/tg2work/dccert-block-marker", "count": float64(2),
		"process": "cat", "user_id": "4242", "agent_name": "claude", "connector": "claudecode", "tool_pid": float64(1302),
		"hook_seen": true, "hook_join": "exact", "hook_action": "alert", "session_id": "sess-1", "tool_invocation_id": "tool-1",
		"at": "2026-10-07T11:59:00Z",
	} {
		if event[key] != want {
			t.Fatalf("%s = %v, want %v (%v)", key, event[key], want, event)
		}
	}
	if id, ok := event["agent_identity_id"].(string); ok && !strings.HasPrefix(id, "agt-") {
		t.Fatalf("agent identity %v", id)
	}

	// /health: counts on the backend, never the events.
	s := &Sidecar{health: NewSidecarHealth()}
	s.publishAIRuntimeHealth(customerSnapshot())
	health := decodeJSONMap(t, s.health.Snapshot())
	details := health["ai_runtime"].(map[string]interface{})["details"].(map[string]interface{})
	if _, ok := details["customer_kernel_events"]; ok {
		t.Fatal("/health carries customer events")
	}
	planeC := details["planes"].(map[string]interface{})["c"].(map[string]interface{})
	if _, ok := planeC["backend"].(map[string]interface{})["customer_policies"]; !ok {
		t.Fatalf("/health backend %v", planeC["backend"])
	}
}

// TestRenderWithoutCustomerData: no customer events key without one, and a
// native backend carries no customer counts unless some were counted.
func TestRenderWithoutCustomerData(t *testing.T) {
	t.Parallel()
	body := decodeJSONMap(t, renderAIRuntimeSnapshot(sensor.Snapshot{
		Planes: []sensor.PlaneHealth{{Plane: platform.PlaneC, Available: true, Running: true,
			Backend: &plane.Backend{Kind: plane.BackendNative, Mode: "off"}}},
	}))
	if _, ok := body["customer_kernel_events"]; ok {
		t.Fatal("customer_kernel_events rendered with none")
	}
	backend := body["planes"].([]interface{})[0].(map[string]interface{})["backend"].(map[string]interface{})
	for _, key := range []string{"customer_policies", "customer_events"} {
		if _, ok := backend[key]; ok {
			t.Fatalf("%s on a native backend with nothing counted", key)
		}
	}
	if kernelNextReadyHours([]acquire.KernelUserStatus{{UID: 1, Ready: true, BurnInSeconds: 10}, {UID: 2, Mode: "observe_only", BurnInSeconds: 10}}) != nil {
		t.Fatal("next_ready_hours with no user measuring")
	}
}

func TestHookJoinActionAndRuleIDs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		resp agentHookResponse
		want string
	}{
		{agentHookResponse{Action: "allow"}, "allow"},
		{agentHookResponse{Action: "alert"}, "alert"},
		{agentHookResponse{Action: "confirm"}, "alert"},
		{agentHookResponse{Action: "allow", WouldBlock: true}, "alert"},
	} {
		if got := hookJoinAction(tc.resp); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.resp, got, tc.want)
		}
	}
	if got := firstRuleIDs([]string{" R-1 ", "", "R-2", "R-3", "R-4"}); !reflect.DeepEqual(got, []string{"R-1", "R-2", "R-3"}) {
		t.Fatalf("rule ids %v", got)
	}
}
