//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

type recordingSink struct {
	hits   []kernelpolicy.Hit
	losses int
}

func (s *recordingSink) RecordHit(h kernelpolicy.Hit) { s.hits = append(s.hits, h) }
func (s *recordingSink) RecordLoss()                  { s.losses++ }

// The cleanup's exit code reaches the command's exit status: the lifecycle
// tells "Tetragon did not answer" (3) from a failed cleanup (1).
func TestCleanupResultKeepsTheExitCode(t *testing.T) {
	if err := cleanupResult(cleanupOK); err != nil {
		t.Fatalf("done: %v", err)
	}
	for _, code := range []int{cleanupUnreachable, cleanupFailed} {
		if err := cleanupResult(code); err == nil || exitCode(err) != code {
			t.Fatalf("code %d: err %v, exit status %d", code, err, exitCode(err))
		}
	}
	if got := exitCode(errors.New("plain")); got != 1 {
		t.Fatalf("a plain error exits %d", got)
	}
}

func TestHitTapCountsControlsEventsAndLoss(t *testing.T) {
	sink := &recordingSink{}
	tap := hitTap(sink)
	uid, root := 1001, 0
	at := time.Now()
	tap(plane.KernelBatch{Events: []plane.Event{
		{Policy: "defenseclaw-controls-0123abcd", UID: &uid, Path: "/home/alice/.ssh/id_rsa", Exe: "/usr/bin/cat", At: at},
		{Policy: "", UID: &uid, Path: "/home/alice/x"},                   // not a DefenseClaw policy event
		{Policy: "defenseclaw-controls-0123abcd", Path: "/home/alice/y"}, // uid not observed
		{Policy: "defenseclaw-observe-0123abcd", UID: &root, Path: "/etc/shadow"},
	}})
	if len(sink.hits) != 2 || sink.hits[0].UID != 1001 || sink.hits[0].Binary != "/usr/bin/cat" || !sink.hits[0].At.Equal(at) {
		t.Fatalf("hits = %+v", sink.hits)
	}
	if sink.losses != 0 {
		t.Fatalf("losses = %d", sink.losses)
	}
	tap(plane.KernelBatch{ThrottleStart: true})
	tap(plane.KernelBatch{Dropped: 3})
	tap(plane.KernelBatch{ThrottleStop: true})
	if sink.losses != 2 {
		t.Fatalf("a throttle start and a drop are loss, a stop is not: %d", sink.losses)
	}
}

// In off and consume nothing reconciles, but what the retire step has not
// removed yet still reaches the gateway (its orphan report), with the
// warnings and the change records of the retire.
func TestKernelStatusOfOffAndConsumeNamesWhatIsStillRecorded(t *testing.T) {
	for _, mode := range []kernelpolicy.Mode{kernelpolicy.ModeOff, kernelpolicy.ModeConsume} {
		status := kernelStatusOf(kernelpolicy.State{}, mode)
		if status.Available || status.Mode != string(mode) || status.Reason == "" || len(status.Policies) != 0 {
			t.Fatalf("%s: %+v", mode, status)
		}
	}
	state := kernelpolicy.State{
		FileState: kernelpolicy.FileState{
			KernelPolicy: "sha256:08b71155b713", Effective: "consume", UpdatedAt: time.Unix(1700000000, 0),
			Tetragon: kernelpolicy.TetragonStatus{Reason: "tetragon_unavailable: connection refused"},
			Warnings: []string{kernelpolicy.WarnTetragonUnavailable},
			Changes:  []kernelpolicy.Change{{Seq: 3, Event: kernelpolicy.EventOrphaned, Reason: "1 recorded policies not retired"}},
		},
		Loaded: []string{"defenseclaw-controls-0123abcd"},
	}
	status := kernelStatusOf(state, kernelpolicy.ModeConsume)
	if status.Available || len(status.Policies) != 1 || !status.Policies[0].Recorded || status.Policies[0].Family != "controls" {
		t.Fatalf("policies = %+v", status.Policies)
	}
	if len(status.Warnings) != 1 || len(status.Changes) != 1 || status.Changes[0].Event != "orphaned" || status.UpdatedUnixNano == 0 {
		t.Fatalf("status = %+v", status)
	}
	if status.Tetragon == nil || status.Tetragon.Connected {
		t.Fatalf("tetragon = %+v", status.Tetragon)
	}
	if off := kernelStatusOf(state, kernelpolicy.ModeOff); off.Tetragon != nil {
		t.Fatalf("off never talks to Tetragon's stream: %+v", off.Tetragon)
	}
}

func TestKernelStatusOfMapsTheState(t *testing.T) {
	uid := 1001
	lsm, keep := true, false
	state := kernelpolicy.State{
		FileState: kernelpolicy.FileState{
			KernelPolicy: "sha256:08b71155b713", Effective: "enforce", InSync: true, UpdatedAt: time.Unix(1700000000, 0),
			Tetragon: kernelpolicy.TetragonStatus{Reachable: true, Version: "v1.7.1", PID: 4242, LSM: &lsm, KeepSensorsOnExit: &keep},
			Policies: []kernelpolicy.PolicyStatus{{Name: "defenseclaw-controls-0123abcd", Family: kernelpolicy.FamilyControls,
				ObservedMode: kernelpolicy.LoadedEnforce, State: kernelpolicy.StateEnabled}},
			UIDs: []kernelpolicy.UIDStatus{
				{UID: 1001, Connectors: []string{"claudecode"}, State: kernelpolicy.UIDEnforcing, CoveredSeconds: 90000, NeededSeconds: 86400},
				{UID: 1002, State: kernelpolicy.UIDBurnIn, CoveredSeconds: 10, NeededSeconds: 86400},
				{UID: 1003, State: kernelpolicy.UIDInactive, Reason: kernelpolicy.ReasonNoAnchors},
			},
			Roots:     kernelpolicy.RootsStatus{Anchored: 2, OverLimit: 1, Observed: []kernelpolicy.Observed{{UID: 1001, Reason: kernelpolicy.ReasonIDEHosted, Count: 3}}},
			Overrides: map[kernelpolicy.Family]kernelpolicy.Override{kernelpolicy.FamilyControls: {Kind: kernelpolicy.OverrideMonitor}},
			Warnings:  []string{"kernel_policy_operator_override:controls"},
			Changes:   []kernelpolicy.Change{{Seq: 7, At: time.Unix(1700000001, 0), Event: kernelpolicy.EventLoaded, Policy: "defenseclaw-controls-0123abcd", UID: &uid}},
		},
		BurnIn: kernelpolicy.BurnInFile{UIDs: map[string]*kernelpolicy.UIDRecord{
			"1001": {Blocked: map[string]*kernelpolicy.HitStats{"kernel.ssh_private_key_read": {Count: 4}}},
			"1002": {WouldBlock: map[string]*kernelpolicy.HitStats{"kernel.persistence_write": {Count: 2}}},
		}},
		Pause: &kernelpolicy.PauseState{Pause: &kernelpolicy.Pause{Until: time.Unix(1700003600, 0), SetByUID: 0, SetAt: time.Unix(1700000000, 0), Reason: "incident"}},
	}
	status := kernelStatusOf(state, kernelpolicy.ModeEnforce)
	if !status.Available || !status.Applied || status.Mode != "enforce" || status.KernelPolicy != "sha256:08b71155b713" {
		t.Fatalf("status = %+v", status)
	}
	if status.Tetragon == nil || !status.Tetragon.Connected || status.Tetragon.PID != 4242 || *status.Tetragon.LSM != true {
		t.Fatalf("tetragon = %+v", status.Tetragon)
	}
	if len(status.Policies) != 1 || status.Policies[0].Mode != "enforce" || status.Policies[0].State != "enabled" || !status.Policies[0].Recorded {
		t.Fatalf("policies = %+v", status.Policies)
	}
	modes := map[int]string{}
	ready := map[int]bool{}
	for _, u := range status.Users {
		modes[u.UID], ready[u.UID] = u.Mode, u.Ready
	}
	if modes[1001] != "enforce" || modes[1002] != "burnin" || modes[1003] != "observe_only" || !ready[1001] || ready[1002] {
		t.Fatalf("users = %+v", status.Users)
	}
	if status.Users[1].Hits["kernel.persistence_write"] != 2 {
		t.Fatalf("would-block hits are per control: %+v", status.Users[1])
	}
	if status.Counters["would_block"] != 2 || status.Counters["blocked"] != 4 || status.Counters["roots_over_limit"] != 1 ||
		status.Counters["roots_anchored"] != 2 || status.Counters["observed_not_enforced"] != 3 {
		t.Fatalf("counters = %v", status.Counters)
	}
	if status.Pause == nil || status.Pause.Reason != "incident" || status.Pause.UntilUnixNano != time.Unix(1700003600, 0).UnixNano() {
		t.Fatalf("pause = %+v", status.Pause)
	}
	if len(status.Overrides) != 1 || status.Overrides[0] != "controls" || len(status.Warnings) != 1 {
		t.Fatalf("overrides %v warnings %v", status.Overrides, status.Warnings)
	}
	if len(status.Changes) != 1 || status.Changes[0].Seq != 7 || status.Changes[0].Event != "loaded" || *status.Changes[0].UID != 1001 {
		t.Fatalf("changes = %+v", status.Changes)
	}
	// Nothing a user did reaches the broker: no path, no command line.
	for _, u := range status.Users {
		for key := range u.Hits {
			if key != "kernel.ssh_private_key_read" && key != "kernel.persistence_write" {
				t.Fatalf("hit key %q", key)
			}
		}
	}
}

func TestLoadedPolicyMapsModeAndState(t *testing.T) {
	cases := []struct {
		mode  pb.TracingPolicyMode
		state pb.TracingPolicyState
		want  kernelpolicy.LoadedMode
		st    kernelpolicy.LoadedState
	}{
		{pb.TracingPolicyMode_TP_MODE_ENFORCE, pb.TracingPolicyState_TP_STATE_ENABLED, kernelpolicy.LoadedEnforce, kernelpolicy.StateEnabled},
		{pb.TracingPolicyMode_TP_MODE_MONITOR, pb.TracingPolicyState_TP_STATE_LOAD_ERROR, kernelpolicy.LoadedMonitor, kernelpolicy.StateLoadError},
		{pb.TracingPolicyMode_TP_MODE_MONITOR_ONLY, pb.TracingPolicyState_TP_STATE_DISABLED, kernelpolicy.LoadedMonitorOnly, kernelpolicy.StateDisabled},
		{pb.TracingPolicyMode_TP_MODE_UNKNOWN, pb.TracingPolicyState_TP_STATE_LOADING, kernelpolicy.LoadedUnknown, kernelpolicy.StateLoading},
	}
	for _, tc := range cases {
		got := loadedPolicy(&pb.TracingPolicyStatus{Name: "n", Mode: tc.mode, State: tc.state, Error: "e"})
		if got.Mode != tc.want || got.State != tc.st || got.Error != "e" || got.Name != "n" {
			t.Errorf("%v/%v -> %+v", tc.mode, tc.state, got)
		}
	}
	if loadedPolicy(&pb.TracingPolicyStatus{Mode: 99}).Mode.Enforcing() {
		t.Fatal("a mode this build does not know must not count as enforcing")
	}
}
