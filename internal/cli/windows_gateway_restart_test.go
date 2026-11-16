// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeWindowsGatewayService plays a sequence of SCM states: each query
// takes the next one and repeats the last. stop and start record the call
// and move the service to the states the SCM reports next; a start with no
// afterStart runs (StartPending, then Running).
type fakeWindowsGatewayService struct {
	states     []windowsServiceState
	afterStop  []windowsServiceState
	afterStart []windowsServiceState
	stopErr    error
	startErr   error
	calls      []string
}

func (f *fakeWindowsGatewayService) state() (windowsServiceState, error) {
	state := f.states[0]
	if len(f.states) > 1 {
		f.states = f.states[1:]
	}
	return state, nil
}

func (f *fakeWindowsGatewayService) stop() error {
	f.calls = append(f.calls, "stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.states = f.afterStop
	return nil
}

func (f *fakeWindowsGatewayService) start() error {
	f.calls = append(f.calls, "start")
	if f.startErr != nil {
		return f.startErr
	}
	f.states = f.afterStart
	if len(f.states) == 0 {
		f.states = []windowsServiceState{windowsServiceStartPending, windowsServiceRunning}
	}
	return nil
}

// A gateway whose process runs or is starting may hold the old credential or
// config, so it is restarted; StartPending is waited out first (the SCM
// refuses a stop while a service starts). Only a stopped gateway, or one
// stopping on its own, needs no restart.
func TestWindowsGatewayRestartTreatsAStartingGatewayAsLive(t *testing.T) {
	stopped := []windowsServiceState{windowsServiceStopPending, windowsServiceStopped}
	for _, tc := range []struct {
		name      string
		states    []windowsServiceState
		restarted bool
	}{
		{"running", []windowsServiceState{windowsServiceRunning}, true},
		{"start pending, then running", []windowsServiceState{windowsServiceStartPending, windowsServiceStartPending, windowsServiceRunning}, true},
		{"paused", []windowsServiceState{windowsServicePaused}, true},
		{"continue pending, then running", []windowsServiceState{windowsServiceContinuePending, windowsServiceRunning}, true},
		{"pause pending, then paused", []windowsServiceState{windowsServicePausePending, windowsServicePaused}, true},
		{"start pending, then stopped (the start failed)", []windowsServiceState{windowsServiceStartPending, windowsServiceStopped}, false},
		{"stopped", []windowsServiceState{windowsServiceStopped}, false},
		{"stop pending, then stopped", stopped, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeWindowsGatewayService{states: tc.states, afterStop: stopped}
			restarted, err := restartWindowsGatewayService(service, "DefenseClawGateway", time.Second, time.Millisecond)
			if err != nil || restarted != tc.restarted {
				t.Fatalf("restarted = %v, %v; want %v", restarted, err, tc.restarted)
			}
			want := ""
			if tc.restarted {
				want = "stop,start"
			}
			if got := strings.Join(service.calls, ","); got != want {
				t.Fatalf("SCM calls = %q, want %q", got, want)
			}
		})
	}
}

func TestWindowsGatewayRecoveryArmsOnlyForAStopAttempt(t *testing.T) {
	for _, tc := range []struct {
		name      string
		states    []windowsServiceState
		wantCalls string
		wantArmed bool
	}{
		{name: "intentionally stopped", states: []windowsServiceState{windowsServiceStopped}},
		{name: "stopping independently", states: []windowsServiceState{windowsServiceStopPending, windowsServiceStopped}},
		{name: "running", states: []windowsServiceState{windowsServiceRunning}, wantCalls: "stop,start", wantArmed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeWindowsGatewayService{
				states:    tc.states,
				afterStop: []windowsServiceState{windowsServiceStopped},
			}
			armed := false
			_, err := restartWindowsGatewayServiceBeforeStop(service, "DefenseClawGateway", time.Second, time.Millisecond, func() error {
				if len(service.calls) != 0 {
					t.Fatal("recovery armed after service state changed")
				}
				armed = true
				return nil
			})
			if err != nil || armed != tc.wantArmed || strings.Join(service.calls, ",") != tc.wantCalls {
				t.Fatalf("armed=%t SCM calls=%v error=%v", armed, service.calls, err)
			}
		})
	}
	service := &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceRunning}}
	if _, err := restartWindowsGatewayServiceBeforeStop(service, "DefenseClawGateway", time.Second, time.Millisecond,
		func() error { return errors.New("helper died") }); err == nil || len(service.calls) != 0 {
		t.Fatalf("failed recovery arm still stopped the gateway: calls=%v err=%v", service.calls, err)
	}
	service = &fakeWindowsGatewayService{
		states:  []windowsServiceState{windowsServiceRunning},
		stopErr: errors.New("service stopped independently"),
	}
	if _, err := restartWindowsGatewayServiceBeforeStop(service, "DefenseClawGateway", time.Second, time.Millisecond,
		func() error { return nil }); !errors.Is(err, errWindowsGatewayStopRefused) {
		t.Fatalf("SCM stop refusal was not distinguished from an interrupted restart: %v", err)
	}
}

// A gateway that stays in StartPending, or does not stop, is restart_failed:
// never a success with no restart.
func TestWindowsGatewayRestartFailsWhenItCannotRestart(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service *fakeWindowsGatewayService
		want    string
	}{
		{"stuck starting", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceStartPending}}, "stayed in service state 2"},
		{"stuck stopping after the stop", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceRunning}, afterStop: []windowsServiceState{windowsServiceStopPending}}, "stayed in service state 3"},
		{"stop refused", &fakeWindowsGatewayService{states: []windowsServiceState{windowsServiceRunning}, stopErr: errors.New("access denied")}, "stop DefenseClawGateway: access denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restarted, err := restartWindowsGatewayService(tc.service, "DefenseClawGateway", 20*time.Millisecond, time.Millisecond)
			if restarted || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("restarted = %v, %v; want an error naming %q", restarted, err, tc.want)
			}
		})
	}
}

// G-small loop round 2: the SCM accepts a start once it launched the process.
// A gateway that then falls back to Stopped, stays StartPending, or settles
// anywhere but Running is down, so the restart is restart_failed, never
// restarted. Only a gateway that reaches Running is restarted.
func TestWindowsGatewayRestartWaitsUntilTheGatewayRuns(t *testing.T) {
	stopped := []windowsServiceState{windowsServiceStopPending, windowsServiceStopped}
	for _, tc := range []struct {
		name       string
		afterStart []windowsServiceState
		startErr   error
		want       string
	}{
		{name: "start pending, then running", afterStart: []windowsServiceState{windowsServiceStartPending, windowsServiceStartPending, windowsServiceRunning}},
		{name: "running at once", afterStart: []windowsServiceState{windowsServiceRunning}},
		{name: "start pending, then stopped", afterStart: []windowsServiceState{windowsServiceStartPending, windowsServiceStopped}, want: "went to state 1 instead of running"},
		{name: "stopped at once", afterStart: []windowsServiceState{windowsServiceStopped}, want: "went to state 1 instead of running"},
		{name: "start pending, then stopping", afterStart: []windowsServiceState{windowsServiceStartPending, windowsServiceStopPending, windowsServiceStopped}, want: "went to state 3 instead of running"},
		{name: "start pending, then paused", afterStart: []windowsServiceState{windowsServiceStartPending, windowsServicePaused}, want: "went to state 7 instead of running"},
		{name: "stuck starting", afterStart: []windowsServiceState{windowsServiceStartPending}, want: "stayed in service state 2"},
		{name: "start refused", startErr: errors.New("the service did not respond"), want: "start DefenseClawGateway: the service did not respond"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeWindowsGatewayService{
				states: []windowsServiceState{windowsServiceRunning}, afterStop: stopped,
				afterStart: tc.afterStart, startErr: tc.startErr,
			}
			restarted, err := restartWindowsGatewayService(service, "DefenseClawGateway", 20*time.Millisecond, time.Millisecond)
			if tc.want == "" {
				if err != nil || !restarted {
					t.Fatalf("restarted = %v, %v; want a restart", restarted, err)
				}
			} else if restarted || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("restarted = %v, %v; want an error naming %q", restarted, err, tc.want)
			}
			if got := strings.Join(service.calls, ","); got != "stop,start" {
				t.Fatalf("SCM calls = %q, want stop,start", got)
			}
		})
	}
}

// The recovery after a failed restart starts only a stopped gateway, never
// stops a live one, and reports a start only once the gateway runs.
func TestWindowsGatewayRecoveryStartsOnlyAStoppedGatewayAndWaitsForRunning(t *testing.T) {
	for _, tc := range []struct {
		name       string
		states     []windowsServiceState
		afterStart []windowsServiceState
		started    bool
		calls      string
		want       string
	}{
		{name: "running", states: []windowsServiceState{windowsServiceRunning}},
		{name: "starting", states: []windowsServiceState{windowsServiceStartPending}},
		{name: "paused", states: []windowsServiceState{windowsServicePaused}},
		{name: "stopped, then runs", states: []windowsServiceState{windowsServiceStopped}, started: true, calls: "start"},
		{name: "stopping, then stopped, then runs", states: []windowsServiceState{windowsServiceStopPending, windowsServiceStopped}, started: true, calls: "start"},
		{name: "stopped, start falls back to stopped", states: []windowsServiceState{windowsServiceStopped},
			afterStart: []windowsServiceState{windowsServiceStartPending, windowsServiceStopped}, calls: "start", want: "went to state 1 instead of running"},
		{name: "stopped, start stuck", states: []windowsServiceState{windowsServiceStopped},
			afterStart: []windowsServiceState{windowsServiceStartPending}, calls: "start", want: "stayed in service state 2"},
		{name: "stuck stopping", states: []windowsServiceState{windowsServiceStopPending}, want: "stayed in service state 3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeWindowsGatewayService{states: tc.states, afterStart: tc.afterStart}
			started, err := startWindowsGatewayServiceIfStopped(service, "DefenseClawGateway", 20*time.Millisecond, time.Millisecond)
			if tc.want == "" {
				if err != nil || started != tc.started {
					t.Fatalf("started = %v, %v; want %v", started, err, tc.started)
				}
			} else if started || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("started = %v, %v; want an error naming %q", started, err, tc.want)
			}
			if got := strings.Join(service.calls, ","); got != tc.calls {
				t.Fatalf("SCM calls = %q, want %q", got, tc.calls)
			}
		})
	}
}

// The bundle receipt and restore read a gateway in StartPending as running
// (its process exists); a stopped or stopping one is not.
func TestWindowsServiceProcessLive(t *testing.T) {
	for state, live := range map[windowsServiceState]bool{
		windowsServiceStopped: false, windowsServiceStopPending: false,
		windowsServiceStartPending: true, windowsServiceRunning: true,
		windowsServiceContinuePending: true, windowsServicePausePending: true, windowsServicePaused: true,
	} {
		if got := windowsServiceProcessLive(state); got != live {
			t.Fatalf("state %d live = %v, want %v", state, got, live)
		}
	}
}
