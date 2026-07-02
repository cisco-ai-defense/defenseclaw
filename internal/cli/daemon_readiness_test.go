// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

func readinessSnapshot(guardrailState, gatewayState gateway.SubsystemState) gateway.HealthSnapshot {
	return gateway.HealthSnapshot{
		API:       gateway.SubsystemHealth{State: gateway.StateRunning},
		Gateway:   gateway.SubsystemHealth{State: gatewayState},
		Watcher:   gateway.SubsystemHealth{State: gateway.StateDisabled},
		Guardrail: gateway.SubsystemHealth{State: guardrailState},
		Telemetry: gateway.SubsystemHealth{State: gateway.StateDisabled},
		Sinks:     gateway.SubsystemHealth{State: gateway.StateDisabled},
	}
}

func TestWaitForGatewayReadinessWaitsForDelayedGuardrailRunning(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		state := gateway.StateDisabled
		if probes.Add(1) >= 3 {
			state = gateway.StateRunning
		}
		_ = json.NewEncoder(w).Encode(readinessSnapshot(state, gateway.StateDisabled))
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("waitForGatewayReadiness() error = %v", err)
	}
	if !ready {
		t.Fatal("waitForGatewayReadiness() ready = false, want true")
	}
	if snap.Guardrail.State != gateway.StateRunning {
		t.Fatalf("guardrail state = %q, want %q", snap.Guardrail.State, gateway.StateRunning)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("health probes = %d, want 3", got)
	}
}

func TestWaitForGatewayReadinessLeavesSlowLiveProcessStarting(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		50*time.Millisecond,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("waitForGatewayReadiness() error = %v, want nil", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
	if snap.Guardrail.State != gateway.StateDisabled {
		t.Fatalf("guardrail state = %q, want %q", snap.Guardrail.State, gateway.StateDisabled)
	}
}

type fakeReadinessProcess struct {
	running   bool
	pid       int
	stopCalls int
	stopErr   error
}

func (p *fakeReadinessProcess) IsRunning() (bool, int) {
	return p.running, p.pid
}

func (p *fakeReadinessProcess) Stop(time.Duration) error {
	p.stopCalls++
	return p.stopErr
}

func TestWaitForStartedDaemonDoesNotStopSlowLiveProcess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer srv.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		25*time.Millisecond,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
	)
	if err != nil || ready {
		t.Fatalf("waitForStartedDaemon() ready = %v, error = %v", ready, err)
	}
	if process.stopCalls != 0 {
		t.Fatalf("Stop() calls = %d, want 0 for a slow live process", process.stopCalls)
	}
}

func TestWaitForStartedDaemonStopsProcessOnFatalReadinessError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateError, LastError: "bind failed"},
		})
	}))
	defer srv.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(
		process,
		42,
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
	)
	if err == nil || !strings.Contains(err.Error(), "bind failed") || ready {
		t.Fatalf("waitForStartedDaemon() ready = %v, error = %v, want fatal bind error", ready, err)
	}
	if process.stopCalls != 1 {
		t.Fatalf("Stop() calls = %d, want 1 for a fatal readiness error", process.stopCalls)
	}
}

func TestPrintDaemonStartResultUsesActualTimeout(t *testing.T) {
	out := captureStdout(t, func() {
		printDaemonStartResult(42, gateway.HealthSnapshot{}, false, 3*time.Second)
	})
	if !strings.Contains(out, "still starting after 3s") {
		t.Fatalf("output = %q, want actual timeout", out)
	}
}

func TestWaitForGatewayReadinessFailsFastWhenProcessExits(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		probes.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
		func() bool { return false },
	)
	if err == nil || !strings.Contains(err.Error(), "exited before readiness") {
		t.Fatalf("error = %v, want process-exit diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
	if got := probes.Load(); got != 0 {
		t.Fatalf("health probes = %d, want 0 after confirmed process exit", got)
	}
}

func TestWaitForGatewayReadinessFailsFastOnAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{
				State:     gateway.StateError,
				LastError: "bind failed",
			},
		})
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{},
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("error = %v, want API startup diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
}

func TestWaitForGatewayReadinessFailsFastOnGuardrailError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateError, gateway.StateDisabled)
		snap.Guardrail.LastError = "connector setup failed"
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "connector setup failed") {
		t.Fatalf("error = %v, want guardrail failure diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
}

func TestWaitForGatewayReadinessAcceptsConfiguredDisabledGuardrail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateRunning))
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: false},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("disabled guardrail readiness = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessWaitsForDisabledGuardrailFinalization(t *testing.T) {
	startedAt := time.Now()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled)
		snap.StartedAt = startedAt
		snap.Guardrail.Since = startedAt
		if probes.Add(1) >= 2 {
			snap.Guardrail.Since = startedAt.Add(time.Millisecond)
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: false},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("disabled guardrail finalization readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestWaitForGatewayReadinessAcceptsHookOnlyGatewayDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateRunning, gateway.StateDisabled))
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("hook-only gateway disabled readiness = %v, error = %v", ready, err)
	}
}

func TestWaitForGatewayReadinessRejectsPreviousProcessGeneration(t *testing.T) {
	startAttemptedAt := time.Now()
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
		if probes.Add(1) < 3 {
			snap.StartedAt = startAttemptedAt.Add(-time.Minute)
		} else {
			snap.StartedAt = startAttemptedAt.Add(time.Millisecond)
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{
			guardrailEnabled: true,
			startedNotBefore: startAttemptedAt,
		},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("new process generation readiness = %v, error = %v", ready, err)
	}
	if snap.StartedAt.Before(startAttemptedAt) {
		t.Fatalf("accepted stale started_at %s before %s", snap.StartedAt, startAttemptedAt)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("health probes = %d, want 3", got)
	}
}

func TestWaitForGatewayReadinessWaitsForConfiguredWatcher(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
		snap.Watcher.State = gateway.StateStarting
		if probes.Add(1) >= 2 {
			snap.Watcher.State = gateway.StateRunning
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, watcherEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("configured watcher readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestWaitForGatewayReadinessAllowsRecoveringGatewayError(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		snap := readinessSnapshot(gateway.StateRunning, gateway.StateError)
		snap.Gateway.LastError = "upstream unavailable"
		if probes.Add(1) >= 2 {
			snap.Gateway = gateway.SubsystemHealth{State: gateway.StateRunning}
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	defer srv.Close()

	_, ready, err := waitForGatewayReadiness(
		srv.Client(), srv.URL, time.Second, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true},
		func() bool { return true },
	)
	if err != nil || !ready {
		t.Fatalf("recovering gateway readiness = %v, error = %v", ready, err)
	}
	if got := probes.Load(); got != 2 {
		t.Fatalf("health probes = %d, want 2", got)
	}
}

func TestFetchSidecarHealthParsesLargeMultiConnectorDocument(t *testing.T) {
	want := gateway.HealthSnapshot{
		Gateway: gateway.SubsystemHealth{
			State: gateway.StateRunning,
			Details: map[string]interface{}{
				"inventory": strings.Repeat("x", 2200),
			},
		},
		API: gateway.SubsystemHealth{State: gateway.StateRunning},
		Connectors: []gateway.ConnectorHealth{
			{Name: "codex", State: gateway.StateRunning},
			{Name: "claudecode", State: gateway.StateRunning},
		},
	}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) <= 2000 {
		t.Fatalf("fixture length = %d, want > 2000", len(payload))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	got, err := fetchSidecarHealth(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("fetchSidecarHealth() error = %v", err)
	}
	if got.API.State != gateway.StateRunning {
		t.Fatalf("API state = %q, want %q", got.API.State, gateway.StateRunning)
	}
	if len(got.Connectors) != 2 {
		t.Fatalf("connectors = %d, want 2", len(got.Connectors))
	}
}

func TestFetchSidecarHealthRejectsOversizedDocument(t *testing.T) {
	payload := []byte(`{"padding":"` + strings.Repeat("x", gatewayHealthDocumentMaxBytes) + `"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	_, err := fetchSidecarHealth(srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error = %v, want bounded-document diagnostic", err)
	}
}
