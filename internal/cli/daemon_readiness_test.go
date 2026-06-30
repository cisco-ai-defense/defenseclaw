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

func TestWaitForGatewayReadinessWaitsForRunningAPI(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		state := gateway.StateStarting
		if probes.Add(1) >= 3 {
			state = gateway.StateRunning
		}
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: state},
		})
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		time.Second,
		5*time.Millisecond,
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("waitForGatewayReadiness() error = %v", err)
	}
	if !ready {
		t.Fatal("waitForGatewayReadiness() ready = false, want true")
	}
	if snap.API.State != gateway.StateRunning {
		t.Fatalf("API state = %q, want %q", snap.API.State, gateway.StateRunning)
	}
	if got := probes.Load(); got != 3 {
		t.Fatalf("health probes = %d, want 3", got)
	}
}

func TestWaitForGatewayReadinessReturnsStableStartingOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateStarting},
		})
	}))
	defer srv.Close()

	snap, ready, err := waitForGatewayReadiness(
		srv.Client(),
		srv.URL,
		50*time.Millisecond,
		5*time.Millisecond,
		func() bool { return true },
	)
	if err != nil {
		t.Fatalf("waitForGatewayReadiness() error = %v", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
	}
	if snap.API.State != gateway.StateStarting {
		t.Fatalf("API state = %q, want %q", snap.API.State, gateway.StateStarting)
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
		func() bool { return true },
	)
	if err == nil || !strings.Contains(err.Error(), "bind failed") {
		t.Fatalf("error = %v, want API startup diagnostic", err)
	}
	if ready {
		t.Fatal("waitForGatewayReadiness() ready = true, want false")
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
