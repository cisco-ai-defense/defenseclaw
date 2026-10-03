// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// GAP-2022: an interactive start or restart keeps a live gateway that is
// still starting at the readiness deadline instead of stopping it; a
// gateway that reports a fatal error is still stopped.
func TestWaitForStartedDaemonKeepsSlowLiveProcessForInteractiveStart(t *testing.T) {
	starting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(readinessSnapshot(gateway.StateDisabled, gateway.StateDisabled))
	}))
	defer starting.Close()

	process := &fakeReadinessProcess{running: true, pid: 42}
	_, ready, err := waitForStartedDaemon(process, 42, starting.Client(), starting.URL,
		25*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, keepSlowStart: true})
	if ready || !errors.Is(err, errGatewayStillStarting) || !strings.Contains(err.Error(), "remained STARTING") {
		t.Fatalf("ready = %v, error = %v, want still starting", ready, err)
	}
	if process.stopCalls != 0 {
		t.Fatalf("stop calls = %d, want the slow gateway left running", process.stopCalls)
	}
	msg := reportGatewayStillStarting(err, 42, "/tmp/gateway.log", nil, errors.New("no config")).Error()
	for _, want := range []string{"PID 42", "still starting and was left running", "defenseclaw-gateway status", "defenseclaw-gateway restart"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message %q lacks %q", msg, want)
		}
	}

	fatal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(gateway.HealthSnapshot{
			API: gateway.SubsystemHealth{State: gateway.StateError, LastError: "bind failed"},
		})
	}))
	defer fatal.Close()
	process = &fakeReadinessProcess{running: true, pid: 42}
	_, _, err = waitForStartedDaemon(process, 42, fatal.Client(), fatal.URL,
		25*time.Millisecond, 5*time.Millisecond, daemonReadinessRequirements{keepSlowStart: true})
	if err == nil || errors.Is(err, errGatewayStillStarting) || process.stopCalls != 1 {
		t.Fatalf("error = %v, stop calls = %d, want the failed gateway stopped", err, process.stopCalls)
	}
}
