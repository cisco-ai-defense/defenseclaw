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

// setupStepServer reports connector setup step 1..4, one step every
// stepEvery, then a running guardrail; stall pins it at step 3 of 4.
func setupStepServer(t *testing.T, stepEvery time.Duration, stall bool) *httptest.Server {
	t.Helper()
	began := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		step := 1 + int(time.Since(began)/stepEvery)
		if stall && step > 3 {
			step = 3
		}
		snap := readinessSnapshot(gateway.StateStarting, gateway.StateDisabled)
		if step > 4 {
			snap.Guardrail = gateway.SubsystemHealth{State: gateway.StateRunning}
		} else {
			snap.Guardrail.Details = map[string]interface{}{
				"setup_connector": []string{"claudecode", "codex", "hermes", "opencode"}[step-1],
				"setup_step":      step,
				"setup_total":     4,
			}
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func withReadinessProgressFactor(t *testing.T, factor time.Duration) {
	t.Helper()
	previous := readinessProgressFactor
	readinessProgressFactor = factor
	t.Cleanup(func() { readinessProgressFactor = previous })
}

// GAP-1556: a start whose connector setup keeps finishing steps is not
// stopped at the readiness timeout, and its progress is reported.
func TestWaitForGatewayReadinessExtendsWhileConnectorSetupProgresses(t *testing.T) {
	withReadinessProgressFactor(t, 20)
	srv := setupStepServer(t, 60*time.Millisecond, false)
	var reported atomic.Int32
	_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, 150*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, reportProgress: func(time.Duration, string) { reported.Add(1) }},
		func() bool { return true })
	if err != nil || !ready {
		t.Fatalf("waitForGatewayReadiness() = ready %v, err %v; want ready after 4 setup steps", ready, err)
	}

	// A hook cold start (no progress reporter) keeps the plain timeout.
	srv = setupStepServer(t, 60*time.Millisecond, false)
	_, ready, err = waitForGatewayReadiness(srv.Client(), srv.URL, 150*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true}, func() bool { return true })
	if ready || err == nil {
		t.Fatalf("cold start readiness = ready %v, err %v; want the plain timeout", ready, err)
	}
}

func TestWaitForGatewayReadinessStalledSetupNamesTheStep(t *testing.T) {
	withReadinessProgressFactor(t, 20)
	srv := setupStepServer(t, 20*time.Millisecond, true)
	_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, 100*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, reportProgress: func(time.Duration, string) {}},
		func() bool { return true })
	if ready || err == nil || !strings.Contains(err.Error(), "last step: setting up connector hermes (3 of 4)") {
		t.Fatalf("stalled setup = ready %v, err %v; want a timeout naming the step", ready, err)
	}
}

// GAP-1850: a retried slow agent probe is progress, so start and restart keep
// waiting while the retries run instead of stopping the gateway.
func TestWaitForGatewayReadinessExtendsWhileASlowProbeRetries(t *testing.T) {
	withReadinessProgressFactor(t, 20)
	began := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempt := 1 + int(time.Since(began)/(100*time.Millisecond))
		snap := readinessSnapshot(gateway.StateStarting, gateway.StateDisabled)
		if attempt > 3 {
			snap.Guardrail = gateway.SubsystemHealth{State: gateway.StateRunning}
		} else {
			snap.Guardrail.Details = map[string]interface{}{
				"setup_connector": "codex", "setup_step": 3, "setup_total": 8, "setup_attempt": attempt,
			}
		}
		_ = json.NewEncoder(w).Encode(snap)
	}))
	t.Cleanup(srv.Close)
	_, ready, err := waitForGatewayReadiness(srv.Client(), srv.URL, 250*time.Millisecond, 5*time.Millisecond,
		daemonReadinessRequirements{guardrailEnabled: true, reportProgress: func(time.Duration, string) {}},
		func() bool { return true })
	if err != nil || !ready {
		t.Fatalf("waitForGatewayReadiness() = ready %v, err %v; want ready after the third attempt", ready, err)
	}
	step := connectorSetupStep(gateway.SubsystemHealth{State: gateway.StateStarting, Details: map[string]interface{}{
		"setup_connector": "codex", "setup_step": 3.0, "setup_total": 8.0, "setup_attempt": 2.0,
	}})
	if step != "setting up connector codex (3 of 8), attempt 2" {
		t.Fatalf("connectorSetupStep() = %q", step)
	}
	if limit := startReadinessProgressFactor * platformStartReadinessTimeout; limit < 180*time.Second {
		t.Fatalf("progress cap %s cannot fit three 20 s Codex probe attempts plus the other connectors", limit)
	}
}
