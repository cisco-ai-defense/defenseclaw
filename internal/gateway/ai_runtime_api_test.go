// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// TestAIRuntimeEndpointReportsDisabledRatherThanErroring pins that the planes
// being switched off is a state the API describes, not a failure.
func TestAIRuntimeEndpointReportsDisabledRatherThanErroring(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	recorder := httptest.NewRecorder()
	api.handleAIRuntime(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/ai-usage/runtime", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	var response aiRuntimeResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.Enabled {
		t.Error("a nil service reported enabled")
	}
	if response.Findings == nil || response.Planes == nil {
		t.Error("disabled response omitted the empty collections, which forces callers to nil-check")
	}
}

// TestAIRuntimeScanIsUnavailableRatherThanNotFoundWhenDisabled pins the status
// the CLI turns into an actionable "enable it first".
func TestAIRuntimeScanIsUnavailableRatherThanNotFoundWhenDisabled(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	recorder := httptest.NewRecorder()
	api.handleAIRuntimeScan(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/runtime/scan", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
}

func TestAIRuntimeRejectsWrongMethods(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	for _, test := range []struct {
		handler func(http.ResponseWriter, *http.Request)
		method  string
		path    string
	}{
		{api.handleAIRuntime, http.MethodPost, "/api/v1/ai-usage/runtime"},
		{api.handleAIRuntimeScan, http.MethodGet, "/api/v1/ai-usage/runtime/scan"},
	} {
		recorder := httptest.NewRecorder()
		test.handler(recorder, httptest.NewRequest(test.method, test.path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s = %d, want 405", test.method, test.path, recorder.Code)
		}
	}
}

// TestRenderCarriesCoverageAndCorrelationAlongsideFindings pins that a caller
// cannot read findings without also reading how much of the host was visible,
// and what the inventory did or did not say.
func TestRenderCarriesCoverageAndCorrelationAlongsideFindings(t *testing.T) {
	t.Parallel()
	scanned := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	rendered := renderAIRuntimeSnapshot(sensor.Snapshot{
		ScannedAt:               scanned,
		ProcessesObserved:       412,
		ProcessesSkipped:        7,
		ConnectionsObserved:     55,
		ConnectionsUnattributed: 48,
		Degraded:                true,
		DegradedReasons:         []string{"agent actions unavailable: eslogger not found"},
		Planes: []sensor.PlaneHealth{
			{Plane: platform.PlaneA, Available: true, Running: true, Mechanism: "ps(1)"},
			{Plane: platform.PlaneC, Available: false, Reason: "eslogger not found"},
		},
		Findings: []sensor.Finding{{
			FindingID: "run-abc", PID: 42, Process: "python3", Score: 65,
			Severity: scoring.SeverityHigh,
			Signals:  []scoring.Signal{{ID: "inference_heartbeat", Weight: 25}},
			Correlation: correlate.Result{
				Verdict: correlate.VerdictUnobserved,
				Reason:  "no discovery snapshot has been produced yet",
			},
		}},
	})

	if rendered.ScannedAt != "2026-09-09T12:00:00Z" {
		t.Errorf("ScannedAt = %q", rendered.ScannedAt)
	}
	if rendered.ConnectionsUnattributed != 48 {
		t.Errorf("ConnectionsUnattributed = %d; coverage must travel with the findings",
			rendered.ConnectionsUnattributed)
	}
	if !rendered.Degraded || len(rendered.DegradedReasons) != 1 {
		t.Errorf("degradation was not carried: %+v", rendered.DegradedReasons)
	}
	if len(rendered.Planes) != 2 || rendered.Planes[1].Reason == "" {
		t.Errorf("plane health lost its reason: %+v", rendered.Planes)
	}
	if rendered.Planes[0].Name != platform.PlaneA.Name() {
		t.Errorf("plane name = %q, want %q", rendered.Planes[0].Name, platform.PlaneA.Name())
	}
	if len(rendered.Findings) != 1 {
		t.Fatalf("findings = %d", len(rendered.Findings))
	}
	correlation := rendered.Findings[0].Correlation
	if correlation.Verdict != string(correlate.VerdictUnobserved) || correlation.Reason == "" {
		t.Fatalf("correlation = %+v; an unobserved inventory must still say so", correlation)
	}
}

// TestDetachAIRuntimeRemovesTheCapabilityNotJustTheLabel pins the disable
// path. On a hot reload from enabled to disabled the poll loop stops, but the
// service pointer used to stay reachable: GET kept reporting the planes
// enabled and POST /runtime/scan kept polling them, reading argv and sockets
// on a host whose operator had just switched that off. Turning a collector
// off has to remove the capability, not only the label.
func TestDetachAIRuntimeRemovesTheCapabilityNotJustTheLabel(t *testing.T) {
	service, err := sensor.New(sensor.Options{
		Config:   config.AIRuntimeConfig{Enabled: true},
		Platform: stubRuntimePlatform{},
		Resolver: sensor.StaticResolver{},
	})
	if err != nil {
		t.Fatalf("sensor.New(): %v", err)
	}

	api := &APIServer{}
	sidecar := &Sidecar{apiServer: api}
	sidecar.aiRuntimeMu.Lock()
	sidecar.aiRuntime = service
	sidecar.aiRuntimeMu.Unlock()
	api.SetAIRuntimeService(service)

	if leased, release := api.leaseAIRuntime(); leased == nil {
		release()
		t.Fatal("precondition: the API has no runtime service to detach")
	} else {
		release()
	}

	sidecar.detachAIRuntime()

	leased, release := api.leaseAIRuntime()
	release()
	if leased != nil {
		t.Error("the API can still reach the runtime service after disable: " +
			"POST /runtime/scan would keep reading argv and sockets")
	}
	sidecar.aiRuntimeMu.RLock()
	held := sidecar.aiRuntime
	sidecar.aiRuntimeMu.RUnlock()
	if held != nil {
		t.Error("the sidecar still holds the disabled runtime service")
	}

	// And the endpoint now reports the disabled state rather than erroring.
	recorder := httptest.NewRecorder()
	api.handleAIRuntimeScan(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/ai-usage/runtime/scan", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Errorf("scan after disable = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
}

type stubRuntimePlatform struct{}

func (stubRuntimePlatform) OSType() string     { return "linux" }
func (stubRuntimePlatform) Name() string       { return "stub" }
func (stubRuntimePlatform) WideCoverage() bool { return false }
func (stubRuntimePlatform) Capabilities() map[platform.Plane]platform.Capability {
	return map[platform.Plane]platform.Capability{
		platform.PlaneA: {Plane: platform.PlaneA, Available: true, Mechanism: "stub"},
		platform.PlaneB: {Plane: platform.PlaneB, Available: true, Mechanism: "stub"},
		platform.PlaneC: {Plane: platform.PlaneC, Available: false, Reason: "stub"},
	}
}

// TestFindingsAreEmittedOncePerPollNotOncePerHealthTick pins that the health
// cadence does not multiply findings. The ticker runs far faster than the
// poll interval on purpose; emitting the snapshot on every tick re-sent the
// same unchanged findings with a fresh occurrence id each time, and the
// packaged dashboard counts those records with count_over_time.
func TestFindingsAreEmittedOncePerPollNotOncePerHealthTick(t *testing.T) {
	t.Parallel()

	poll := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	var lastEmitted time.Time

	// Before any poll completes there is nothing to emit, and the zero scan
	// time must not read as "older than last time" either.
	if shouldEmitAIRuntimeSnapshot(time.Time{}, lastEmitted) {
		t.Fatal("emitted a snapshot before any poll completed")
	}

	if !shouldEmitAIRuntimeSnapshot(poll, lastEmitted) {
		t.Fatal("the first completed poll was not emitted")
	}
	lastEmitted = poll

	// Many health ticks pass with no new poll behind them.
	for tick := range 12 {
		if shouldEmitAIRuntimeSnapshot(poll, lastEmitted) {
			t.Fatalf("health tick %d re-emitted an unchanged snapshot", tick+1)
		}
	}

	// The next poll completes and is emitted exactly once.
	next := poll.Add(time.Hour)
	if !shouldEmitAIRuntimeSnapshot(next, lastEmitted) {
		t.Fatal("a newly completed poll was not emitted")
	}
	lastEmitted = next
	if shouldEmitAIRuntimeSnapshot(next, lastEmitted) {
		t.Fatal("the same poll was emitted twice")
	}
}
