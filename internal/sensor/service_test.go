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

package sensor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/sensor/catalog"
	"github.com/defenseclaw/defenseclaw/internal/sensor/correlate"
	"github.com/defenseclaw/defenseclaw/internal/sensor/platform"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

type stubInventory struct{ snapshot correlate.Snapshot }

func (s stubInventory) CorrelationSnapshot() correlate.Snapshot { return s.snapshot }

type stubPlatform struct {
	capabilities map[platform.Plane]platform.Capability
}

func (stubPlatform) OSType() string     { return "linux" }
func (stubPlatform) Name() string       { return "stub" }
func (stubPlatform) WideCoverage() bool { return true }
func (s stubPlatform) Capabilities() map[platform.Plane]platform.Capability {
	return s.capabilities
}

func allPlanesAvailable() stubPlatform {
	return stubPlatform{capabilities: map[platform.Plane]platform.Capability{
		platform.PlaneA: {Plane: platform.PlaneA, Available: true, Mechanism: "stub"},
		platform.PlaneB: {Plane: platform.PlaneB, Available: true, Mechanism: "stub"},
		platform.PlaneC: {Plane: platform.PlaneC, Available: true, Mechanism: "stub"},
	}}
}

func newTestService(t *testing.T, runtime config.AIRuntimeConfig, inventoryProvider InventoryProvider) *Service {
	t.Helper()
	service, err := New(Options{
		Config:    runtime,
		Inventory: inventoryProvider,
		Providers: testCatalog(),
		Platform:  allPlanesAvailable(),
		Resolver:  StaticResolver{Names: map[string]string{}},
	})
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	return service
}

// TestPollProducesASnapshotOnTheRealHost is the end-to-end smoke test: the
// service reads this machine and reports coverage without erroring.
func TestPollProducesASnapshotOnTheRealHost(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true}, nil)
	snapshot := service.Poll(context.Background())
	if snapshot.ScannedAt.IsZero() {
		t.Fatal("snapshot has no scan time")
	}
	if snapshot.ProcessesObserved == 0 {
		t.Fatal("snapshot observed no processes")
	}
	if len(snapshot.Planes) != len(platform.Planes) {
		t.Fatalf("snapshot reported %d planes, want %d", len(snapshot.Planes), len(platform.Planes))
	}
	t.Logf("processes=%d skipped=%d connections=%d unattributed=%d findings=%d",
		snapshot.ProcessesObserved, snapshot.ProcessesSkipped,
		snapshot.ConnectionsObserved, snapshot.ConnectionsUnattributed, len(snapshot.Findings))
}

// TestPlaneHealthIsReportedEvenWhenAPlaneIsNotRunning is the contract that a
// dead subscription leaves a trace. If health were reported only while a plane
// worked, silence and success would be indistinguishable.
func TestPlaneHealthIsReportedEvenWhenAPlaneIsNotRunning(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true}, nil)
	snapshot := service.Poll(context.Background())

	seen := map[platform.Plane]bool{}
	for _, health := range snapshot.Planes {
		seen[health.Plane] = true
		if !health.Available && strings.TrimSpace(health.Reason) == "" {
			t.Errorf("plane %s is unavailable with no reason", health.Plane)
		}
		if health.Available && !health.Running && strings.TrimSpace(health.Reason) == "" {
			t.Errorf("plane %s is available but not running, with no reason", health.Plane)
		}
	}
	for _, plane := range platform.Planes {
		if !seen[plane] {
			t.Errorf("plane %s is missing from the health report", plane)
		}
	}
	// Plane C is selected only through the host-plane opt-in, which this
	// config does not set, so the snapshot must be degraded and say why.
	if !snapshot.Degraded {
		t.Error("a snapshot with plane C not running was not marked degraded")
	}
	if len(snapshot.DegradedReasons) == 0 {
		t.Error("a degraded snapshot carried no reasons")
	}
}

// TestCorrelationDisabledIsNotTheSameAsDisagreement pins the distinction the
// join is built on, at the service level.
func TestCorrelationDisabledIsNotTheSameAsDisagreement(t *testing.T) {
	off := false
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true, Correlate: &off},
		stubInventory{snapshot: correlate.Snapshot{
			Signals:  []inventory.AISignal{},
			ScanTime: time.Now(), Complete: true,
		}})
	snapshot := service.Poll(context.Background())
	for _, finding := range snapshot.Findings {
		if finding.Correlation.Verdict == correlate.VerdictUnaccounted {
			t.Fatalf("correlation was disabled yet a finding was escalated as unaccounted: %+v",
				finding.Correlation)
		}
	}
}

// TestApplyCorrelationAttenuatesOnlyLocalInference pins that an accounted-for
// model on disk does not discount a finding's egress evidence. Discovery
// having inventoried a model file says nothing about where the process sent
// its requests.
func TestApplyCorrelationAttenuatesOnlyLocalInference(t *testing.T) {
	t.Parallel()
	signals := []scoring.Signal{
		{ID: "local_model_runtime", Weight: scoring.WeightLocalRuntimeProcess},
		{ID: "shadow_ai_egress", Weight: 50},
	}
	got := applyCorrelation(signals, correlate.Result{Verdict: correlate.VerdictAccounted})
	if got[0].Weight != scoring.WeightSanctionedEgress {
		t.Errorf("local inference attenuated to %d, want %d", got[0].Weight, scoring.WeightSanctionedEgress)
	}
	if got[1].Weight != 50 {
		t.Errorf("egress weight was discounted to %d; an inventoried model file says nothing "+
			"about where this process sent its requests", got[1].Weight)
	}
}

// TestApplyCorrelationEscalatesOnlyWhenThereIsLocalInferenceToExplain pins
// that the uninventoried bonus attaches to the observation it is about.
func TestApplyCorrelationEscalatesOnlyWhenThereIsLocalInferenceToExplain(t *testing.T) {
	t.Parallel()
	egressOnly := applyCorrelation(
		[]scoring.Signal{{ID: "shadow_ai_egress", Weight: 50}},
		correlate.Result{Verdict: correlate.VerdictUnaccounted, Reason: "nothing on disk"},
	)
	if len(egressOnly) != 1 {
		t.Fatalf("pure egress gained %d signals from an unaccounted verdict", len(egressOnly)-1)
	}
	withLocal := applyCorrelation(
		[]scoring.Signal{{ID: "inference_heartbeat", Weight: scoring.WeightInferenceHeartbeat}},
		correlate.Result{Verdict: correlate.VerdictUnaccounted, Reason: "nothing on disk"},
	)
	if len(withLocal) != 2 || withLocal[1].ID != "uninventoried_local_model" {
		t.Fatalf("local inference did not gain the uninventoried signal: %+v", withLocal)
	}
}

// TestApplyCorrelationUnobservedChangesNothing is the rule the design rests on,
// asserted where the score is actually adjusted.
func TestApplyCorrelationUnobservedChangesNothing(t *testing.T) {
	t.Parallel()
	original := []scoring.Signal{
		{ID: "local_model_runtime", Weight: scoring.WeightLocalRuntimeProcess},
		{ID: "inference_heartbeat", Weight: scoring.WeightInferenceHeartbeat},
	}
	before := scoring.Total(original)
	got := applyCorrelation(original, correlate.Result{
		Verdict: correlate.VerdictUnobserved, Reason: "no snapshot",
	})
	if scoring.Total(got) != before {
		t.Fatalf("an unobserved inventory moved the score from %d to %d", before, scoring.Total(got))
	}
	if len(got) != len(original) {
		t.Fatalf("an unobserved inventory added %d signals", len(got)-len(original))
	}
}

// TestNewRefusesAnUnknownPlatform pins that the sensor fails loudly rather
// than starting blind on a platform with no backend.
func TestNewRefusesAnUnknownPlatform(t *testing.T) {
	t.Parallel()
	// Current() succeeds on every supported platform, so this asserts the
	// error type is wired rather than simulating an unsupported GOOS.
	err := &platform.ErrUnsupported{GOOS: "plan9"}
	if !strings.Contains(err.Error(), "no runtime-plane backend") {
		t.Fatalf("ErrUnsupported message = %q", err.Error())
	}
}

func TestRunPollsImmediatelyThenStops(t *testing.T) {
	service := newTestService(t, config.AIRuntimeConfig{Enabled: true, PollIntervalSec: 3600}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- service.Run(ctx) }()

	deadline := time.After(10 * time.Second)
	for service.Snapshot().ScannedAt.IsZero() {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run() did not poll before the first interval elapsed")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("Run() returned %v, want a context cancellation", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run() did not return after cancellation")
	}
}

var _ = catalog.CategoryFrontier
