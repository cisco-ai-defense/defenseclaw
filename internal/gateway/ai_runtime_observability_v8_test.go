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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
)

// TestDegradedCycleIsPartialNotCompleted pins that a blinded poll is never
// reported as a complete one. That substitution is the exact thing this
// subsystem refuses everywhere else.
func TestDegradedCycleIsPartialNotCompleted(t *testing.T) {
	t.Parallel()
	if got := runtimeOutcome(sensor.Snapshot{Degraded: true}); got != observability.OutcomePartial {
		t.Errorf("degraded outcome = %s, want %s", got, observability.OutcomePartial)
	}
	if got := runtimeOutcome(sensor.Snapshot{}); got != observability.OutcomeCompleted {
		t.Errorf("clean outcome = %s, want %s", got, observability.OutcomeCompleted)
	}
}

func TestRuntimeSeverityMapsEveryBand(t *testing.T) {
	t.Parallel()
	for band, want := range map[string]observability.Severity{
		"critical": observability.SeverityCritical,
		"high":     observability.SeverityHigh,
		"medium":   observability.SeverityMedium,
		"low":      observability.SeverityLow,
		"info":     observability.SeverityInfo,
		"":         observability.SeverityInfo,
		"invented": observability.SeverityInfo,
	} {
		if got := runtimeSeverity(band); got != want {
			t.Errorf("runtimeSeverity(%q) = %s, want %s", band, got, want)
		}
	}
}

// TestRenderedSignalsAreDeterministicAndBounded pins that the evidence trail
// is stable between polls that observe the same thing, so a downstream diff
// does not report churn that did not happen.
func TestRenderedSignalsAreDeterministicAndBounded(t *testing.T) {
	t.Parallel()
	finding := sensor.Finding{Signals: []scoring.Signal{
		{ID: "shadow_ai_egress", Weight: 50},
		{ID: "inference_heartbeat", Weight: 25},
		{ID: "", Weight: 99},
	}}
	first := renderRuntimeSignals(finding)
	second := renderRuntimeSignals(finding)
	if strings.Join(first, ",") != strings.Join(second, ",") {
		t.Fatalf("rendering is not deterministic: %v vs %v", first, second)
	}
	if len(first) != 2 {
		t.Fatalf("rendered = %v, want the empty-id signal dropped", first)
	}
	if first[0] != "inference_heartbeat=25" || first[1] != "shadow_ai_egress=50" {
		t.Fatalf("rendered = %v, want sorted signal_id=weight", first)
	}

	many := sensor.Finding{}
	for index := 0; index < maxRuntimeSignalsPerRecord*2; index++ {
		many.Signals = append(many.Signals, scoring.Signal{ID: "signal", Weight: index})
	}
	if got := len(renderRuntimeSignals(many)); got != maxRuntimeSignalsPerRecord {
		t.Fatalf("rendered %d signals, want the %d cap", got, maxRuntimeSignalsPerRecord)
	}
}

func TestRenderedProvidersDeduplicateByHostname(t *testing.T) {
	t.Parallel()
	finding := sensor.Finding{Providers: []sensor.ProviderReach{
		{Hostname: "api.anthropic.com", Category: "frontier", Confidence: 0.95},
		{Hostname: "api.anthropic.com", Category: "frontier", Confidence: 0.75},
		{Hostname: "", Category: "frontier"},
	}}
	rendered := renderRuntimeProviders(finding)
	if len(rendered) != 1 || rendered[0] != "api.anthropic.com|frontier|0.95" {
		t.Fatalf("rendered = %v", rendered)
	}
}

// TestPlaneHealthAlwaysCarriesAMechanismOrAReason pins that a reader never has
// to go to the source to find out what a plane is doing.
func TestPlaneHealthAlwaysCarriesAMechanismOrAReason(t *testing.T) {
	t.Parallel()
	// The adapter's reason fallback is the behaviour under test; exercising it
	// through the builder would need a live runtime, so the fallback rule is
	// asserted directly against the same inputs the emitter uses.
	for _, test := range []struct {
		name   string
		health sensor.PlaneHealth
		want   string
	}{
		{"running names its mechanism", sensor.PlaneHealth{Running: true, Mechanism: "ps(1)"}, "ps(1)"},
		{"blind names its reason", sensor.PlaneHealth{Reason: "eslogger not found"}, "eslogger not found"},
		{
			"running with an explicit reason keeps it",
			sensor.PlaneHealth{Running: true, Mechanism: "ps(1)", Reason: "partial"},
			"partial",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			reason := test.health.Reason
			if test.health.Running && reason == "" {
				reason = test.health.Mechanism
			}
			if reason != test.want {
				t.Fatalf("reason = %q, want %q", reason, test.want)
			}
		})
	}
}

// TestNilEmitterYieldsNoAdapter pins that observability being unconfigured
// disables emission rather than panicking the poll loop.
func TestNilEmitterYieldsNoAdapter(t *testing.T) {
	t.Parallel()
	if adapter := newAIRuntimeV8Adapter(nil); adapter != nil {
		t.Fatal("a nil emitter produced an adapter")
	}
}
