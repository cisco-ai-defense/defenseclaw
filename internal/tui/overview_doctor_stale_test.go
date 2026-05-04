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

package tui

import (
	"strings"
	"testing"
	"time"
)

// TestLiveHealthContradicts_KnownLabels nails down the small set of
// doctor check labels we know how to reconcile against /health. The
// matching is intentionally case-insensitive on the trimmed label so
// future _emit() callsites in cmd_doctor.py with extra trailing
// whitespace don't quietly stop being suppressed.
func TestLiveHealthContradicts_KnownLabels(t *testing.T) {
	t.Parallel()
	running := SubsystemHealth{State: "running"}
	stopped := SubsystemHealth{State: "stopped"}

	cases := []struct {
		name   string
		check  DoctorCheck
		health *HealthSnapshot
		want   bool
	}{
		{
			name:   "sidecar api fail vs running",
			check:  DoctorCheck{Status: "fail", Label: "Sidecar API"},
			health: &HealthSnapshot{API: running},
			want:   true,
		},
		{
			name:   "sidecar api fail vs stopped",
			check:  DoctorCheck{Status: "fail", Label: "Sidecar API"},
			health: &HealthSnapshot{API: stopped},
			want:   false,
		},
		{
			name:   "guardrail proxy fail vs running",
			check:  DoctorCheck{Status: "fail", Label: "Guardrail proxy"},
			health: &HealthSnapshot{Guardrail: running},
			want:   true,
		},
		{
			name:   "openclaw gateway fail vs running",
			check:  DoctorCheck{Status: "fail", Label: "OpenClaw gateway"},
			health: &HealthSnapshot{Gateway: running},
			want:   true,
		},
		{
			name:   "otel fail vs running telemetry",
			check:  DoctorCheck{Status: "fail", Label: "otel (OTLP)"},
			health: &HealthSnapshot{Telemetry: running},
			want:   true,
		},
		{
			name:   "otel fail vs stopped telemetry preserves failure",
			check:  DoctorCheck{Status: "fail", Label: "otel (OTLP)"},
			health: &HealthSnapshot{Telemetry: stopped},
			want:   false,
		},
		{
			name:   "case insensitivity",
			check:  DoctorCheck{Status: "fail", Label: "  SIDECAR API  "},
			health: &HealthSnapshot{API: running},
			want:   true,
		},
		{
			name:  "passing checks are never contradicted",
			check: DoctorCheck{Status: "pass", Label: "Sidecar API"},
			// pass-status checks shouldn't be flipped to STALE
			// because they're not failures to begin with.
			health: &HealthSnapshot{API: running},
			want:   false,
		},
		{
			name:   "unknown label",
			check:  DoctorCheck{Status: "fail", Label: "Some Other Probe"},
			health: &HealthSnapshot{API: running, Guardrail: running, Gateway: running, Telemetry: running},
			want:   false,
		},
		{
			name:   "nil health never contradicts",
			check:  DoctorCheck{Status: "fail", Label: "Sidecar API"},
			health: nil,
			want:   false,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := liveHealthContradicts(tc.check, tc.health); got != tc.want {
				t.Fatalf("liveHealthContradicts(%+v, %+v) = %v, want %v", tc.check, tc.health, got, tc.want)
			}
		})
	}
}

// TestOverview_DoctorBox_StaleFailureSuppressedByLiveHealth covers the
// exact bug the user reported: doctor cache from yesterday says
// "[FAIL] Sidecar API not reachable on port 18790" but the live
// /health snapshot reports the API server as running. The DOCTOR box
// must:
//  1. NOT count that row in the red "fail" tally
//  2. Render the row as [STALE] instead of [FAIL]
//  3. Suppress the top-of-screen "Doctor found N failure(s)" notice
func TestOverview_DoctorBox_StaleFailureSuppressedByLiveHealth(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	// Pretend the user pressed [d] yesterday when the sidecar was
	// down. Cache says fail; live /health (set below) says fine.
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now().Add(-24 * time.Hour),
		Passed:     6, Failed: 2,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "Sidecar API", Detail: "not reachable on port 18790"},
			{Status: "fail", Label: "Guardrail proxy", Detail: "not responding on port 4000"},
		},
	})
	p.SetHealth(&HealthSnapshot{
		API:       SubsystemHealth{State: "running"},
		Guardrail: SubsystemHealth{State: "running"},
	})
	out := stripANSI(p.View(120, 40))

	// Summary should show "0 fail" via omission (we drop the part
	// when zero) and an explicit "2 stale" callout instead.
	if strings.Contains(out, "2 fail") {
		t.Fatalf("contradicted failures should not show as fails, got:\n%s", out)
	}
	if !strings.Contains(out, "2 stale") {
		t.Fatalf("expected '2 stale' summary part, got:\n%s", out)
	}

	// The detail rows should switch from [FAIL] to [STALE].
	if strings.Contains(out, "[FAIL] Sidecar API") {
		t.Fatalf("Sidecar API should not be rendered [FAIL] when /health says running, got:\n%s", out)
	}
	if !strings.Contains(out, "[STALE]") {
		t.Fatalf("expected at least one [STALE] row, got:\n%s", out)
	}

	// And the top-of-screen error notice must NOT shout
	// "Doctor found 2 failure(s)" — that was the user-visible
	// regression. We replace it with the gentler info notice.
	if strings.Contains(out, "Doctor found 2 failure(s)") {
		t.Fatalf("error notice should be suppressed when all fails are contradicted, got:\n%s", out)
	}
	if !strings.Contains(out, "/health disagrees") {
		t.Fatalf("expected '/health disagrees' info notice, got:\n%s", out)
	}
}

// TestOverview_DoctorBox_PartialContradiction_StillShowsRealFailures
// makes sure we don't over-suppress: when half the cached failures
// are stale and half are still real, the user must see the count of
// real ones.
func TestOverview_DoctorBox_PartialContradiction_StillShowsRealFailures(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now().Add(-StaleAfter - time.Minute),
		Passed:     4, Failed: 2,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "Sidecar API", Detail: "not reachable on port 18790"},
			{Status: "fail", Label: "LLM key (Anthropic)", Detail: "HTTP 401"},
		},
	})
	// Sidecar recovered but LLM key is still bogus.
	p.SetHealth(&HealthSnapshot{API: SubsystemHealth{State: "running"}})
	out := stripANSI(p.View(120, 40))

	if !strings.Contains(out, "1 fail") {
		t.Fatalf("expected '1 fail' for the genuinely-failed LLM key check, got:\n%s", out)
	}
	if !strings.Contains(out, "1 stale") {
		t.Fatalf("expected '1 stale' for the contradicted Sidecar row, got:\n%s", out)
	}
	if !strings.Contains(out, "Doctor found 1 failure(s)") {
		t.Fatalf("notice should report 1 real failure, got:\n%s", out)
	}
}
