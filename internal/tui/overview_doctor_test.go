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

// Renderer-level tests for the P3-#21 Overview "DOCTOR" box. We
// drive the OverviewPanel through SetDoctorCache with a variety of
// cache states and assert on the rendered output (stripped of
// lipgloss ANSI codes) so the assertions remain stable across
// terminal backends.

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// stripANSI drops any CSI escape sequences so substring assertions
// work against the visible rendered text.
func stripANSI(s string) string {
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
	return ansi.ReplaceAllString(s, "")
}

func newOverviewForTest() OverviewPanel {
	return NewOverviewPanel(DefaultTheme(), &config.Config{DataDir: "/tmp/dc"}, "test")
}

func TestOverview_DoctorBox_NoData(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "DOCTOR") {
		t.Fatalf("expected DOCTOR header, got:\n%s", out)
	}
	if !strings.Contains(out, "not yet run") {
		t.Fatalf("expected 'not yet run' hint when no cache, got:\n%s", out)
	}
}

func TestOverview_DoctorBox_AllGreen(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Passed:     5,
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "DOCTOR") {
		t.Fatalf("expected DOCTOR header")
	}
	if !strings.Contains(out, "5 pass") {
		t.Fatalf("expected '5 pass' in summary, got:\n%s", out)
	}
	if !strings.Contains(out, "all green") {
		t.Fatalf("expected 'all green' when zero failures/warnings, got:\n%s", out)
	}
	// No stale nudge on a fresh run.
	if strings.Contains(out, "stale") {
		t.Fatalf("fresh cache should not be flagged stale")
	}
}

func TestOverview_DoctorBox_WithFailures(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Passed:     3, Failed: 2, Warned: 1,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "Sidecar API", Detail: "not reachable on port 7779"},
			{Status: "warn", Label: "Guardrail", Detail: "model empty"},
			{Status: "fail", Label: "LLM key (Anthropic)", Detail: "HTTP 401"},
		},
	})
	out := stripANSI(p.View(120, 40))

	// Summary line must carry all four counts.
	if !strings.Contains(out, "3 pass") {
		t.Fatalf("missing '3 pass': %s", out)
	}
	if !strings.Contains(out, "2 fail") {
		t.Fatalf("missing '2 fail': %s", out)
	}
	if !strings.Contains(out, "1 warn") {
		t.Fatalf("missing '1 warn': %s", out)
	}

	// Top failures should include both FAILs before the WARN
	// (TopFailures contract) and the labels should be visible.
	if !strings.Contains(out, "Sidecar API") {
		t.Fatalf("expected top-failure Sidecar API in detail, got:\n%s", out)
	}
	if !strings.Contains(out, "LLM key (Anthropic)") {
		t.Fatalf("expected top-failure LLM key in detail, got:\n%s", out)
	}
	// And the WARN also appears since we show up to 3.
	if !strings.Contains(out, "Guardrail") {
		t.Fatalf("expected warn Guardrail in detail, got:\n%s", out)
	}

	// Notices also surface the doctor failure count up top.
	if !strings.Contains(out, "Doctor found 2 failure(s)") {
		t.Fatalf("expected doctor failure notice, got:\n%s", out)
	}
}

func TestOverview_ZeroRequestNotice_CodexObservabilityUsesHookGuidance(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.cfg.Claw.Mode = config.ClawMode("codex")
	p.cfg.Guardrail.Connector = "codex"
	p.cfg.Guardrail.CodexEnforcementEnabled = false
	p.SetHealth(&HealthSnapshot{
		UptimeMS: int64(3 * time.Minute / time.Millisecond),
		Connector: &ConnectorHealth{
			Name:     "codex",
			State:    "running",
			Requests: 0,
		},
	})

	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "0 hook events") {
		t.Fatalf("expected Codex hook-event guidance, got:\n%s", out)
	}
	if strings.Contains(out, "gateway port") {
		t.Fatalf("Codex observability mode should not suggest gateway port routing, got:\n%s", out)
	}
}

func TestOverview_ZeroRequestNotice_HookOnlyConnectorUsesHookGuidance(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.cfg.Claw.Mode = config.ClawMode("copilot")
	p.cfg.Guardrail.Connector = "copilot"
	p.SetHealth(&HealthSnapshot{
		UptimeMS: int64(3 * time.Minute / time.Millisecond),
		Connector: &ConnectorHealth{
			Name:     "copilot",
			State:    "running",
			Requests: 0,
		},
	})

	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "0 hook events") {
		t.Fatalf("expected Copilot hook-event guidance, got:\n%s", out)
	}
	if strings.Contains(out, "gateway port") {
		t.Fatalf("hook-only connector should not suggest gateway port routing, got:\n%s", out)
	}
}

func TestOverview_ZeroRequestNotice_OpenClawKeepsGatewayPortGuidance(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.cfg.Claw.Mode = config.ClawOpenClaw
	p.cfg.Guardrail.Connector = "openclaw"
	p.SetHealth(&HealthSnapshot{
		UptimeMS: int64(3 * time.Minute / time.Millisecond),
		Connector: &ConnectorHealth{
			Name:     "openclaw",
			State:    "running",
			Requests: 0,
		},
	})

	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "gateway port") {
		t.Fatalf("expected OpenClaw gateway-port guidance, got:\n%s", out)
	}
}

func TestOverview_DoctorBox_StaleCache(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now().Add(-StaleAfter - 5*time.Minute),
		Passed:     7,
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "stale") {
		t.Fatalf("stale cache should be flagged in box, got:\n%s", out)
	}
	// The stale notice should bubble up to the top notices row
	// since failures are zero.
	if !strings.Contains(out, "Doctor cache is stale") {
		t.Fatalf("expected stale notice up top, got:\n%s", out)
	}
}

func TestOverview_DoctorBox_StaleWithFailures_NoticeIsError(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now().Add(-StaleAfter - time.Hour),
		Passed:     2, Failed: 1,
		Checks: []DoctorCheck{{Status: "fail", Label: "X"}},
	})
	out := stripANSI(p.View(120, 40))
	// A failing cache must show the failure notice, not the
	// stale one — failures dominate.
	if !strings.Contains(out, "Doctor found 1 failure(s)") {
		t.Fatalf("expected failure notice, got:\n%s", out)
	}
	if strings.Contains(out, "Doctor cache is stale") {
		t.Fatalf("stale notice should be suppressed when failures exist, got:\n%s", out)
	}
}

func TestOverview_DoctorBox_TopFailuresBounded(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	checks := make([]DoctorCheck, 0, 10)
	for i := 0; i < 10; i++ {
		checks = append(checks, DoctorCheck{
			Status: "fail", Label: "fail-" + string(rune('a'+i)), Detail: "d",
		})
	}
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Failed:     len(checks), Checks: checks,
	})
	out := stripANSI(p.View(160, 60))
	// Only 3 should render (TopFailures budget).
	visible := 0
	for i := 0; i < 10; i++ {
		if strings.Contains(out, "fail-"+string(rune('a'+i))) {
			visible++
		}
	}
	if visible != 3 {
		t.Fatalf("expected 3 top failures in box, got %d rendered. Output:\n%s", visible, out)
	}
}

func TestOverview_SetDoctorCache_Getter(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	if p.DoctorCache() != nil {
		t.Fatalf("fresh panel should have nil cache")
	}
	c := &DoctorCache{CapturedAt: time.Now(), Passed: 1}
	p.SetDoctorCache(c)
	if p.DoctorCache() != c {
		t.Fatalf("DoctorCache() getter should return set value")
	}
	p.SetDoctorCache(nil)
	if p.DoctorCache() != nil {
		t.Fatalf("nil should clear cache")
	}
}
