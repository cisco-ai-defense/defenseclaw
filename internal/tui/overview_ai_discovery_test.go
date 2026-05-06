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

// Renderer-level tests for the Overview "DISCOVERED AI AGENTS" box.
// We exercise the offline placeholder, the disabled placeholder,
// the populated table (including new-then-changed sort order and
// truncation), and the helper functions used by the renderer
// directly so a refactor that breaks tie-breaking can be caught
// without going through View().

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOverview_AIDiscoveryBox_Offline(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "DISCOVERED AI AGENTS") {
		t.Fatalf("expected DISCOVERED AI AGENTS header, got:\n%s", out)
	}
	if !strings.Contains(out, "ai discovery offline") {
		t.Fatalf("expected offline placeholder, got:\n%s", out)
	}
	if !strings.Contains(out, "defenseclaw agent discovery status") {
		t.Fatalf("expected diagnostic command hint, got:\n%s", out)
	}
}

func TestOverview_AIDiscoveryBox_Disabled(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetAIUsage(&AIUsageSnapshot{Enabled: false})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "DISCOVERED AI AGENTS") {
		t.Fatalf("expected DISCOVERED AI AGENTS header, got:\n%s", out)
	}
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected disabled placeholder, got:\n%s", out)
	}
	if !strings.Contains(out, "defenseclaw agent discovery enable") {
		t.Fatalf("expected enable hint, got:\n%s", out)
	}
}

func TestOverview_AIDiscoveryBox_EnabledNoSignals(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetAIUsage(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ScannedAt:     time.Now().Add(-2 * time.Minute),
			PrivacyMode:   "enhanced",
			ActiveSignals: 0,
		},
	})
	out := stripANSI(p.View(160, 40))
	if !strings.Contains(out, "0 active") {
		t.Fatalf("expected '0 active' summary, got:\n%s", out)
	}
	if !strings.Contains(out, "no AI agents detected yet") {
		t.Fatalf("expected empty-list hint, got:\n%s", out)
	}
	if !strings.Contains(out, "mode enhanced") {
		t.Fatalf("expected privacy mode breadcrumb, got:\n%s", out)
	}
}

func TestOverview_AIDiscoveryBox_RendersSignalsAndSortsNewFirst(t *testing.T) {
	t.Parallel()
	now := time.Now()
	p := newOverviewForTest()
	p.SetAIUsage(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ScannedAt:     now.Add(-15 * time.Second),
			PrivacyMode:   "enhanced",
			ActiveSignals: 3,
			NewSignals:    1,
		},
		Signals: []AIUsageSignal{
			{
				SignatureID: "claude-code",
				Name:        "Claude Code",
				Vendor:      "Anthropic",
				State:       "active",
				Confidence:  0.91,
				LastSeen:    now.Add(-30 * time.Second),
			},
			{
				SignatureID: "codex-cli",
				Name:        "Codex",
				Vendor:      "OpenAI",
				State:       "new",
				Confidence:  0.95,
				LastSeen:    now.Add(-5 * time.Second),
			},
			{
				SignatureID: "cursor",
				Name:        "Cursor",
				Vendor:      "Cursor AI",
				State:       "active",
				Confidence:  0.88,
				LastSeen:    now.Add(-5 * time.Minute),
			},
		},
	})
	out := stripANSI(p.View(180, 40))

	if !strings.Contains(out, "DISCOVERED AI AGENTS") {
		t.Fatalf("expected DISCOVERED AI AGENTS header, got:\n%s", out)
	}
	if !strings.Contains(out, "3 active") || !strings.Contains(out, "1 new") {
		t.Fatalf("expected active+new counts in summary, got:\n%s", out)
	}
	for _, want := range []string{"Claude Code", "Codex", "Cursor", "Anthropic", "OpenAI", "Cursor AI"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in rendered table, got:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "[NEW]") || !strings.Contains(out, "[OK ]") {
		t.Fatalf("expected NEW and OK state badges, got:\n%s", out)
	}
	// New row must appear above the active rows in the table — find
	// the line indices and assert. The DISCOVERED header is above
	// both, so the relative order between Codex (new) and Claude
	// Code (active) is what we care about.
	codexIdx := strings.Index(out, "Codex")
	claudeIdx := strings.Index(out, "Claude Code")
	if codexIdx < 0 || claudeIdx < 0 {
		t.Fatalf("missing rows: codexIdx=%d claudeIdx=%d", codexIdx, claudeIdx)
	}
	if codexIdx > claudeIdx {
		t.Fatalf("expected NEW row to render above active row; got codex@%d after claude@%d:\n%s", codexIdx, claudeIdx, out)
	}

	// Confidence percentages must render — defensive against the
	// 0..1 → 0..100 conversion regressing.
	if !strings.Contains(out, "95%") || !strings.Contains(out, "91%") {
		t.Fatalf("expected confidence percentages, got:\n%s", out)
	}
}

func TestOverview_AIDiscoveryBox_TruncatesAtCap(t *testing.T) {
	t.Parallel()
	now := time.Now()
	signals := make([]AIUsageSignal, 0, maxAIDiscoveryRows+3)
	for i := 0; i < maxAIDiscoveryRows+3; i++ {
		signals = append(signals, AIUsageSignal{
			SignatureID: "agent-" + string(rune('a'+i)),
			Name:        "Agent " + string(rune('A'+i)),
			Vendor:      "VendorCo",
			State:       "active",
			Confidence:  0.5 + float64(i)*0.01,
			LastSeen:    now.Add(-time.Duration(i) * time.Minute),
		})
	}
	p := newOverviewForTest()
	p.SetAIUsage(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ScannedAt:     now,
			ActiveSignals: len(signals),
		},
		Signals: signals,
	})
	out := stripANSI(p.View(200, 60))

	overflow := len(signals) - maxAIDiscoveryRows
	wantTail := "+" + strconv.Itoa(overflow) + " more"
	if !strings.Contains(out, wantTail) {
		t.Fatalf("expected overflow tail %q, got:\n%s", wantTail, out)
	}
	if !strings.Contains(out, "defenseclaw agent discover") {
		t.Fatalf("expected CLI hint in overflow tail, got:\n%s", out)
	}
}

func TestOverview_AIDiscoveryBox_GoneSortedLast(t *testing.T) {
	t.Parallel()
	now := time.Now()
	p := newOverviewForTest()
	p.SetAIUsage(&AIUsageSnapshot{
		Enabled: true,
		Summary: AIUsageSummary{
			ScannedAt:     now,
			ActiveSignals: 1,
			GoneSignals:   1,
		},
		Signals: []AIUsageSignal{
			{
				SignatureID: "old-agent",
				Name:        "Old Agent",
				State:       "gone",
				Confidence:  0.99,
				LastSeen:    now.Add(-1 * time.Hour),
			},
			{
				SignatureID: "new-agent",
				Name:        "New Agent",
				State:       "active",
				Confidence:  0.5,
				LastSeen:    now,
			},
		},
	})
	out := stripANSI(p.View(180, 40))

	newIdx := strings.Index(out, "New Agent")
	goneIdx := strings.Index(out, "Old Agent")
	if newIdx < 0 || goneIdx < 0 {
		t.Fatalf("missing rows: newIdx=%d goneIdx=%d", newIdx, goneIdx)
	}
	if newIdx > goneIdx {
		t.Fatalf("expected active to render before gone; got new@%d after gone@%d:\n%s", newIdx, goneIdx, out)
	}
	if !strings.Contains(out, "[GONE]") {
		t.Fatalf("expected [GONE] badge in output:\n%s", out)
	}
}

func TestSortAIDiscoverySignalsForOverview_TieBreakers(t *testing.T) {
	t.Parallel()
	now := time.Now()
	in := []AIUsageSignal{
		{Name: "Bravo", State: "active", Confidence: 0.5, LastSeen: now.Add(-1 * time.Hour)},
		{Name: "Alpha", State: "active", Confidence: 0.5, LastSeen: now},
		{Name: "Charlie", State: "new", Confidence: 0.1, LastSeen: now.Add(-2 * time.Hour)},
	}
	got := sortAIDiscoverySignalsForOverview(in)
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	// New first regardless of confidence.
	if got[0].Name != "Charlie" {
		t.Fatalf("got[0].Name = %q, want Charlie (new state should win)", got[0].Name)
	}
	// Then active rows tie on confidence; recency wins so Alpha (now)
	// outranks Bravo (-1h).
	if got[1].Name != "Alpha" || got[2].Name != "Bravo" {
		t.Fatalf("got order = [%s, %s, %s], want [Charlie, Alpha, Bravo]", got[0].Name, got[1].Name, got[2].Name)
	}

	// Input must be untouched (we return a copy).
	if in[0].Name != "Bravo" || in[1].Name != "Alpha" || in[2].Name != "Charlie" {
		t.Fatalf("input was mutated: %+v", in)
	}
}

func TestDisplayAIDiscoveryName_FallbackChain(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   AIUsageSignal
		want string
	}{
		{"prefers Name", AIUsageSignal{Name: "Codex", Product: "p", SignatureID: "s", SignalID: "x"}, "Codex"},
		{"falls back to Product", AIUsageSignal{Product: "Aider", SignatureID: "s"}, "Aider"},
		{"then signature ID", AIUsageSignal{SignatureID: "claude-code"}, "claude-code"},
		{"then signal ID", AIUsageSignal{SignalID: "fp-1"}, "fp-1"},
		{"empty -> (unknown)", AIUsageSignal{}, "(unknown)"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := displayAIDiscoveryName(c.in); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDisplayAIDiscoveryVendor_AnnotatesVersionAndConnector(t *testing.T) {
	t.Parallel()
	got := displayAIDiscoveryVendor(AIUsageSignal{
		Vendor:             "Anthropic",
		Version:            "1.2.3",
		SupportedConnector: "claudecode",
	})
	if got != "Anthropic 1.2.3 (claudecode)" {
		t.Fatalf("got %q", got)
	}
	if v := displayAIDiscoveryVendor(AIUsageSignal{}); v != "—" {
		t.Fatalf("empty signal got %q, want '—'", v)
	}
	if v := displayAIDiscoveryVendor(AIUsageSignal{Category: "ide_extension"}); v != "ide_extension" {
		t.Fatalf("category fallback got %q", v)
	}
}

func TestFormatScanAge_Buckets(t *testing.T) {
	t.Parallel()
	now := time.Now()
	cases := []struct {
		t    time.Time
		want string
	}{
		{time.Time{}, "—"},
		{now.Add(5 * time.Second), "now"}, // future / clock skew
		{now.Add(-30 * time.Second), "30s ago"},
		{now.Add(-90 * time.Second), "1m ago"},
		{now.Add(-2 * time.Hour), "2h ago"},
		{now.Add(-48 * time.Hour), "2d ago"},
	}
	for _, c := range cases {
		if got := formatScanAge(c.t); got != c.want {
			t.Errorf("formatScanAge(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestClampPercent_Bounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   float64
		want int
	}{
		{-1, 0},
		{0, 0},
		{12.4, 12},
		{12.6, 13},
		{99.9, 100},
		{200, 100},
	}
	for _, c := range cases {
		if got := clampPercent(c.in); got != c.want {
			t.Errorf("clampPercent(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}
