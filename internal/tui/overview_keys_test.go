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

// Renderer-level tests for the "keys" status line in the Overview
// SCANNERS box and the sibling "Missing required API key(s)"
// notice up top. Both surfaces read the cached doctor snapshot so
// these tests drive OverviewPanel through SetDoctorCache and
// assert on the visible output (ANSI-stripped) — the exact style
// is intentionally not tested so theme tweaks don't break us.

import (
	"strings"
	"testing"
	"time"
)

func TestDoctorCache_MissingRequiredCredentials(t *testing.T) {
	t.Parallel()

	t.Run("nil cache returns nil", func(t *testing.T) {
		var c *DoctorCache
		if got := c.MissingRequiredCredentials(); got != nil {
			t.Fatalf("nil cache should yield nil, got %v", got)
		}
	})

	t.Run("ignores non-fail and non-credential checks", func(t *testing.T) {
		c := &DoctorCache{Checks: []DoctorCheck{
			{Status: "pass", Label: "credential IGNORED_PASS"},
			{Status: "warn", Label: "credential IGNORED_WARN"},
			{Status: "fail", Label: "Sidecar API"},
			{Status: "fail", Label: "credentialMISSING_NO_SPACE"},
		}}
		if got := c.MissingRequiredCredentials(); got != nil {
			t.Fatalf("expected no matches, got %v", got)
		}
	})

	t.Run("extracts env names in emission order", func(t *testing.T) {
		c := &DoctorCache{Checks: []DoctorCheck{
			{Status: "fail", Label: "credential OPENCLAW_GATEWAY_TOKEN"},
			{Status: "pass", Label: "Sidecar API"},
			{Status: "fail", Label: "credential CISCO_AI_DEFENSE_API_KEY"},
		}}
		got := c.MissingRequiredCredentials()
		want := []string{"OPENCLAW_GATEWAY_TOKEN", "CISCO_AI_DEFENSE_API_KEY"}
		if len(got) != len(want) {
			t.Fatalf("len mismatch: got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("position %d: got %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("trims surrounding whitespace from env name", func(t *testing.T) {
		c := &DoctorCache{Checks: []DoctorCheck{
			{Status: "fail", Label: "credential  PADDED_NAME  "},
		}}
		got := c.MissingRequiredCredentials()
		if len(got) != 1 || got[0] != "PADDED_NAME" {
			t.Fatalf("trim expected, got %v", got)
		}
	})
}

func TestOverview_ScannersBox_KeysLine_AllSet(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Passed:     3,
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "SCANNERS") {
		t.Fatalf("expected SCANNERS header")
	}
	if !strings.Contains(out, "keys") {
		t.Fatalf("expected 'keys' row, got:\n%s", out)
	}
	if !strings.Contains(out, "all required set") {
		t.Fatalf("expected 'all required set' for empty-missing cache, got:\n%s", out)
	}
}

func TestOverview_ScannersBox_KeysLine_Missing(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Passed:     2, Failed: 2,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "credential OPENCLAW_GATEWAY_TOKEN"},
			{Status: "fail", Label: "credential ANTHROPIC_API_KEY"},
		},
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "2 missing") {
		t.Fatalf("expected '2 missing' count, got:\n%s", out)
	}
	if !strings.Contains(out, "OPENCLAW_GATEWAY_TOKEN") {
		t.Fatalf("expected first missing key in scanners row, got:\n%s", out)
	}
	if !strings.Contains(out, "ANTHROPIC_API_KEY") {
		t.Fatalf("expected second missing key in scanners row, got:\n%s", out)
	}
}

func TestOverview_ScannersBox_KeysLine_Overflow(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Failed:     4,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "credential KEY_A"},
			{Status: "fail", Label: "credential KEY_B"},
			{Status: "fail", Label: "credential KEY_C"},
			{Status: "fail", Label: "credential KEY_D"},
		},
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "4 missing") {
		t.Fatalf("expected '4 missing', got:\n%s", out)
	}
	if !strings.Contains(out, "KEY_A") || !strings.Contains(out, "KEY_B") {
		t.Fatalf("expected first two keys inline, got:\n%s", out)
	}
	if !strings.Contains(out, "(+2 more)") {
		t.Fatalf("expected overflow suffix '(+2 more)', got:\n%s", out)
	}
}

func TestOverview_ScannersBox_KeysLine_NoCache(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	// No SetDoctorCache call — renderer should stay quiet about
	// keys to avoid asserting a status we don't have evidence
	// for. The "not yet run" hint lives in the DOCTOR box.
	out := stripANSI(p.View(120, 40))
	scanners := scannersBoxSlice(out)
	if strings.Contains(scanners, "keys") {
		t.Fatalf("no cache should not render 'keys' row, got scanners box:\n%s", scanners)
	}
}

func TestOverview_TopNotice_MissingKeys(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Failed:     1,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "credential OPENCLAW_GATEWAY_TOKEN"},
		},
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "Missing required API key(s)") {
		t.Fatalf("expected top-level missing-keys notice, got:\n%s", out)
	}
	if !strings.Contains(out, "OPENCLAW_GATEWAY_TOKEN") {
		t.Fatalf("notice should name the missing key, got:\n%s", out)
	}
	if !strings.Contains(out, "defenseclaw keys fill-missing") {
		t.Fatalf("notice should point at the remediation command, got:\n%s", out)
	}
}

func TestOverview_TopNotice_MissingKeys_Overflow(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{
		CapturedAt: time.Now(),
		Failed:     5,
		Checks: []DoctorCheck{
			{Status: "fail", Label: "credential K1"},
			{Status: "fail", Label: "credential K2"},
			{Status: "fail", Label: "credential K3"},
			{Status: "fail", Label: "credential K4"},
			{Status: "fail", Label: "credential K5"},
		},
	})
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "(+3 more)") {
		t.Fatalf("expected notice overflow suffix, got:\n%s", out)
	}
	// First two previewed names must appear
	if !strings.Contains(out, "K1") || !strings.Contains(out, "K2") {
		t.Fatalf("first two keys should be inlined, got:\n%s", out)
	}
}

func TestOverview_TopNotice_NoMissingKeys_NoNotice(t *testing.T) {
	t.Parallel()
	p := newOverviewForTest()
	p.SetDoctorCache(&DoctorCache{CapturedAt: time.Now(), Passed: 2})
	out := stripANSI(p.View(120, 40))
	if strings.Contains(out, "Missing required API key(s)") {
		t.Fatalf("no missing keys should not emit notice, got:\n%s", out)
	}
}

func TestKeysOverflowSuffix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		total, shown int
		want         string
	}{
		{0, 0, ""},
		{2, 2, ""},
		{3, 2, " (+1 more)"},
		{10, 2, " (+8 more)"},
		// Defensive: shown > total should not produce a negative
		// suffix — the helper just reports nothing.
		{1, 2, ""},
	}
	for _, tc := range cases {
		if got := keysOverflowSuffix(tc.total, tc.shown); got != tc.want {
			t.Fatalf("keysOverflowSuffix(%d,%d) = %q, want %q",
				tc.total, tc.shown, got, tc.want)
		}
	}
}

// scannersBoxSlice returns the SCANNERS box portion of the view so
// tests can assert "this content lives here and not in some other
// box". Uses simple header anchors since the box widths may vary
// with terminal size.
func scannersBoxSlice(view string) string {
	idx := strings.Index(view, "SCANNERS")
	if idx < 0 {
		return ""
	}
	rest := view[idx:]
	// Box ends at next all-caps header or double newline.
	for _, anchor := range []string{"DOCTOR", "ENFORCEMENT", "CONFIGURATION"} {
		if j := strings.Index(rest[len("SCANNERS"):], anchor); j >= 0 {
			return rest[:len("SCANNERS")+j]
		}
	}
	return rest
}
