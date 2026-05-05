// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"
)

// TestGatewayHealthIsBroken pins the predicate the Overview panel uses
// to decide whether to surface the red "Gateway is offline" notice.
// The split between "intentional" (running, disabled) and "broken"
// (everything else) is the entire reason the codex+standalone
// regression existed pre-fix — the previous predicate compared
// against "running" alone and lit up red on every codex-only dev
// box. Drift here would re-introduce that symptom, so this test
// is a regression seal.
func TestGatewayHealthIsBroken(t *testing.T) {
	cases := []struct {
		state string
		want  bool
	}{
		// Healthy / intentional non-broken states.
		{"running", false},
		{"RUNNING", false},
		{" Running ", false},
		{"disabled", false},
		{"DISABLED", false},

		// Anything else is "operator should care".
		{"reconnecting", true},
		{"error", true},
		{"stopped", true},
		{"starting", true},
		{"unknown", true},
		{"", true},
		{"garbage", true},
	}
	for _, tc := range cases {
		t.Run(strings.ReplaceAll(tc.state, " ", "_space_"), func(t *testing.T) {
			if got := gatewayHealthIsBroken(tc.state); got != tc.want {
				t.Errorf("gatewayHealthIsBroken(%q) = %v, want %v", tc.state, got, tc.want)
			}
		})
	}
}

// TestStringDetail covers the helper used by the Overview's standalone
// hint extraction. It MUST never panic on a malformed health snapshot
// (the TUI re-renders on every refresh tick, so a single bad map
// would crash the whole UI).
func TestStringDetail(t *testing.T) {
	t.Run("nil_map", func(t *testing.T) {
		if got := stringDetail(nil, "summary"); got != "" {
			t.Errorf("stringDetail(nil, _) = %q, want empty", got)
		}
	})
	t.Run("missing_key", func(t *testing.T) {
		if got := stringDetail(map[string]interface{}{"foo": "bar"}, "summary"); got != "" {
			t.Errorf("stringDetail(missing, _) = %q, want empty", got)
		}
	})
	t.Run("type_mismatch", func(t *testing.T) {
		// numeric value where a string is expected — must NOT panic
		// and must return "" rather than fmt.Sprint-ing the int.
		got := stringDetail(map[string]interface{}{"summary": 42}, "summary")
		if got != "" {
			t.Errorf("stringDetail(int, _) = %q, want empty", got)
		}
	})
	t.Run("string_value_trimmed", func(t *testing.T) {
		got := stringDetail(map[string]interface{}{"summary": "  hello  "}, "summary")
		if got != "hello" {
			t.Errorf("stringDetail trimmed = %q, want %q", got, "hello")
		}
	})
}

// TestOverview_StandaloneHint_FromHealthSnapshot proves the panel
// reads the `hint`/`summary` keys the sidecar publishes in
// runGatewayLoop's standalone short-circuit. The two surfaces (TUI
// + sidecar) are coupled by these key names, so a rename on either
// side must update the other — this test catches that drift.
func TestOverview_StandaloneHint_FromHealthSnapshot(t *testing.T) {
	p := newOverviewForTest()

	// No snapshot → no hint.
	if got := p.gatewayStandaloneHint(); got != "" {
		t.Errorf("hint with nil health = %q, want empty", got)
	}

	// Hint key wins over summary when both are present (matches the
	// preference in gatewayStandaloneHint: hint is operator-actionable
	// "do this", summary is "this is the current state").
	p.SetHealth(&HealthSnapshot{
		Gateway: SubsystemHealth{
			State: "disabled",
			Details: map[string]interface{}{
				"summary": "no OpenClaw fleet configured (standalone mode)",
				"hint":    "set gateway.host and restart",
			},
		},
	})
	if got := p.gatewayStandaloneHint(); got != "set gateway.host and restart" {
		t.Errorf("hint preference broken: got %q, want %q", got, "set gateway.host and restart")
	}

	// summary alone (older sidecar that didn't publish hint) still works.
	p.SetHealth(&HealthSnapshot{
		Gateway: SubsystemHealth{
			State: "disabled",
			Details: map[string]interface{}{
				"summary": "no OpenClaw fleet configured (standalone mode)",
			},
		},
	})
	if got := p.gatewayStandaloneHint(); got != "no OpenClaw fleet configured (standalone mode)" {
		t.Errorf("hint summary fallback broken: got %q", got)
	}
}

// TestOverview_BuildNotices_StandaloneSuppressesOfflineRed proves the
// regression we just fixed: when health.Gateway.State is "disabled"
// (the codex+loopback no-fleet path), the panel must NOT surface
// the red "Gateway is offline" error notice. Pre-fix, the predicate
// `state != "running"` caught DISABLED in the same bucket as
// RECONNECTING/ERROR, which painted every codex dev box red. The
// post-fix split (gatewayHealthIsBroken returns false for both
// running and disabled) is what this test pins.
func TestOverview_BuildNotices_StandaloneSuppressesOfflineRed(t *testing.T) {
	p := newOverviewForTest()
	p.SetHealth(&HealthSnapshot{
		Gateway: SubsystemHealth{
			State: "disabled",
			Details: map[string]interface{}{
				"summary": "no OpenClaw fleet configured (standalone mode)",
				"hint":    "set gateway.host to a real OpenClaw upstream and restart",
			},
		},
	})
	p.buildNotices()
	for _, n := range p.notices {
		if n.level == "error" && strings.Contains(n.message, "Gateway is offline") {
			t.Fatalf("standalone gateway should NOT raise red 'Gateway is offline' notice; got: %+v", p.notices)
		}
	}
}

// TestOverview_BuildNotices_BrokenStillRaisesOffline is the symmetric
// guard: a state of "reconnecting" / "error" / "stopped" MUST still
// trigger the red notice. The fix narrowed the predicate; it must
// not have *removed* the legitimate "operator, look at me" path.
func TestOverview_BuildNotices_BrokenStillRaisesOffline(t *testing.T) {
	for _, state := range []string{"reconnecting", "error", "stopped", "unknown"} {
		t.Run(state, func(t *testing.T) {
			p := newOverviewForTest()
			p.SetHealth(&HealthSnapshot{
				Gateway: SubsystemHealth{State: state},
			})
			p.buildNotices()
			found := false
			for _, n := range p.notices {
				if n.level == "error" && strings.Contains(n.message, "Gateway is offline") {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("state=%q must surface red 'Gateway is offline' notice; notices=%+v",
					state, p.notices)
			}
		})
	}
}
