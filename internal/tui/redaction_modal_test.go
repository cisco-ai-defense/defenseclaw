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

// TestRedactionToggleModal_DesiredAction pins the contract that
// the modal computes the destination action from the cached
// "currently disabled" flag. A bug here means [Enter] dispatches
// the wrong CLI subcommand — flipping privacy state in the
// opposite direction of what the operator just confirmed.
func TestRedactionToggleModal_DesiredAction(t *testing.T) {
	cases := []struct {
		name      string
		curDisabl bool
		want      string
	}{
		{name: "currently_redacted_flips_to_off", curDisabl: false, want: "off"},
		{name: "currently_raw_flips_to_on", curDisabl: true, want: "on"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := NewRedactionToggleModal(DefaultTheme())
			m.Show(tc.curDisabl)
			if got := m.DesiredAction(); got != tc.want {
				t.Fatalf("DesiredAction()=%q, want %q", got, tc.want)
			}
			if !m.IsVisible() {
				t.Fatal("Show() must mark the modal visible")
			}
			m.Hide()
			if m.IsVisible() {
				t.Fatal("Hide() must clear visibility")
			}
		})
	}
}

// TestRedactionToggleModal_View_OffBranchSurfacesPrivacyWarning
// guards the wording the operator sees when going from REDACTED to
// RAW. The modal MUST name the affected sinks (audit DB, Splunk,
// OTel, webhooks) so a hurried operator can't miss the privacy
// implications. A regression that drops the sink list is exactly
// the failure mode the modal exists to prevent.
func TestRedactionToggleModal_View_OffBranchSurfacesPrivacyWarning(t *testing.T) {
	m := NewRedactionToggleModal(DefaultTheme())
	m.SetSize(80, 24)
	m.Show(false) // currently REDACTED → modal will offer to flip OFF

	view := m.View()
	required := []string{
		"Redaction kill-switch",
		"REDACTED",
		"RAW",
		"SQLite audit DB",
		"Splunk HEC",
		"webhooks",
		"gateway.log",
		"[Enter]",
		"[esc]",
	}
	for _, want := range required {
		if !strings.Contains(view, want) {
			t.Fatalf("OFF-branch modal view missing %q\nfull view:\n%s", want, view)
		}
	}
}

// TestRedactionToggleModal_View_OnBranchSkipsScaryWarning ensures
// the safe direction (RAW → REDACTED) renders a calmer message.
// We reuse the same sink list because re-enabling redaction also
// affects them, but we should NOT re-show the "only proceed if…"
// warning because there's no privacy hazard in turning redaction
// back on.
func TestRedactionToggleModal_View_OnBranchSkipsScaryWarning(t *testing.T) {
	m := NewRedactionToggleModal(DefaultTheme())
	m.SetSize(80, 24)
	m.Show(true) // currently RAW → modal will offer to flip ON

	view := m.View()
	if !strings.Contains(view, "Re-enables redaction") {
		t.Fatalf("ON-branch modal must announce the safe direction:\n%s", view)
	}
	// The "Disabling redaction" + "trust boundary" warning is for
	// the OFF branch only.
	if strings.Contains(view, "Disabling redaction") {
		t.Fatalf("ON-branch modal must NOT show the OFF-direction warning:\n%s", view)
	}
	if strings.Contains(view, "trust boundary") {
		t.Fatalf("ON-branch modal must NOT show the trust-boundary nag:\n%s", view)
	}
}

// TestRedactionToggleModal_View_HiddenWhenNotVisible pins the
// laziness contract: a hidden modal renders as the empty string
// so the View() composer can unconditionally append it without
// double-painting on top of the underlying panel.
func TestRedactionToggleModal_View_HiddenWhenNotVisible(t *testing.T) {
	m := NewRedactionToggleModal(DefaultTheme())
	if got := m.View(); got != "" {
		t.Fatalf("hidden modal must render empty, got %q", got)
	}
}

// TestConfirmRedactionToggle_AppliesOverrideImmediately pins the
// process-local RAW badge update that happens before the async CLI
// subprocess restarts the gateway.
func TestConfirmRedactionToggle_AppliesOverrideImmediately(t *testing.T) {
	old := applyTUIRedactionOverride
	var calls []bool
	applyTUIRedactionOverride = func(disable bool) {
		calls = append(calls, disable)
	}
	t.Cleanup(func() { applyTUIRedactionOverride = old })

	cases := []struct {
		name              string
		currentlyDisabled bool
		wantDisable       bool
	}{
		{name: "redacted_to_raw", currentlyDisabled: false, wantDisable: true},
		{name: "raw_to_redacted", currentlyDisabled: true, wantDisable: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls = nil
			m := Model{
				executor:       NewCommandExecutor(),
				redactionModal: NewRedactionToggleModal(DefaultTheme()),
			}
			m.redactionModal.Show(tc.currentlyDisabled)

			next, cmd := m.confirmRedactionToggle()
			if cmd == nil {
				t.Fatal("confirmRedactionToggle must return a command")
			}
			if len(calls) != 1 || calls[0] != tc.wantDisable {
				t.Fatalf("override calls=%v, want [%v]", calls, tc.wantDisable)
			}
			got, ok := next.(Model)
			if !ok {
				t.Fatalf("confirmRedactionToggle returned %T, want Model", next)
			}
			if got.activePanel != PanelActivity {
				t.Fatalf("activePanel=%d, want PanelActivity", got.activePanel)
			}
			if got.redactionModal.IsVisible() {
				t.Fatal("modal should be hidden after confirm")
			}
		})
	}
}
