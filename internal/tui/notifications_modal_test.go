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

// TestNotificationsToggleModal_DesiredAction pins the contract
// that the modal computes the destination action from the cached
// "currently enabled" flag. A bug here means [Enter] dispatches
// the wrong CLI subcommand — flipping the dispatcher state in the
// opposite direction of what the operator confirmed.
func TestNotificationsToggleModal_DesiredAction(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		want    string
	}{
		{name: "currently_on_flips_to_off", enabled: true, want: "off"},
		{name: "currently_off_flips_to_on", enabled: false, want: "on"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m := NewNotificationsToggleModal(DefaultTheme())
			m.Show(tc.enabled)
			if got := m.DesiredAction(); got != tc.want {
				t.Fatalf("DesiredAction()=%q, want %q", got, tc.want)
			}
			if !m.IsVisible() {
				t.Fatal("Show() must mark the modal visible")
			}
			if m.CurrentlyEnabled() != tc.enabled {
				t.Fatalf("CurrentlyEnabled()=%v, want %v",
					m.CurrentlyEnabled(), tc.enabled)
			}
			m.Hide()
			if m.IsVisible() {
				t.Fatal("Hide() must clear visibility")
			}
		})
	}
}

// TestNotificationsToggleModal_View_OnBranch guards the wording an
// operator sees when flipping notifications ON. The modal must
// describe what categories the dispatcher actually surfaces (block,
// would-block, HITL approval) so a "yes" answer is informed —
// dropping that list defeats the purpose of the confirmation step.
func TestNotificationsToggleModal_View_OnBranch(t *testing.T) {
	m := NewNotificationsToggleModal(DefaultTheme())
	m.SetSize(80, 24)
	m.Show(false) // currently OFF → modal offers to flip ON

	v := m.View()
	for _, want := range []string{
		"Desktop notifications",
		"blocks",
		"approval",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("View() missing required substring %q\n--- view ---\n%s",
				want, v)
		}
	}
}

// TestNotificationsToggleModal_View_OffBranch checks the OFF
// transition surfaces the audit-trail invariant: the toaster
// silences, but the audit DB / SIEM / webhook sinks keep working.
// Operators who turn off toasts because they're noisy must not
// mistakenly think they've also turned off compliance logging.
func TestNotificationsToggleModal_View_OffBranch(t *testing.T) {
	m := NewNotificationsToggleModal(DefaultTheme())
	m.SetSize(80, 24)
	m.Show(true) // currently ON → modal offers to flip OFF

	v := m.View()
	for _, want := range []string{
		"Desktop notifications",
		"Audit",
		"NOT affected",
	} {
		if !strings.Contains(v, want) {
			t.Errorf("View() missing required substring %q\n--- view ---\n%s",
				want, v)
		}
	}
}

// TestNotificationsToggleModal_View_HiddenWhenNotVisible pins the
// invariant that View() returns empty when the modal is hidden,
// matching the redaction modal contract. Owning Model relies on
// this so it never overlays a stale modal frame on the active
// panel after Hide().
func TestNotificationsToggleModal_View_HiddenWhenNotVisible(t *testing.T) {
	m := NewNotificationsToggleModal(DefaultTheme())
	m.SetSize(80, 24)
	if got := m.View(); got != "" {
		t.Fatalf("View() on hidden modal returned %q, want empty", got)
	}
	m.Show(false)
	if m.View() == "" {
		t.Fatal("View() returned empty after Show()")
	}
	m.Hide()
	if got := m.View(); got != "" {
		t.Fatalf("View() after Hide() returned %q, want empty", got)
	}
}
