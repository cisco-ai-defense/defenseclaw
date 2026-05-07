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

	tea "charm.land/bubbletea/v2"
)

// ctrlKey builds a synthetic “Ctrl+<rune>“ press matching how
// Bubble Tea reports the keystroke (KeyPressMsg.String() returns
// “"ctrl+t"“). Re-implemented locally rather than imported from
// app_test.go so this test file compiles on its own.
func ctrlKey(r rune) tea.KeyPressMsg {
	return tea.KeyPressMsg(tea.Key{Code: r, Mod: tea.ModCtrl})
}

// TestSetupReveal_TogglesPasswordMask pins the operator-visible
// contract that Ctrl+T flips a wizard's password-kind fields between
// the default mask (“****abcd“) and the raw value.
//
// The masking exists to keep secrets out of screen recordings; the
// reveal toggle is the escape hatch when the operator needs to
// sanity-check a token without leaving the TUI. Both paths must
// stay correct because the renderer is the only place that decides
// which form a secret takes on screen.
func TestSetupReveal_TogglesPasswordMask(t *testing.T) {
	p := &SetupPanel{
		theme: DefaultTheme(),
		wizFormFields: []wizardFormField{
			{Label: "API Key", Kind: "password", Value: "sk-test-1234567890abcdef"},
		},
		wizFormCursor: 0,
		wizFormActive: true,
		wizRunIdx:     0,
		// Larger height so the form actually renders the field row
		// instead of getting clipped by the visible-line budget.
		height: 30,
		width:  120,
	}

	// Default state: masked. The view must contain the last 4
	// characters of the value with the standard mask prefix and
	// must NOT contain the full secret.
	out := p.renderWizardForm()
	if !strings.Contains(out, "****cdef") {
		t.Fatalf("masked render missing ``****cdef`` suffix:\n%s", out)
	}
	if strings.Contains(out, "sk-test-1234567890abcdef") {
		t.Fatalf("default render leaked the full secret:\n%s", out)
	}
	if !strings.Contains(out, "Reveal secrets") {
		t.Fatalf("help line should advertise ``Reveal secrets`` when masked, got:\n%s", out)
	}
	if strings.Contains(out, "Hide secrets") {
		t.Fatalf("help line should not advertise ``Hide secrets`` while still masked:\n%s", out)
	}

	// Toggle: Ctrl+T must flip wizFormReveal and the very next
	// render must show the plaintext value. The "(revealed —
	// Ctrl+T to hide)" trailer is the user-visible signal that
	// the unmasked state is active and intentional.
	p.handleFormKey(ctrlKey('t'))
	if !p.wizFormReveal {
		t.Fatal("Ctrl+T did not flip wizFormReveal to true")
	}
	out = p.renderWizardForm()
	if !strings.Contains(out, "sk-test-1234567890abcdef") {
		t.Fatalf("reveal render missing plaintext value:\n%s", out)
	}
	if !strings.Contains(out, "(revealed") {
		t.Fatalf("reveal render missing ``(revealed`` trailer:\n%s", out)
	}
	if !strings.Contains(out, "Hide secrets") {
		t.Fatalf("help line should advertise ``Hide secrets`` while revealed:\n%s", out)
	}

	// Toggle back: Ctrl+T returns to the default mask. We also
	// check that the trailer is gone — a leftover trailer would
	// imply the renderer is stuck in reveal mode.
	p.handleFormKey(ctrlKey('t'))
	if p.wizFormReveal {
		t.Fatal("second Ctrl+T did not flip wizFormReveal back to false")
	}
	out = p.renderWizardForm()
	if strings.Contains(out, "sk-test-1234567890abcdef") {
		t.Fatalf("hide render leaked the full secret:\n%s", out)
	}
	if strings.Contains(out, "(revealed") {
		t.Fatalf("hide render still shows reveal trailer:\n%s", out)
	}
}

// TestSetupReveal_NoOpWithoutPasswordField guards the help-line
// contract: forms that don't have any password-kind field must not
// surface the Ctrl+T hint, otherwise operators see a keystroke that
// silently does nothing — exactly the kind of TUI papercut that
// erodes trust in the rest of the surface.
func TestSetupReveal_NoOpWithoutPasswordField(t *testing.T) {
	p := &SetupPanel{
		theme: DefaultTheme(),
		wizFormFields: []wizardFormField{
			{Label: "Mode", Kind: "choice", Value: "observe", Options: []string{"observe", "action"}},
		},
		wizFormCursor: 0,
		wizFormActive: true,
		wizRunIdx:     0,
		height:        30,
		width:         120,
	}

	out := p.renderWizardForm()
	if strings.Contains(out, "Ctrl+T") {
		t.Fatalf("help line surfaced Ctrl+T hint without any password field:\n%s", out)
	}

	p.handleFormKey(ctrlKey('t'))
	if p.wizFormReveal {
		t.Fatal("Ctrl+T flipped reveal even though no password field exists")
	}
}

// TestSetupReveal_ResetOnFormClose enforces the "reveal never
// silently persists across forms" rule. Closing the form (Esc),
// re-opening a different wizard, cycling a preset, or submitting
// the form must all return wizFormReveal to false so the next form
// the operator sees is masked again by default.
func TestSetupReveal_ResetOnFormClose(t *testing.T) {
	p := &SetupPanel{
		theme: DefaultTheme(),
		wizFormFields: []wizardFormField{
			{Label: "API Key", Kind: "password", Value: "sk-secret"},
		},
		wizFormCursor: 0,
		wizFormActive: true,
		wizRunIdx:     0,
		height:        30,
		width:         120,
	}

	// Reveal, then ESC to close.
	p.handleFormKey(ctrlKey('t'))
	if !p.wizFormReveal {
		t.Fatal("precondition: Ctrl+T should have flipped reveal on")
	}
	p.handleFormKey(tea.KeyPressMsg(tea.Key{Text: "esc", Code: tea.KeyEscape}))
	if p.wizFormReveal {
		t.Fatal("Esc must reset wizFormReveal so a re-opened form starts masked")
	}
}

// TestSetupReveal_ShortValueShowsBareMask confirms the renderer's
// short-value branch still respects the toggle. Values shorter than
// 5 characters render as a bare “****“ (no suffix) when masked,
// but must still flip to plaintext when revealed.
func TestSetupReveal_ShortValueShowsBareMask(t *testing.T) {
	p := &SetupPanel{
		theme: DefaultTheme(),
		wizFormFields: []wizardFormField{
			{Label: "PIN", Kind: "password", Value: "abcd"},
		},
		wizFormCursor: 0,
		wizFormActive: true,
		wizRunIdx:     0,
		height:        30,
		width:         120,
	}

	out := p.renderWizardForm()
	if !strings.Contains(out, "****") {
		t.Fatalf("short masked value missing bare ``****``:\n%s", out)
	}

	p.handleFormKey(ctrlKey('t'))
	out = p.renderWizardForm()
	if !strings.Contains(out, "abcd") {
		t.Fatalf("short revealed value missing plaintext:\n%s", out)
	}
}

// TestSetupReveal_EmptyValueRendersEmptyMarker guards the empty-value
// branch of the renderer: a password-kind field with an empty value
// must always render “(empty)“ regardless of reveal state — there
// is nothing to reveal, and showing “(revealed — …)“ next to an
// empty value would mislead the operator into thinking a secret is
// present.
func TestSetupReveal_EmptyValueRendersEmptyMarker(t *testing.T) {
	p := &SetupPanel{
		theme: DefaultTheme(),
		wizFormFields: []wizardFormField{
			{Label: "API Key", Kind: "password", Value: ""},
		},
		wizFormCursor: 0,
		wizFormActive: true,
		wizRunIdx:     0,
		height:        30,
		width:         120,
	}

	// Default state: empty marker.
	out := p.renderWizardForm()
	if !strings.Contains(out, "(empty)") {
		t.Fatalf("empty-value masked render missing ``(empty)``:\n%s", out)
	}

	// Reveal flag flipped, value still empty: still shows
	// ``(empty)`` and never ``(revealed —``.
	p.handleFormKey(ctrlKey('t'))
	out = p.renderWizardForm()
	if !strings.Contains(out, "(empty)") {
		t.Fatalf("empty-value revealed render missing ``(empty)``:\n%s", out)
	}
	if strings.Contains(out, "(revealed") {
		t.Fatalf("empty-value should never show reveal trailer:\n%s", out)
	}
}
