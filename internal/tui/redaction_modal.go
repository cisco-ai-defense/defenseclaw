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

	"charm.land/lipgloss/v2"
)

// RedactionToggleModal is the [R]-from-Logs confirmation overlay.
// We deliberately keep it richer than the connector picker because
// the privacy implications of flipping redaction off are
// asymmetric: re-enabling is harmless, disabling persistently
// rewrites the audit DB / Splunk / OTel contract for every future
// event. The modal makes the destination state, the affected
// sinks, and the recovery command unambiguous in a single screen.
//
// The modal is stateful only over its own visibility + the cached
// "currently-disabled" flag. The actual flip is dispatched by the
// owning Model so the subprocess plumbing
// (defenseclaw setup redaction <on|off> --yes) lives next to the
// other CLI dispatches in app.go.
type RedactionToggleModal struct {
	visible           bool
	width, height     int
	theme             *Theme
	currentlyDisabled bool
}

// NewRedactionToggleModal allocates a hidden modal bound to theme.
// Reusable: Show / Hide may be called any number of times.
func NewRedactionToggleModal(theme *Theme) RedactionToggleModal {
	return RedactionToggleModal{theme: theme}
}

// Show opens the modal with the current redaction state captured
// so the caller can decide which CLI subcommand to dispatch on
// confirm. ``currentlyDisabled`` mirrors ``redaction.DisableAll()``
// at the moment of the keypress; the modal does NOT re-poll the
// flag because that could race with a setup-redaction subprocess
// that hasn't finished yet — the operator should see consistent
// "you're about to flip from X to Y" text for the entire prompt.
func (r *RedactionToggleModal) Show(currentlyDisabled bool) {
	r.visible = true
	r.currentlyDisabled = currentlyDisabled
}

// Hide closes the modal without dispatching anything.
func (r *RedactionToggleModal) Hide() { r.visible = false }

// IsVisible reports whether the modal should consume keys / paint.
func (r *RedactionToggleModal) IsVisible() bool { return r.visible }

// SetSize plumbs surrounding TUI dimensions so the View() box can
// pick a sensible width.
func (r *RedactionToggleModal) SetSize(w, h int) {
	r.width = w
	r.height = h
}

// CurrentlyDisabled reports the cached state at Show() time.
// Owning Model uses this to pick the "on" or "off" subcommand.
func (r *RedactionToggleModal) CurrentlyDisabled() bool { return r.currentlyDisabled }

// DesiredAction returns the CLI subcommand (``on`` or ``off``)
// that flipping the current state would produce. Caller passes
// this directly to ``defenseclaw setup redaction <action> --yes``.
func (r *RedactionToggleModal) DesiredAction() string {
	if r.currentlyDisabled {
		return "on"
	}
	return "off"
}

// View renders the modal box. Layout:
//
//	┌────────────────────────────────────────────────────┐
//	│  Redaction kill-switch                             │
//	│                                                    │
//	│  Current state: REDACTED  (placeholders only)      │
//	│  Will become:   RAW       (full prompts to Splunk) │
//	│                                                    │
//	│  Sinks affected by RAW state:                      │
//	│    • SQLite audit DB                               │
//	│    • Splunk HEC / OTel logs / webhooks             │
//	│    • TUI Logs panel & gateway.log                  │
//	│                                                    │
//	│  Only proceed if every downstream sink lives in    │
//	│  the same trust boundary as this install.          │
//	│                                                    │
//	│  [Enter] confirm   [esc] cancel                    │
//	└────────────────────────────────────────────────────┘
//
// The colour scheme reuses the panel's red/green vocabulary so the
// "going RAW" branch shouts at the operator without needing
// dedicated ANSI codes; "going REDACTED" stays calm.
func (r *RedactionToggleModal) View() string {
	if !r.visible {
		return ""
	}

	desired := r.DesiredAction()
	currentLabel := "REDACTED  (placeholders only)"
	desiredLabel := "RAW       (full prompts to ALL sinks)"
	if r.currentlyDisabled {
		currentLabel = "RAW       (full prompts to ALL sinks)"
		desiredLabel = "REDACTED  (placeholders only)"
	}

	red := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	green := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))

	currentStyled := green.Render(currentLabel)
	desiredStyled := red.Render(desiredLabel)
	if r.currentlyDisabled {
		currentStyled = red.Render(currentLabel)
		desiredStyled = green.Render(desiredLabel)
	}

	var body strings.Builder
	body.WriteString(headerStyle.Render("Redaction kill-switch"))
	body.WriteString("\n\n")
	body.WriteString("Current state: " + currentStyled)
	body.WriteString("\n")
	body.WriteString("Will become:   " + desiredStyled)
	body.WriteString("\n\n")

	if desired == "off" {
		body.WriteString(red.Render("⚠ Disabling redaction") + " writes RAW content to:")
		body.WriteString("\n")
		body.WriteString(dim.Render("    • SQLite audit DB"))
		body.WriteString("\n")
		body.WriteString(dim.Render("    • Splunk HEC, OTel log exporters, webhooks"))
		body.WriteString("\n")
		body.WriteString(dim.Render("    • gateway.log + this Logs panel"))
		body.WriteString("\n\n")
		body.WriteString(dim.Render("Only proceed if every downstream sink lives in the"))
		body.WriteString("\n")
		body.WriteString(dim.Render("same trust boundary as this install."))
	} else {
		body.WriteString(green.Render("Re-enables redaction") + " — placeholders return")
		body.WriteString("\n")
		body.WriteString(dim.Render("on the next sidecar boot. Existing already-emitted"))
		body.WriteString("\n")
		body.WriteString(dim.Render("audit rows / Splunk events stay as they were written."))
	}
	body.WriteString("\n\n")
	body.WriteString(dim.Render("[Enter] confirm    [esc] cancel"))

	w := r.width - 8
	if w < 56 {
		w = 56
	}
	if w > 80 {
		w = 80
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("196")).
		Padding(1, 2).
		Width(w).
		Render(body.String())

	return box
}
