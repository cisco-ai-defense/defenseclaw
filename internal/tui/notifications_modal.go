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

// NotificationsToggleModal is the [N]-from-Overview/Logs confirmation
// overlay for the user-session OS notifier. Lighter-weight than
// RedactionToggleModal because the privacy implications are
// symmetric (both directions are reversible and never alter
// persisted audit content) — the modal exists so the operator
// confirms the change explicitly rather than triggering it on a
// stray keystroke, and to surface what the dispatcher actually
// covers (block / would-block / approval) so a "yes" answer is
// informed.
//
// Like RedactionToggleModal, the modal is stateful only over its
// visibility + the cached "currently-enabled" flag; the actual flip
// is dispatched by the owning Model so the subprocess plumbing
// (defenseclaw setup notifications <on|off> --yes) lives next to
// the other CLI dispatches in app.go.
type NotificationsToggleModal struct {
	visible          bool
	width, height    int
	theme            *Theme
	currentlyEnabled bool
}

// NewNotificationsToggleModal allocates a hidden modal bound to theme.
// Reusable: Show / Hide may be called any number of times.
func NewNotificationsToggleModal(theme *Theme) NotificationsToggleModal {
	return NotificationsToggleModal{theme: theme}
}

// Show opens the modal with the current notifications state captured
// so the caller can decide which CLI subcommand to dispatch on
// confirm. “currentlyEnabled“ mirrors the “notifications.enabled“
// config field at the moment of the keypress; we cache rather than
// re-poll so the modal copy stays consistent across the prompt.
func (n *NotificationsToggleModal) Show(currentlyEnabled bool) {
	n.visible = true
	n.currentlyEnabled = currentlyEnabled
}

// Hide closes the modal without dispatching anything.
func (n *NotificationsToggleModal) Hide() { n.visible = false }

// IsVisible reports whether the modal should consume keys / paint.
func (n *NotificationsToggleModal) IsVisible() bool { return n.visible }

// SetSize plumbs surrounding TUI dimensions so the View() box can
// pick a sensible width.
func (n *NotificationsToggleModal) SetSize(w, h int) {
	n.width = w
	n.height = h
}

// CurrentlyEnabled reports the cached state at Show() time.
// Owning Model uses this to pick the "on" or "off" subcommand.
func (n *NotificationsToggleModal) CurrentlyEnabled() bool { return n.currentlyEnabled }

// DesiredAction returns the CLI subcommand (“on“ or “off“)
// that flipping the current state would produce. Caller passes
// this directly to “defenseclaw setup notifications <action> --yes“.
func (n *NotificationsToggleModal) DesiredAction() string {
	if n.currentlyEnabled {
		return "off"
	}
	return "on"
}

// View renders the modal box. Layout intentionally parallels
// RedactionToggleModal so an operator who's seen one immediately
// understands the other.
func (n *NotificationsToggleModal) View() string {
	if !n.visible {
		return ""
	}

	desired := n.DesiredAction()
	currentLabel := "ON  (toasts on every block / approval)"
	desiredLabel := "OFF (no toasts; audit log unchanged)"
	if !n.currentlyEnabled {
		currentLabel = "OFF (no toasts; audit log unchanged)"
		desiredLabel = "ON  (toasts on every block / approval)"
	}

	green := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Bold(true)
	yellow := lipgloss.NewStyle().Foreground(lipgloss.Color("214")).Bold(true)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230"))

	currentStyled := green.Render(currentLabel)
	desiredStyled := yellow.Render(desiredLabel)
	if !n.currentlyEnabled {
		currentStyled = yellow.Render(currentLabel)
		desiredStyled = green.Render(desiredLabel)
	}

	var body strings.Builder
	body.WriteString(headerStyle.Render("Desktop notifications"))
	body.WriteString("\n\n")
	body.WriteString("Current state: " + currentStyled)
	body.WriteString("\n")
	body.WriteString("Will become:   " + desiredStyled)
	body.WriteString("\n\n")

	if desired == "on" {
		body.WriteString(green.Render("Turning notifications ON") + " surfaces:")
		body.WriteString("\n")
		body.WriteString(dim.Render("    • Hook / guardrail / asset-policy blocks"))
		body.WriteString("\n")
		body.WriteString(dim.Render("    • Observe-mode would-blocks"))
		body.WriteString("\n")
		body.WriteString(dim.Render("    • Pending HITL approval prompts"))
		body.WriteString("\n\n")
		body.WriteString(dim.Render("Toasts are informational — clicking does not"))
		body.WriteString("\n")
		body.WriteString(dim.Render("approve anything. Reply in chat / TUI as today."))
	} else {
		body.WriteString(yellow.Render("Turning notifications OFF") + " stops the toaster.")
		body.WriteString("\n")
		body.WriteString(dim.Render("Audit DB / Splunk / OTel / webhooks are NOT affected;"))
		body.WriteString("\n")
		body.WriteString(dim.Render("they continue to record blocks and approvals."))
		body.WriteString("\n\n")
		body.WriteString(dim.Render("Per-category and per-source filters in"))
		body.WriteString("\n")
		body.WriteString(dim.Render("notifications.* let you keep some toasts and silence"))
		body.WriteString("\n")
		body.WriteString(dim.Render("others without flipping the master switch."))
	}
	body.WriteString("\n\n")
	body.WriteString(dim.Render("[Enter] confirm    [esc] cancel"))

	w := n.width - 8
	if w < 56 {
		w = 56
	}
	if w > 80 {
		w = 80
	}

	// Off→On (operator opting in)  → green border (positive action).
	// On→Off (operator opting out) → yellow border (cautionary, but
	// not red — flipping notifications off is fully reversible and
	// never alters audit trails, unlike the redaction kill-switch).
	border := lipgloss.Color("46")
	if n.currentlyEnabled {
		border = lipgloss.Color("214")
	}

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(1, 2).
		Width(w).
		Render(body.String())

	return box
}
