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
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
)

// modeChoice is one row in the picker. Order matches the user-facing
// presentation order: guardrail-supporting connectors first
// (openclaw, zeptoclaw), observability-only connectors below
// (codex, claudecode). The keyboard shortcut is always the connector's
// initial letter so muscle memory is trivial; `c` is reserved for
// `codex` and `k` for `claudecode` (the alternative letter on
// "claude" since c/codex would collide).
type modeChoice struct {
	wire    string // canonical config value (openclaw / zeptoclaw / codex / claudecode)
	label   string // user-facing display name
	hotkey  rune   // single-letter shortcut for this row
	guardOK bool   // does this connector support enforcement?
	tagline string // one-line description shown in the row
}

var modePickerChoices = []modeChoice{
	{wire: "openclaw", label: "OpenClaw", hotkey: 'o', guardOK: true,
		tagline: "fetch interceptor + before_tool_call plugin (full guardrail)"},
	{wire: "zeptoclaw", label: "ZeptoClaw", hotkey: 'z', guardOK: true,
		tagline: "api_base redirect + proxy response-scan (full guardrail)"},
	{wire: "claudecode", label: "Claude Code", hotkey: 'k', guardOK: false,
		tagline: "PreToolUse hooks + native OTel (observability only)"},
	{wire: "codex", label: "Codex", hotkey: 'c', guardOK: false,
		tagline: "hook scripts + native OTel + notify (observability only)"},
}

// ModePickerModal is the overlay launched by `[m]` on the Overview
// panel. It lets the operator switch the active claw connector
// without leaving the TUI; the chosen wire name is dispatched to
// `defenseclaw setup mode <wire>` by the owning Model so the same
// inheritance rules (codex/claudecode → observability-only,
// openclaw↔zeptoclaw → inherit) that the CLI command implements
// apply uniformly.
//
// The picker is intentionally small: just a choice list with a
// preview line at the bottom that explains what will happen when the
// user confirms. We don't try to present a config diff — the user
// can always read the resulting config or just use `defenseclaw
// status` afterwards. The goal here is "one keystroke to switch".
type ModePickerModal struct {
	visible bool
	cursor  int    // 0..len(modePickerChoices)-1
	current string // currently active wire name (highlighted as such)
	width   int
	height  int
	theme   *Theme
}

// NewModePickerModal allocates an empty (hidden) picker bound to
// theme. The picker is reusable: Show / Hide can be called any
// number of times without leaking selection state because Show
// resets the cursor every time.
func NewModePickerModal(theme *Theme) ModePickerModal {
	return ModePickerModal{theme: theme}
}

// Show opens the picker with currentWire highlighted. The cursor
// starts on the current row so pressing Enter immediately is a safe
// no-op (the matching `setup mode` invocation early-returns when
// target == current).
func (p *ModePickerModal) Show(currentWire string) {
	p.visible = true
	p.current = strings.ToLower(strings.TrimSpace(currentWire))
	p.cursor = 0
	for i, ch := range modePickerChoices {
		if ch.wire == p.current {
			p.cursor = i
			return
		}
	}
}

// Hide closes the picker without choosing.
func (p *ModePickerModal) Hide() { p.visible = false }

// IsVisible reports whether the picker should consume keys / paint
// over the panel.
func (p *ModePickerModal) IsVisible() bool { return p.visible }

// SetSize plumbs the surrounding TUI dimensions so the modal can
// pick a sensible width.
func (p *ModePickerModal) SetSize(w, h int) {
	p.width = w
	p.height = h
}

// CursorUp / CursorDown move the highlighted row, clamped to bounds.
func (p *ModePickerModal) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *ModePickerModal) CursorDown() {
	if p.cursor < len(modePickerChoices)-1 {
		p.cursor++
	}
}

// SelectByHotkey moves the cursor to the row whose hotkey matches r.
// Returns true iff a row was matched; the caller can choose to
// auto-confirm (Enter semantics) on a hotkey press by calling
// Selected after this returns true.
func (p *ModePickerModal) SelectByHotkey(r rune) bool {
	for i, ch := range modePickerChoices {
		if ch.hotkey == r {
			p.cursor = i
			return true
		}
	}
	return false
}

// Selected returns the wire name of the row currently under the
// cursor. Always safe to call when IsVisible() is true.
func (p *ModePickerModal) Selected() string {
	if p.cursor < 0 || p.cursor >= len(modePickerChoices) {
		return ""
	}
	return modePickerChoices[p.cursor].wire
}

// previewForSwitch returns the human-readable line that explains
// what moving from p.current to dest will do. Mirrors the
// inheritance branches in cli/defenseclaw/commands/cmd_setup.py
// _apply_connector_mode_switch so the TUI never lies about what
// the CLI is about to do.
func (p *ModePickerModal) previewForSwitch(dest string) string {
	prev := p.current
	if prev == dest {
		return "Already active — selecting will be a no-op."
	}
	prevGuard := isGuardrailSupporting(prev)
	destGuard := isGuardrailSupporting(dest)
	switch {
	case prevGuard && destGuard:
		return "Inherits current guardrail config; previous integration is restored first."
	case !destGuard:
		return "Switches to observability-only — restores previous integration, then wires hooks + OTel."
	case prevGuard != destGuard && destGuard:
		return "Enables guardrail in observe mode (no auto-enforcement) after restoring previous integration."
	}
	return ""
}

func isGuardrailSupporting(wire string) bool {
	switch strings.ToLower(strings.TrimSpace(wire)) {
	case "openclaw", "zeptoclaw":
		return true
	default:
		return false
	}
}

// View renders the modal. Returns "" when not visible so the
// owning Model can early-return without painting the overlay layer.
func (p *ModePickerModal) View() string {
	if !p.visible {
		return ""
	}

	modalW := p.width - 20
	if modalW < 56 {
		modalW = 56
	}
	if modalW > 78 {
		modalW = 78
	}

	var b strings.Builder

	if p.theme != nil {
		b.WriteString(p.theme.ModalTitle.Render("Switch active claw connector"))
	} else {
		b.WriteString("Switch active claw connector")
	}
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", modalW-4))
	b.WriteString("\n")

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	currentBadge := lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render(" (active)")

	for i, ch := range modePickerChoices {
		key := keyStyle.Render(fmt.Sprintf("[%c]", ch.hotkey))
		labelText := fmt.Sprintf("%-12s", ch.label)
		row := fmt.Sprintf("%s %s %s", key, labelText, dim.Render(ch.tagline))
		if ch.wire == p.current {
			row += currentBadge
		}
		if i == p.cursor {
			row = SelectedStyle.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}

	b.WriteString(strings.Repeat("─", modalW-4))
	b.WriteString("\n")
	dest := p.Selected()
	preview := p.previewForSwitch(dest)
	if preview != "" {
		// Prefix with the destination label so the preview makes
		// sense when read on its own.
		destLabel := dest
		for _, ch := range modePickerChoices {
			if ch.wire == dest {
				destLabel = ch.label
				break
			}
		}
		b.WriteString(dim.Render("→ ") + lipgloss.NewStyle().Bold(true).Render(destLabel) + dim.Render(": "+preview))
		b.WriteString("\n")
	}
	b.WriteString(dim.Render("DefenseClaw keeps hash-checked backups and preserves non-DefenseClaw hooks/settings on teardown."))
	b.WriteString("\n")
	b.WriteString("\n")
	if p.theme != nil {
		b.WriteString(p.theme.Help.Render("↑/↓ move  •  o/z/k/c jump  •  enter confirm  •  esc close"))
	} else {
		b.WriteString("↑/↓ move  •  o/z/k/c jump  •  enter confirm  •  esc close")
	}

	content := b.String()
	if p.theme != nil {
		return p.theme.Modal.Width(modalW).Render(content)
	}
	return content
}
