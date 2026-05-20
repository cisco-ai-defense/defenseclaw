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
// (openclaw, zeptoclaw), hook/observability connectors below. The keyboard
// shortcut is stable and unique; collision cases use a memorable alternate.
type modeChoice struct {
	wire    string // canonical connector config value
	label   string // user-facing display name
	hotkey  rune   // single-letter shortcut for this row
	guardOK bool   // does this connector use proxy-backed guardrail setup?
	tagline string // one-line description shown in the row
}

var modePickerChoices = []modeChoice{
	{wire: "openclaw", label: "OpenClaw", hotkey: 'o', guardOK: true,
		tagline: "fetch interceptor + before_tool_call plugin (full guardrail)"},
	{wire: "zeptoclaw", label: "ZeptoClaw", hotkey: 'z', guardOK: true,
		tagline: "api_base redirect + proxy response-scan (full guardrail)"},
	{wire: "claudecode", label: "Claude Code", hotkey: 'k', guardOK: false,
		tagline: "PreToolUse hooks + native OTel + CodeGuard plugin"},
	{wire: "codex", label: "Codex", hotkey: 'c', guardOK: false,
		tagline: "hook scripts + native OTel + notify + CodeGuard skill"},
	{wire: "hermes", label: "Hermes", hotkey: 'h', guardOK: false,
		tagline: "shell hooks + vendor-native block events"},
	{wire: "cursor", label: "Cursor", hotkey: 'u', guardOK: false,
		tagline: "command hooks + event-scoped ask/block"},
	{wire: "windsurf", label: "Windsurf", hotkey: 'w', guardOK: false,
		tagline: "Cascade hooks + fail-open block decisions"},
	{wire: "geminicli", label: "Gemini CLI", hotkey: 'g', guardOK: false,
		tagline: "settings.json hooks + structured deny responses"},
	{wire: "copilot", label: "Copilot", hotkey: 'p', guardOK: false,
		tagline: "workspace hooks + native pre-tool approval"},
	{wire: "openhands", label: "OpenHands", hotkey: 'n', guardOK: false,
		tagline: "repo-local hooks + exit-code deny responses"},
}

// ModePickerModal is the overlay launched by `[m]` on the Overview
// panel. It lets the operator run first-class connector setup without
// leaving the TUI; the chosen wire name is dispatched to
// `defenseclaw setup <connector> --yes` by the owning Model. The
// command-palette `setup mode` path remains available as a fast
// scripted switch, but Overview favors the full setup flow.
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
// starts on the current row so pressing Enter immediately re-runs
// the active connector setup. This is intentional: setup can refresh
// hooks/runtime files even when the selected connector is unchanged.
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

func (p *ModePickerModal) ChoiceAt(x, y int) (int, bool) {
	if !p.visible {
		return 0, false
	}
	view := p.View()
	rect := newClickBox("mode", 0, 0, lipgloss.Width(view), lipgloss.Height(view))
	if !rect.contains(x, y) {
		return 0, false
	}
	idx := y - 4 // border + top padding + title + separator
	if idx < 0 || idx >= len(modePickerChoices) {
		return 0, true
	}
	p.cursor = idx
	return idx, true
}

// previewForSwitch returns the human-readable line that explains
// what confirming dest will do. It describes the full setup aliases
// (`setup openclaw`, `setup zeptoclaw`, `setup codex`, ...), not the
// fast/scripted `setup mode` fallback.
func (p *ModePickerModal) previewForSwitch(dest string) string {
	prev := p.current
	if prev == dest {
		return "Already active — setup will be re-run to refresh hooks, config, and runtime files."
	}
	destGuard := isGuardrailSupporting(dest)
	if destGuard {
		return "Runs proxy-backed connector setup and pins claw.mode plus guardrail.connector; preserves the existing guardrail.mode."
	}
	return "Runs hook-driven connector setup — wires hooks, native OTel where supported, and CodeGuard surfaces. Honors guardrail.mode (action blocks via the pre-tool hook)."
}

func isGuardrailSupporting(wire string) bool {
	switch strings.ToLower(strings.TrimSpace(wire)) {
	case "openclaw", "zeptoclaw":
		return true
	default:
		return false
	}
}

func connectorSetupAlias(wire string) string {
	switch strings.ToLower(strings.TrimSpace(wire)) {
	case "claudecode", "claude-code", "claude_code":
		return "claude-code"
	case "openclaw", "zeptoclaw", "codex", "hermes", "cursor", "windsurf", "geminicli", "copilot", "openhands":
		return strings.ToLower(strings.TrimSpace(wire))
	default:
		return ""
	}
}

func connectorSetupCommandForMode(wire string) ([]string, string) {
	alias := connectorSetupAlias(wire)
	if alias == "" {
		return nil, ""
	}
	return []string{"setup", alias, "--yes"}, "setup " + alias
}

func connectorSetupCommandForModeWithGuardrailMode(wire, mode string) ([]string, string) {
	args, display := connectorSetupCommandForMode(wire)
	if len(args) == 0 || isGuardrailSupporting(wire) {
		return args, display
	}
	normalizedMode := "observe"
	if strings.EqualFold(strings.TrimSpace(mode), "action") {
		normalizedMode = "action"
	}
	return append(args, "--mode", normalizedMode), display
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
		b.WriteString(p.theme.Help.Render("↑/↓ move  •  o/z/k/c/h/u/w/g/p/n jump  •  enter confirm  •  esc close"))
	} else {
		b.WriteString("↑/↓ move  •  o/z/k/c/h/u/w/g/p/n jump  •  enter confirm  •  esc close")
	}

	content := b.String()
	if p.theme != nil {
		return p.theme.Modal.Width(modalW).Render(content)
	}
	return content
}
