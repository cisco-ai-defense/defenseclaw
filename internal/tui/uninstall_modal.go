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

type UninstallOption int

const (
	UninstallDryRun UninstallOption = iota
	UninstallKeepData
	UninstallWipeData
)

type uninstallChoice struct {
	option UninstallOption
	hotkey rune
	label  string
	detail string
	danger bool
}

var uninstallChoices = []uninstallChoice{
	{
		option: UninstallDryRun,
		hotkey: 'p',
		label:  "Preview plan",
		detail: "Runs uninstall --dry-run and changes nothing.",
	},
	{
		option: UninstallKeepData,
		hotkey: 'u',
		label:  "Uninstall, keep data",
		detail: "Reverts hooks/plugin integration and keeps ~/.defenseclaw.",
		danger: true,
	},
	{
		option: UninstallWipeData,
		hotkey: 'a',
		label:  "Uninstall and wipe data",
		detail: "Also deletes ~/.defenseclaw audit DB, config, and secrets.",
		danger: true,
	},
}

// UninstallModal is the guarded Overview [X] flow for uninstalling.
// It defaults to dry-run and requires Enter to execute the selected row.
type UninstallModal struct {
	visible       bool
	cursor        int
	width, height int
	theme         *Theme
}

func NewUninstallModal(theme *Theme) UninstallModal {
	return UninstallModal{theme: theme}
}

func (m *UninstallModal) Show() {
	m.visible = true
	m.cursor = 0
}

func (m *UninstallModal) Hide() { m.visible = false }

func (m *UninstallModal) IsVisible() bool { return m.visible }

func (m *UninstallModal) SetSize(w, h int) {
	m.width = w
	m.height = h
}

func (m *UninstallModal) CursorUp() {
	if m.cursor > 0 {
		m.cursor--
	}
}

func (m *UninstallModal) CursorDown() {
	if m.cursor < len(uninstallChoices)-1 {
		m.cursor++
	}
}

func (m *UninstallModal) SelectByHotkey(r rune) bool {
	for i, ch := range uninstallChoices {
		if ch.hotkey == r {
			m.cursor = i
			return true
		}
	}
	return false
}

func (m *UninstallModal) Selected() UninstallOption {
	if m.cursor < 0 || m.cursor >= len(uninstallChoices) {
		return UninstallDryRun
	}
	return uninstallChoices[m.cursor].option
}

func (m *UninstallModal) View() string {
	if !m.visible {
		return ""
	}

	w := m.width - 12
	if w < 62 {
		w = 62
	}
	if w > 86 {
		w = 86
	}

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Render("Uninstall DefenseClaw")
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	keyStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	dangerStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true)
	normalStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	var b strings.Builder
	b.WriteString(title)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("-", w-4))
	b.WriteString("\n\n")
	b.WriteString(dim.Render("Choose what the TUI should run. The default is preview-only."))
	b.WriteString("\n\n")

	for i, ch := range uninstallChoices {
		labelStyle := normalStyle
		if ch.danger {
			labelStyle = dangerStyle
		}
		row := fmt.Sprintf("%s %-25s %s",
			keyStyle.Render(fmt.Sprintf("[%c]", ch.hotkey)),
			labelStyle.Render(ch.label),
			dim.Render(ch.detail),
		)
		if i == m.cursor {
			row = SelectedStyle.Render(row)
		}
		b.WriteString(row)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dangerStyle.Render("Destructive rows pass --yes because this modal is the confirmation step."))
	b.WriteString("\n")
	b.WriteString(dim.Render("Use the dry-run row first if you want to inspect the plan."))
	b.WriteString("\n\n")
	b.WriteString(dim.Render("[Enter] run selected    [up/down] choose    [p/u/a] select    [esc] cancel"))

	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("196")).
		Padding(1, 2).
		Width(w).
		Render(b.String())

	return box
}
