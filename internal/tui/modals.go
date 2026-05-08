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

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

type ConfigDiffModal struct {
	Active bool
	Diff   []ConfigDiffEntry
}

func (m ConfigDiffModal) View(width, height int, theme *Theme) string {
	if !m.Active {
		return ""
	}
	box, _ := m.renderBox(width, height, theme)
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func (m ConfigDiffModal) ClickAction(x, y, width, height int, theme *Theme) string {
	if !m.Active {
		return ""
	}
	box, hintY := m.renderBox(width, height, theme)
	rect := centeredRenderedBox(box, width, height)
	if !rect.contains(x, y) {
		return "cancel"
	}
	row := rect.y + 2 + hintY
	if y != row {
		return ""
	}
	run := newClickBox("save", rect.x+3, row, 31, 1)
	cancel := newClickBox("cancel", rect.x+36, row, 14, 1)
	if id, ok := hitClickBox([]clickBox{run, cancel}, x, y); ok {
		return id
	}
	return ""
}

func (m ConfigDiffModal) renderBox(width, height int, theme *Theme) (string, int) {
	var b strings.Builder
	boxW := min(width-8, 100)
	if boxW < 60 {
		boxW = width - 4
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Render("Review Config Changes")
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	warn := lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	b.WriteString(title + "\n\n")
	if len(m.Diff) == 0 {
		b.WriteString(dim.Render("No pending changes.") + "\n")
	} else {
		for i, d := range m.Diff {
			if i >= height-10 {
				fmt.Fprintf(&b, "%s\n", dim.Render(fmt.Sprintf("... %d more changes", len(m.Diff)-i)))
				break
			}
			key := d.Key
			if d.Secret {
				key += " " + warn.Render("(masked)")
			}
			fmt.Fprintf(&b, "  %s\n", key)
			fmt.Fprintf(&b, "    before: %s\n", dim.Render(truncateStr(d.Before, boxW-16)))
			fmt.Fprintf(&b, "    after:  %s\n", truncateStr(d.After, boxW-16))
		}
	}
	b.WriteString("\n" + dim.Render("[Enter] Save and queue restart  [Esc] Cancel"))
	hintY := lipgloss.Height(b.String()) - 1
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(1, 2).
		Width(boxW)
	return style.Render(b.String()), hintY
}

type CommandPreviewModal struct {
	Active bool
	Intent CommandIntent
}

func (m CommandPreviewModal) View(width, height int, theme *Theme) string {
	if !m.Active {
		return ""
	}
	box, _ := m.renderBox(width, height, theme)
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}

func (m CommandPreviewModal) ClickAction(x, y, width, height int, theme *Theme) string {
	if !m.Active {
		return ""
	}
	box, hintY := m.renderBox(width, height, theme)
	rect := centeredRenderedBox(box, width, height)
	if !rect.contains(x, y) {
		return "cancel"
	}
	row := rect.y + 2 + hintY
	if y != row {
		return ""
	}
	run := newClickBox("run", rect.x+3, row, 13, 1)
	cancel := newClickBox("cancel", rect.x+17, row, 14, 1)
	if id, ok := hitClickBox([]clickBox{run, cancel}, x, y); ok {
		return id
	}
	return ""
}

func (m CommandPreviewModal) renderBox(width, height int, theme *Theme) (string, int) {
	var b strings.Builder
	boxW := min(width-8, 96)
	if boxW < 56 {
		boxW = width - 4
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("230")).Render("Confirm Command")
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	risk := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")).Render(string(m.Intent.Risk))
	b.WriteString(title + "\n\n")
	b.WriteString(fmt.Sprintf("  Command: %s\n", truncateStr(m.Intent.MaskedCommandLine(), boxW-13)))
	b.WriteString(fmt.Sprintf("  Origin:  %s\n", emptyAs(m.Intent.Origin, "unknown")))
	b.WriteString(fmt.Sprintf("  Risk:    %s\n", risk))
	b.WriteString(fmt.Sprintf("  Change:  %s\n", m.Intent.Summary))
	b.WriteString(fmt.Sprintf("  Restart: %s\n", m.Intent.RestartEffect))
	if m.Intent.HasSecretArgs() {
		b.WriteString("  Secrets: values are masked in preview and activity\n")
	}
	b.WriteString("\n" + dim.Render("[Enter] Run  [Esc] Cancel"))
	hintY := lipgloss.Height(b.String()) - 1
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("214")).
		Padding(1, 2).
		Width(boxW)
	return style.Render(b.String()), hintY
}

func emptyAs(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

func keyConfirms(msg tea.KeyPressMsg) bool {
	return msg.String() == "enter"
}
