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
)

// ActionItem represents a single action in the contextual menu.
type ActionItem struct {
	Key         string // keyboard shortcut
	Label       string
	Description string
}

// ActionMenu renders a contextual action overlay for a selected item.
type ActionMenu struct {
	visible bool
	title   string
	status  string
	info    [][2]string // key-value pairs shown below actions
	actions []ActionItem
	cursor  int
	width   int
	height  int
	theme   *Theme
}

// NewActionMenu creates a new action menu.
func NewActionMenu(theme *Theme) ActionMenu {
	return ActionMenu{theme: theme}
}

// Show opens the action menu with the given content.
func (m *ActionMenu) Show(title, status string, info [][2]string, actions []ActionItem) {
	m.visible = true
	m.title = title
	m.status = status
	m.info = info
	m.actions = actions
	m.cursor = 0
}

// Hide closes the action menu.
func (m *ActionMenu) Hide() {
	m.visible = false
}

// IsVisible returns whether the menu is displayed.
func (m *ActionMenu) IsVisible() bool {
	return m.visible
}

// SetSize sets the menu dimensions.
func (m *ActionMenu) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// SelectedAction returns the action at the current cursor, or nil.
func (m *ActionMenu) SelectedAction() *ActionItem {
	if m.cursor >= 0 && m.cursor < len(m.actions) {
		return &m.actions[m.cursor]
	}
	return nil
}

// CursorUp moves the cursor up.
func (m *ActionMenu) CursorUp() {
	if m.cursor > 0 {
		m.cursor--
	}
}

// CursorDown moves the cursor down.
func (m *ActionMenu) CursorDown() {
	if m.cursor < len(m.actions)-1 {
		m.cursor++
	}
}

// View renders the action menu.
func (m *ActionMenu) View() string {
	if !m.visible {
		return ""
	}

	modalW := m.width - 20
	if modalW < 40 {
		modalW = 40
	}
	if modalW > 60 {
		modalW = 60
	}

	var b strings.Builder

	titleLine := m.theme.ModalTitle.Render(m.title)
	if m.status != "" {
		statusColor := m.theme.StateColor(m.status)
		titleLine += "  " + statusColor.Render("("+m.status+")")
	}
	b.WriteString(titleLine)
	b.WriteString("\n")
	b.WriteString(strings.Repeat("─", modalW-4))
	b.WriteString("\n")

	for i, action := range m.actions {
		key := m.theme.KeyHint.Render(fmt.Sprintf("[%s]", action.Key))
		line := fmt.Sprintf("%s %-20s %s", key, action.Label, m.theme.Dimmed.Render(action.Description))
		if i == m.cursor {
			line = SelectedStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	if len(m.info) > 0 {
		b.WriteString(strings.Repeat("─", modalW-4))
		b.WriteString("\n")
		for _, kv := range m.info {
			b.WriteString(fmt.Sprintf("%s %s\n", m.theme.ModalLabel.Render(kv[0]+":"), kv[1]))
		}
	}

	b.WriteString("\n")
	b.WriteString(m.theme.Help.Render("press esc to close, enter to execute"))

	content := b.String()
	modal := m.theme.Modal.Width(modalW).Render(content)

	return modal
}

// SkillActions returns the action items for a skill based on its current status.
func SkillActions(status string) []ActionItem {
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run security scan"},
		{Key: "i", Label: "Info", Description: "Show full details"},
	}

	switch status {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block list"},
			ActionItem{Key: "r", Label: "Restore", Description: "Restore if quarantined"},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Add to allow list"},
			ActionItem{Key: "d", Label: "Disable", Description: "Disable at runtime"},
			ActionItem{Key: "q", Label: "Quarantine", Description: "Move to quarantine"},
		)
	}

	return actions
}

// MCPActions returns the action items for an MCP server based on its current status.
func MCPActions(status string) []ActionItem {
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run security scan"},
		{Key: "i", Label: "Info", Description: "Show full details"},
	}

	switch status {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block list"},
			ActionItem{Key: "x", Label: "Unset", Description: "Remove from OpenClaw config"},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "x", Label: "Unset", Description: "Remove from OpenClaw config"},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Add to allow list"},
		)
	}

	return actions
}
