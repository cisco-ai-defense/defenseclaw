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
			fmt.Fprintf(&b, "%s %s\n", m.theme.ModalLabel.Render(kv[0]+":"), kv[1])
		}
	}

	b.WriteString("\n")
	b.WriteString(m.theme.Help.Render("press esc to close, enter to execute"))

	content := b.String()
	modal := m.theme.Modal.Width(modalW).Render(content)

	return modal
}

// SkillActions returns the action items for a skill based on its
// current status. Every key here must map to a real CLI verb in
// executeActionMenuItem's PanelSkills case or the menu silently
// no-ops on the operator (see TestExecuteActionMenuItem_SkillDispatch).
//
// Branch rules:
//   - "blocked":     unblock / allow to move out of the block list.
//   - "allowed":     block / disable. Quarantine doesn't belong here
//     because an allow-listed skill is intentionally
//     kept around; quarantine implies "make it go away".
//   - "quarantined": restore (only valid CLI path out of quarantine).
//   - "disabled":    enable to re-arm at runtime.
//   - default:       block / allow / disable / quarantine / install.
//     Install is offered to cover the case where `skill list` shows
//     a known-but-not-installed row so operators can pull it in from
//     ClawHub without dropping to the shell.
func SkillActions(status string) []ActionItem {
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run security scan"},
		{Key: "i", Label: "Info", Description: "Show full details"},
	}

	switch status {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Pin as allow-listed"},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "d", Label: "Disable", Description: "Disable at runtime"},
		)
	case "quarantined":
		actions = append(actions,
			ActionItem{Key: "r", Label: "Restore", Description: "Restore from quarantine"},
		)
	case "disabled":
		actions = append(actions,
			ActionItem{Key: "e", Label: "Enable", Description: "Enable at runtime"},
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Add to allow list"},
			ActionItem{Key: "d", Label: "Disable", Description: "Disable at runtime"},
			ActionItem{Key: "q", Label: "Quarantine", Description: "Move to quarantine"},
			ActionItem{Key: "n", Label: "Install", Description: "Install via ClawHub"},
		)
	}

	return actions
}

// PluginActions returns the action items for a plugin based on its
// current verdict, runtime enabled-state, and coarse status string.
//
// Visibility rules mirror the CLI surface in cli/defenseclaw/commands/
// cmd_plugin.py so operators can execute any supported mutation from
// the TUI without dropping to a shell:
//
//   - scan + info are always available (read-only introspection)
//   - block / unblock are driven by verdict (defense-in-depth: the
//     status field alone can lag behind admission changes)
//   - allow is offered whenever the plugin is not already allowed
//   - enable / disable mirror runtime state (gateway RPC)
//   - quarantine is gated so we never offer it on an already-quarantined
//     plugin; restore is only shown when status reports quarantine
//   - remove is always last and destructive — surface it explicitly
//     instead of hiding it behind a confirmation modal the operator
//     must discover
//
// Extra arguments (e.g. --reason) are not handled here — the executor
// shells out with just the plugin name and relies on the CLI's
// default-reason fallback. If we add a reason-prompt in future it
// should live in a follow-up form, not inline action args.
func PluginActions(verdict, status string, enabled bool) []ActionItem {
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run security scan"},
		{Key: "i", Label: "Info", Description: "Show full details"},
	}

	// Block / unblock is driven by verdict because the admission
	// gate applies before runtime state changes — a plugin can be
	// "blocked" but still technically "enabled" on disk until the
	// gateway reloads.
	switch verdict {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block list (runs plugin allow)"},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to install block list"},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to install block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Add to install allow list"},
		)
	}

	// Runtime enable/disable via gateway RPC. Surfaces regardless of
	// verdict — an allowed-and-enabled plugin is still disable-able.
	if enabled {
		actions = append(actions,
			ActionItem{Key: "d", Label: "Disable", Description: "Disable at runtime (gateway RPC)"},
		)
	} else {
		actions = append(actions,
			ActionItem{Key: "e", Label: "Enable", Description: "Enable at runtime (gateway RPC)"},
		)
	}

	// Quarantine / restore are driven off status because that's where
	// the PluginEnforcer records quarantine state in the audit
	// store (see plugin_enforcer.is_quarantined).
	if strings.Contains(strings.ToLower(status), "quarantine") {
		actions = append(actions,
			ActionItem{Key: "r", Label: "Restore", Description: "Restore from quarantine"},
		)
	} else {
		actions = append(actions,
			ActionItem{Key: "q", Label: "Quarantine", Description: "Move files to quarantine dir"},
		)
	}

	actions = append(actions,
		ActionItem{Key: "x", Label: "Remove", Description: "Delete plugin files from disk"},
	)

	return actions
}

// ToolActions returns the action items for a tool-policy row (a
// `tool.<name>` or `tool.<name>@<scope>` action entry) based on the
// current Install decision recorded by the admission gate.
//
// The surface is deliberately narrower than Skills/MCPs/Plugins:
// tools don't have a scanner of their own — their provenance is the
// owning skill or MCP server, so "scan" would be a no-op. Tools also
// don't have a runtime enable/disable toggle (that's modelled at the
// skill/MCP layer). What remains is the install-gate outcome:
// block / allow / unblock. The key map intentionally matches
// SkillActions/PluginActions (b/a/u + i) so muscle memory carries over.
func ToolActions(status string) []ActionItem {
	actions := []ActionItem{
		{Key: "i", Label: "Info", Description: "Show full details"},
	}
	switch status {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block/allow list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Pin as allow-listed"},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block/allow list"},
			ActionItem{Key: "b", Label: "Block", Description: "Add to tool block list"},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to tool block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Pin as allow-listed"},
		)
	}
	return actions
}

// MCPActions returns the action items for an MCP server based on its
// current status. The connector argument is the active agent framework
// (openclaw / zeptoclaw / claudecode / codex) so the "Unset" item's
// description names the right config file (openclaw config, ~/.claude/
// settings.json, ./.mcp.json, ~/.zeptoclaw/config.json), and so we can
// surface a clear "read-only" hint for ZeptoClaw which does not
// support MCP write through the CLI (connector_paths.set_mcp_server
// raises MCPWriteUnsupportedError for it).
func MCPActions(status, connector string) []ActionItem {
	actions := []ActionItem{
		{Key: "s", Label: "Scan", Description: "Run security scan"},
		{Key: "i", Label: "Info", Description: "Show full details"},
	}

	connector = strings.TrimSpace(connector)
	unsetTarget := mcpUnsetTargetForConnector(connector)
	unsetDesc := "Remove from " + unsetTarget
	if connector == "zeptoclaw" {
		unsetDesc = "Read-only — edit " + unsetTarget + " manually"
	}

	switch status {
	case "blocked":
		actions = append(actions,
			ActionItem{Key: "u", Label: "Unblock", Description: "Remove from block list"},
			ActionItem{Key: "x", Label: "Unset", Description: unsetDesc},
		)
	case "allowed":
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "x", Label: "Unset", Description: unsetDesc},
		)
	default:
		actions = append(actions,
			ActionItem{Key: "b", Label: "Block", Description: "Add to block list"},
			ActionItem{Key: "a", Label: "Allow", Description: "Add to allow list"},
		)
	}

	return actions
}

func mcpUnsetTargetForConnector(connector string) string {
	switch connector {
	case "claudecode":
		return "~/.claude/settings.json"
	case "codex":
		return "./.mcp.json"
	case "zeptoclaw":
		return "~/.zeptoclaw/config.json"
	default:
		return "OpenClaw config"
	}
}
