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

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// toolItem is a flattened view of an audit.ActionEntry for the Tools
// panel. We surface only the fields an operator cares about at the list
// level — scoped entries (e.g. `delete_file@filesystem`) keep their full
// target_name and are parsed into Name+Scope at render time so both
// parts remain searchable. Findings/scan columns are absent on purpose:
// tools don't have their own scanner (they're enforced at the
// skill/mcp gate), so there's nothing to display there.
type toolItem struct {
	// Name is the bare tool name as it appears in policy rows.
	// For scoped entries (e.g. "write_file@filesystem") this is
	// just the tool part ("write_file"); the scope is split off
	// into Scope. Keeping them separate lets the View render a
	// two-column layout without re-parsing on every redraw.
	Name   string
	Scope  string
	Status string
	Reason string
	Time   string
	// TargetName is the raw audit store target_name used for
	// CLI dispatch — scoped mutations must preserve the "@scope"
	// suffix so PolicyEngine can match the same row it resolved.
	TargetName string
}

// ToolsPanel lists block/allow entries of type "tool" from the audit
// store. It mirrors SkillsPanel's surface (Refresh, Cursor*, Selected,
// ScrollBy, ScrollOffset, Count, FilteredCount, CursorAt, IsDetailOpen,
// ToggleDetail, SetSize, View) so callers in app.go can use the same
// switch-case plumbing as every other list panel.
//
// Unlike Skills, tools have no findings UI because tool enforcement
// happens at skill/MCP load time — the decision surface is just
// install (block/allow). If we ever add a tool-scanner this panel
// should grow a findings panel mirroring SkillsPanel.renderDetail.
type ToolsPanel struct {
	items      []toolItem
	cursor     int
	width      int
	height     int
	store      *audit.Store
	message    string
	detailOpen bool
}

// NewToolsPanel constructs a tools panel bound to the shared audit
// store. A nil store is allowed — Refresh becomes a no-op and View
// renders an empty hint so tests that don't care about tool content
// don't need a full SQLite stub.
func NewToolsPanel(store *audit.Store) ToolsPanel {
	return ToolsPanel{store: store}
}

// Refresh re-pulls the tool entries from the audit store. Called on
// panel open, on `r` keypress, and after any successful CLI mutation
// dispatched through the action menu.
func (p *ToolsPanel) Refresh() {
	if p.store == nil {
		return
	}
	p.items = nil
	entries, err := p.store.ListActionsByType("tool")
	if err != nil {
		p.message = fmt.Sprintf("Error loading tools: %v", err)
		return
	}
	for _, e := range entries {
		// Scoped entries use the `<tool>@<scope>` convention
		// established by cli/defenseclaw/enforce/policy.py
		// (see also cmd_tool.block/allow --source). Split so the
		// View can render them in two columns without reparsing.
		name := e.TargetName
		scope := ""
		if idx := strings.LastIndex(name, "@"); idx > 0 {
			scope = name[idx+1:]
			name = name[:idx]
		}
		status := "active"
		switch e.Actions.Install {
		case "block":
			status = "blocked"
		case "allow":
			status = "allowed"
		}
		p.items = append(p.items, toolItem{
			Name:       name,
			Scope:      scope,
			Status:     status,
			Reason:     e.Reason,
			Time:       e.UpdatedAt.Format("2006-01-02 15:04"),
			TargetName: e.TargetName,
		})
	}
	p.message = ""
	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
}

// SetSize lets app.go propagate width/height to the panel. Called
// from the top-level resize handler; rendering relies on these to
// truncate long reasons and compute viewport.
func (p *ToolsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *ToolsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *ToolsPanel) CursorDown() {
	if p.cursor < len(p.items)-1 {
		p.cursor++
	}
}

// Selected returns the currently highlighted tool, or nil if the list
// is empty. Callers must not retain the pointer across Refresh — the
// backing slice may be reallocated when entries come and go.
func (p *ToolsPanel) Selected() *toolItem {
	if p.cursor < 0 || p.cursor >= len(p.items) {
		return nil
	}
	return &p.items[p.cursor]
}

func (p *ToolsPanel) Count() int         { return len(p.items) }
func (p *ToolsPanel) FilteredCount() int { return len(p.items) }
func (p *ToolsPanel) CursorAt() int      { return p.cursor }

func (p *ToolsPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if maxVisible < 1 {
		maxVisible = 10
	}
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *ToolsPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.items) {
		i = len(p.items) - 1
	}
	p.cursor = i
}

func (p *ToolsPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.items) {
		p.cursor = len(p.items) - 1
	}
}

func (p *ToolsPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *ToolsPanel) ToggleDetail()      { p.detailOpen = !p.detailOpen }

func (p *ToolsPanel) listHeight() int {
	h := p.height - 4 // summary(1) + sep(1) + header(1) + margin(1)
	if p.detailOpen {
		h -= 8
	}
	if h < 3 {
		h = 3
	}
	return h
}

// BlockedCount returns the number of tools currently on the block
// list. The Overview panel uses this to render the "N blocked" badge,
// matching the pattern already used by SkillsPanel/MCPsPanel.
func (p *ToolsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

// View renders the Tools panel. Layout is intentionally close to
// SkillsPanel so operators switching between the two don't suffer
// cognitive whiplash: summary bar → separator → header → rows. Tools
// rows also include a SCOPE column because scoped policy is the
// main reason operators land on this panel (blocking `write_file`
// globally is rare; blocking `write_file@filesystem` is common).
func (p *ToolsPanel) View() string {
	if p.message != "" {
		return p.message
	}

	var b strings.Builder

	blocked := 0
	allowed := 0
	for _, i := range p.items {
		switch i.Status {
		case "blocked":
			blocked++
		case "allowed":
			allowed++
		}
	}
	blockedBadge := lipgloss.NewStyle().
		Background(lipgloss.Color("196")).
		Foreground(lipgloss.Color("16")).
		Bold(true).
		Render(fmt.Sprintf(" %d blocked ", blocked))
	allowedBadge := lipgloss.NewStyle().
		Background(lipgloss.Color("46")).
		Foreground(lipgloss.Color("16")).
		Bold(true).
		Render(fmt.Sprintf(" %d allowed ", allowed))
	totalLabel := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Render(fmt.Sprintf("%d total", len(p.items)))

	b.WriteString("  " + blockedBadge + "  " + allowedBadge + "   " + totalLabel + "\n")
	sepW := p.width
	if sepW <= 0 {
		sepW = 80
	}
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", sepW)))
	b.WriteString("\n")

	if len(p.items) == 0 {
		return b.String() + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			"  No tools in the block/allow list.\n  Press : then type \"tool block <name>\" or \"tool allow <name> --source <skill|mcp>\"",
		)
	}

	header := fmt.Sprintf("  %-14s %-28s %-18s %-32s %-16s", "STATUS", "NAME", "SCOPE", "REASON", "SINCE")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	maxVisible := p.listHeight()
	if maxVisible < 1 {
		maxVisible = 10
	}
	start := 0
	if p.cursor >= maxVisible {
		start = p.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(p.items) {
		end = len(p.items)
	}

	for i := start; i < end; i++ {
		item := p.items[i]
		badge := statusBadge(item.Status)
		name := truncate(item.Name, 28)
		scope := item.Scope
		if scope == "" {
			scope = "(global)"
		}
		scope = truncate(scope, 18)
		reason := truncate(item.Reason, 32)

		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		line := fmt.Sprintf("%s%s %-28s %-18s %-32s %-16s",
			pointer, badge, name, scope, reason, item.Time)
		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(p.width).Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	if len(p.items) > maxVisible {
		b.WriteString("\n")
		pct := 0
		if len(p.items) > 0 {
			pct = (end * 100) / len(p.items)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  ↕ %d–%d of %d (%d%%)", start+1, end, len(p.items), pct),
		))
	}

	if p.detailOpen {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}
	return b.String()
}

// renderDetail draws the expanded per-tool context box. Kept compact
// because tools have no scan findings or gateway runtime state —
// everything an operator needs (scope, status, reason, updated_at)
// fits on a few lines.
func (p *ToolsPanel) renderDetail() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Width(p.width - 4).
		MaxHeight(8)
	label := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	val := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true)

	var d strings.Builder
	d.WriteString(title.Render(fmt.Sprintf("  %s  %s", statusBadge(sel.Status), sel.Name)))
	d.WriteString("\n")
	scope := sel.Scope
	if scope == "" {
		scope = "(global)"
	}
	d.WriteString(label.Render("  Scope: ") + val.Render(scope) + "\n")
	d.WriteString(label.Render("  Status: ") + val.Render(strings.ToUpper(sel.Status)))
	d.WriteString(label.Render("    Since: ") + val.Render(sel.Time) + "\n")
	if sel.Reason != "" {
		d.WriteString(label.Render("  Reason: ") + val.Render(sel.Reason) + "\n")
	}
	d.WriteString(label.Render("  [o] actions  [Enter] close  [Esc] close"))
	return box.Render(d.String())
}
