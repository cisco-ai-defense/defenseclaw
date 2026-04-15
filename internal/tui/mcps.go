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

type mcpItem struct {
	URL     string
	Status  string
	Actions string
	Reason  string
	Time    string
}

type MCPDetailInfo struct {
	Item     mcpItem
	Action   *audit.ActionEntry
	Findings []audit.FindingRow
	History  []audit.Event
	ScanInfo *audit.LatestScanInfo
}

type MCPsPanel struct {
	items          []mcpItem
	filtered       []mcpItem
	cursor         int
	width          int
	height         int
	store          *audit.Store
	message        string
	filter         string
	filtering      bool
	detailOpen     bool
	detailCache    *MCPDetailInfo
	detailCacheIdx int
}

func NewMCPsPanel(store *audit.Store) MCPsPanel {
	return MCPsPanel{store: store}
}

func (p *MCPsPanel) Refresh() {
	if p.store == nil {
		return
	}

	p.items = nil

	entries, err := p.store.ListActionsByType("mcp")
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	for _, e := range entries {
		var status string
		switch e.Actions.Install {
		case "block":
			status = "blocked"
		case "allow":
			status = "allowed"
		default:
			status = "active"
		}
		p.items = append(p.items, mcpItem{
			URL:     e.TargetName,
			Status:  status,
			Actions: e.Actions.Summary(),
			Reason:  e.Reason,
			Time:    e.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	p.applyFilter()
	p.message = ""
}

func (p *MCPsPanel) applyFilter() {
	if p.filter == "" {
		p.filtered = p.items
	} else {
		p.filtered = nil
		query := strings.ToLower(p.filter)
		for _, item := range p.items {
			text := strings.ToLower(item.URL + " " + item.Status + " " + item.Reason)
			if strings.Contains(text, query) {
				p.filtered = append(p.filtered, item)
			}
		}
	}
	if p.cursor >= len(p.filtered) && len(p.filtered) > 0 {
		p.cursor = len(p.filtered) - 1
	}
	if len(p.filtered) == 0 {
		p.cursor = 0
	}
}

func (p *MCPsPanel) SetFilter(f string) {
	p.filter = f
	p.applyFilter()
}

func (p *MCPsPanel) IsFiltering() bool { return p.filtering }
func (p *MCPsPanel) StartFilter()      { p.filtering = true }
func (p *MCPsPanel) StopFilter()       { p.filtering = false }
func (p *MCPsPanel) ClearFilter() {
	p.filter = ""
	p.filtering = false
	p.applyFilter()
}
func (p *MCPsPanel) FilterText() string { return p.filter }

func (p *MCPsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *MCPsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *MCPsPanel) CursorDown() { if p.cursor < len(p.filtered)-1 { p.cursor++ } }

func (p *MCPsPanel) Selected() *mcpItem {
	if p.cursor >= 0 && p.cursor < len(p.filtered) {
		return &p.filtered[p.cursor]
	}
	return nil
}

func (p *MCPsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.SetActionField("mcp", sel.URL, "install", "allow", "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed MCP: %s", sel.URL)
	}
	_ = p.store.SetActionField("mcp", sel.URL, "install", "block", "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked MCP: %s", sel.URL)
}

func (p *MCPsPanel) Count() int        { return len(p.items) }
func (p *MCPsPanel) FilteredCount() int { return len(p.filtered) }
func (p *MCPsPanel) CursorAt() int     { return p.cursor }

func (p *MCPsPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *MCPsPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

func (p *MCPsPanel) detailHeight() int {
	if !p.detailOpen {
		return 0
	}
	h := p.height / 3
	if h < 6 {
		h = 6
	}
	if h > 14 {
		h = 14
	}
	return h
}

func (p *MCPsPanel) listHeight() int {
	h := p.height - p.filterBarHeight() - 1 - p.detailHeight()
	if h < 3 {
		h = 3
	}
	return h
}

func (p *MCPsPanel) filterBarHeight() int {
	h := 2
	if p.filter != "" {
		h++
	}
	if p.filtering {
		h++
	}
	return h
}

func (p *MCPsPanel) GetDetailInfo() *MCPDetailInfo {
	sel := p.Selected()
	if sel == nil {
		return nil
	}
	info := &MCPDetailInfo{Item: *sel}
	if p.store == nil {
		return info
	}
	action, err := p.store.GetAction("mcp", sel.URL)
	if err == nil && action != nil {
		info.Action = action
	}
	history, _ := p.store.ListEventsByTarget(sel.URL, 10)
	info.History = history

	scans, _ := p.store.LatestScansByScanner("mcp-scanner")
	for i := range scans {
		if scans[i].Target == sel.URL {
			info.ScanInfo = &scans[i]
			findings, _ := p.store.ListFindingsByScan(scans[i].ID)
			info.Findings = findings
			break
		}
	}
	return info
}

func (p *MCPsPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if maxVisible < 1 {
		maxVisible = 10
	}
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *MCPsPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.filtered) {
		i = len(p.filtered) - 1
	}
	p.cursor = i
}

func (p *MCPsPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
}
func (p *MCPsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func (p *MCPsPanel) View() string {
	if p.message != "" {
		return p.message
	}

	var b strings.Builder

	// Summary bar
	blockedCount := 0
	allowedCount := 0
	for _, i := range p.items {
		switch strings.ToLower(i.Status) {
		case "blocked":
			blockedCount++
		case "allowed":
			allowedCount++
		}
	}
	blockedBadge := lipgloss.NewStyle().
		Background(lipgloss.Color("196")).
		Foreground(lipgloss.Color("16")).
		Bold(true).
		Render(fmt.Sprintf(" %d blocked ", blockedCount))
	allowedBadge := lipgloss.NewStyle().
		Background(lipgloss.Color("46")).
		Foreground(lipgloss.Color("16")).
		Bold(true).
		Render(fmt.Sprintf(" %d allowed ", allowedCount))
	totalLabel := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Render(fmt.Sprintf("%d total", len(p.items)))

	b.WriteString("  " + blockedBadge + "  " + allowedBadge + "   " + totalLabel + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", p.width)) + "\n")

	if p.filter != "" {
		b.WriteString(StyleInfo.Render(fmt.Sprintf("  Filter: %s (%d of %d)", p.filter, len(p.filtered), len(p.items))))
		b.WriteString("\n")
	}
	if p.filtering {
		b.WriteString(fmt.Sprintf("  / %s█\n", p.filter))
	}

	if len(p.filtered) == 0 {
		if p.filter != "" {
			return b.String() + StyleInfo.Render("  No MCP servers match the filter.")
		}
		return b.String() + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			"  No MCP servers with enforcement actions.\n  Press : then type \"block mcp <url>\" or \"allow mcp <url>\"")
	}

	header := fmt.Sprintf("  %-14s %-38s %-20s %-20s %-16s", "STATUS", "URL", "ACTIONS", "REASON", "SINCE")
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
	if end > len(p.filtered) {
		end = len(p.filtered)
	}

	for i := start; i < end; i++ {
		item := p.filtered[i]
		badge := statusBadge(item.Status)
		url := item.URL
		if len(url) > 38 {
			url = url[:35] + "…"
		}
		actions := item.Actions
		if len(actions) > 20 {
			actions = actions[:17] + "…"
		}
		reason := item.Reason
		if len(reason) > 20 {
			reason = reason[:17] + "…"
		}

		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		line := fmt.Sprintf("%s%s %-38s %-20s %-20s %-16s", pointer, badge, url, actions, reason, item.Time)

		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(p.width).Render(line)
		}
		b.WriteString(line)
		if i < end-1 {
			b.WriteString("\n")
		}
	}

	if len(p.filtered) > maxVisible {
		b.WriteString("\n")
		pct := 0
		if len(p.filtered) > 0 {
			pct = (end * 100) / len(p.filtered)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  ↕ %d–%d of %d (%d%%)", start+1, end, len(p.filtered), pct),
		))
	}

	if p.detailOpen {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}

	return b.String()
}

func (p *MCPsPanel) renderDetail() string {
	if p.detailCache == nil || p.detailCacheIdx != p.cursor {
		p.detailCache = p.GetDetailInfo()
		p.detailCacheIdx = p.cursor
	}
	info := p.detailCache
	if info == nil {
		return ""
	}

	dh := p.detailHeight()
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Width(p.width - 4).
		MaxHeight(dh)
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	var d strings.Builder
	d.WriteString(titleStyle.Render(fmt.Sprintf("  %s  %s", statusBadge(info.Item.Status), info.Item.URL)))
	d.WriteString("\n")

	d.WriteString(labelStyle.Render("  Status: ") + valStyle.Render(strings.ToUpper(info.Item.Status)))
	d.WriteString(labelStyle.Render("    Since: ") + valStyle.Render(info.Item.Time) + "\n")

	if info.Item.Reason != "" {
		d.WriteString(labelStyle.Render("  Reason: ") + valStyle.Render(info.Item.Reason) + "\n")
	}

	if info.Action != nil {
		if info.Action.SourcePath != "" {
			d.WriteString(labelStyle.Render("  Source: ") + valStyle.Render(info.Action.SourcePath) + "\n")
		}
		var policyParts []string
		if info.Action.Actions.Install != "" {
			policyParts = append(policyParts, "install="+info.Action.Actions.Install)
		}
		if info.Action.Actions.File != "" {
			policyParts = append(policyParts, "file="+info.Action.Actions.File)
		}
		if info.Action.Actions.Runtime != "" {
			policyParts = append(policyParts, "runtime="+info.Action.Actions.Runtime)
		}
		if len(policyParts) > 0 {
			d.WriteString(labelStyle.Render("  Policy: ") + valStyle.Render(strings.Join(policyParts, "  ")) + "\n")
		}
	}

	if len(info.Findings) > 0 {
		d.WriteString("\n" + titleStyle.Render(fmt.Sprintf("  Findings (%d):", len(info.Findings))) + "\n")
		limit := dh - 8
		if limit < 2 {
			limit = 2
		}
		if limit > len(info.Findings) {
			limit = len(info.Findings)
		}
		for i := 0; i < limit; i++ {
			f := info.Findings[i]
			fSev := SeverityStyle(f.Severity).Render(fmt.Sprintf("%-8s", f.Severity))
			title := f.Title
			if len(title) > 45 {
				title = title[:42] + "..."
			}
			d.WriteString(fmt.Sprintf("    %s %s", fSev, title))
			if f.Location != "" {
				loc := f.Location
				if len(loc) > 25 {
					loc = loc[:22] + "..."
				}
				d.WriteString(labelStyle.Render("  @ " + loc))
			}
			d.WriteString("\n")
		}
		if len(info.Findings) > limit {
			d.WriteString(labelStyle.Render(fmt.Sprintf("    ... and %d more findings\n", len(info.Findings)-limit)))
		}
	} else if info.ScanInfo != nil {
		d.WriteString("\n" + labelStyle.Render("  Last scan: ") + valStyle.Render("clean (no findings)") + "\n")
	}

	if len(info.History) > 0 {
		d.WriteString("\n" + titleStyle.Render("  Recent Activity:") + "\n")
		shown := 0
		for _, h := range info.History {
			if shown >= 3 {
				break
			}
			ts := h.Timestamp.Format("Jan 02 15:04")
			action := h.Action
			if len(action) > 18 {
				action = action[:15] + "..."
			}
			d.WriteString(fmt.Sprintf("    %s  %-18s  %s\n",
				labelStyle.Render(ts),
				action,
				SeverityStyle(h.Severity).Render(h.Severity),
			))
			shown++
		}
	}

	d.WriteString(labelStyle.Render("  [Enter] close  [o] actions  [Esc] close"))

	return boxStyle.Render(d.String())
}
