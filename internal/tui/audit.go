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

type AuditDetailInfo struct {
	Event    audit.Event
	Findings []audit.FindingRow
	Related  []audit.Event
	Action   *audit.ActionEntry
}

type AuditPanel struct {
	theme          *Theme
	store          *audit.Store
	items          []audit.Event
	filtered       []audit.Event
	cursor         int
	filter         string
	filtering      bool
	detailOpen     bool
	width          int
	height         int
	detailCache    *AuditDetailInfo
	detailCacheIdx int
	errMsg         string
}

// NewAuditPanel creates the audit history panel.
func NewAuditPanel(theme *Theme, store *audit.Store) AuditPanel {
	return AuditPanel{theme: theme, store: store}
}

// Refresh loads the latest audit events from SQLite.
func (p *AuditPanel) Refresh() {
	if p.store == nil {
		return
	}
	events, err := p.store.ListEvents(500)
	if err != nil {
		p.errMsg = fmt.Sprintf("Audit refresh failed: %v", err)
		return
	}
	p.errMsg = ""
	p.items = events
	p.applyFilter()
}

func (p *AuditPanel) applyFilter() {
	if p.filter == "" {
		p.filtered = p.items
	} else {
		p.filtered = nil
		query := strings.ToLower(p.filter)
		for _, e := range p.items {
			text := strings.ToLower(e.Action + " " + e.Target + " " + e.Severity + " " + e.Details)
			if strings.Contains(text, query) {
				p.filtered = append(p.filtered, e)
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

func (p *AuditPanel) SetFilter(f string) {
	p.filter = f
	p.applyFilter()
}

func (p *AuditPanel) IsFiltering() bool { return p.filtering }
func (p *AuditPanel) StartFilter()      { p.filtering = true }
func (p *AuditPanel) StopFilter()       { p.filtering = false }
func (p *AuditPanel) ClearFilter() {
	p.filter = ""
	p.filtering = false
	p.applyFilter()
}
func (p *AuditPanel) FilterText() string { return p.filter }

func (p *AuditPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}
func (p *AuditPanel) CursorDown() {
	if p.cursor < len(p.filtered)-1 {
		p.cursor++
	}
}

func (p *AuditPanel) Selected() *audit.Event {
	if p.cursor >= 0 && p.cursor < len(p.filtered) {
		return &p.filtered[p.cursor]
	}
	return nil
}

func (p *AuditPanel) Count() int         { return len(p.items) }
func (p *AuditPanel) FilteredCount() int { return len(p.filtered) }
func (p *AuditPanel) CursorAt() int      { return p.cursor }

func (p *AuditPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *AuditPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.filtered) {
		i = len(p.filtered) - 1
	}
	p.cursor = i
}

func (p *AuditPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
}

func (p *AuditPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *AuditPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

func (p *AuditPanel) detailHeight() int {
	if !p.detailOpen {
		return 0
	}
	h := p.height / 2
	if h < 8 {
		h = 8
	}
	if h > 26 {
		h = 26
	}
	return h
}

func (p *AuditPanel) listHeight() int {
	h := p.height - p.filterBarHeight() - 3 - p.detailHeight() // summary(1) + sep(1) + header(1) = 3
	if h < 3 {
		h = 3
	}
	return h
}

func (p *AuditPanel) filterBarHeight() int {
	h := 0
	if p.filter != "" {
		h++
	}
	if p.filtering {
		h++
	}
	return h
}

func (p *AuditPanel) GetDetailInfo() *AuditDetailInfo {
	sel := p.Selected()
	if sel == nil {
		return nil
	}
	info := &AuditDetailInfo{Event: *sel}
	if p.store == nil {
		return info
	}
	if sel.RunID != "" {
		findings, _ := p.store.ListFindingsByRunID(sel.RunID)
		info.Findings = findings
	}
	related, _ := p.store.ListEventsByTarget(sel.Target, 10)
	info.Related = related

	targetType := ""
	lower := strings.ToLower(sel.Action)
	switch {
	case strings.Contains(lower, "skill"):
		targetType = "skill"
	case strings.Contains(lower, "mcp"):
		targetType = "mcp"
	case strings.Contains(lower, "plugin"):
		targetType = "plugin"
	}
	if targetType != "" {
		action, err := p.store.GetAction(targetType, sel.Target)
		if err == nil && action != nil {
			info.Action = action
		}
	}
	return info
}

func (p *AuditPanel) View(width, height int) string {
	p.width = width
	p.height = height
	var b strings.Builder

	// Filter bar
	if p.filter != "" {
		b.WriteString(p.theme.Info.Render(fmt.Sprintf("  Filter: %s (%d of %d)", p.filter, len(p.filtered), len(p.items))))
		b.WriteString("\n")
	}
	if p.filtering {
		fmt.Fprintf(&b, "  / %s█\n", p.filter)
	}

	if len(p.filtered) == 0 && p.filter == "" {
		return b.String() + p.theme.Dimmed.Render("  No audit events yet. Events are recorded when you scan, block, allow, or configure DefenseClaw.")
	}
	if len(p.filtered) == 0 {
		return b.String() + p.theme.Dimmed.Render("  No events match the filter.")
	}

	// Summary + header
	fmt.Fprintf(&b, "  %d events recorded", len(p.items))
	if p.filter != "" {
		fmt.Fprintf(&b, "  ·  filtered: %s", p.filter)
	}
	b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("[e] export  [/] filter") + "\n")
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", width)) + "\n")

	header := fmt.Sprintf("  %-8s %-14s %-10s %-32s %-10s %-20s", "TIME", "ACTION", "TYPE", "TARGET", "SEVERITY", "DETAILS")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	maxVisible := p.listHeight()
	if maxVisible < 5 {
		maxVisible = 5
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
		ts := p.theme.Timestamp.Render(item.Timestamp.Format("15:04:05"))
		action := p.colorAction(item.Action)

		targetType := ""
		if strings.Contains(item.Action, "skill") {
			targetType = "skill"
		} else if strings.Contains(item.Action, "mcp") {
			targetType = "mcp"
		} else if strings.Contains(item.Action, "plugin") {
			targetType = "plugin"
		}

		target := item.Target
		if len(target) > 32 {
			target = target[:29] + "..."
		}
		sev := p.theme.SeverityColor(item.Severity).Render(fmt.Sprintf("%-10s", item.Severity))

		details := item.Details
		if len(details) > 20 {
			details = details[:17] + "..."
		}

		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}
		line := fmt.Sprintf("%s%s %s %-10s %-32s %s %-20s", pointer, ts, action, targetType, target, sev, details)
		if i == p.cursor {
			line = lipgloss.NewStyle().Background(lipgloss.Color("236")).Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	if len(p.filtered) > maxVisible {
		pct := 0
		if len(p.filtered) > 0 {
			pct = (end * 100) / len(p.filtered)
		}
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			fmt.Sprintf("  ↕ %d–%d of %d (%d%%)", start+1, end, len(p.filtered), pct)))
	}

	if p.detailOpen {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}

	return b.String()
}

func (p *AuditPanel) renderDetail() string {
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

	e := info.Event
	var d strings.Builder
	d.WriteString(titleStyle.Render("  EVENT: "+e.Action) + "\n")

	d.WriteString(labelStyle.Render("  Time: ") + valStyle.Render(e.Timestamp.Format("2006-01-02 15:04:05")))
	d.WriteString(labelStyle.Render("    Severity: ") + SeverityStyle(e.Severity).Render(e.Severity) + "\n")

	d.WriteString(labelStyle.Render("  Target: ") + valStyle.Render(e.Target) + "\n")

	if e.Actor != "" {
		d.WriteString(labelStyle.Render("  Actor: ") + valStyle.Render(e.Actor) + "\n")
	}
	if e.Details != "" {
		d.WriteString(labelStyle.Render("  Details: ") + valStyle.Render(e.Details) + "\n")
	}
	if e.RunID != "" {
		d.WriteString(labelStyle.Render("  Run ID: ") + valStyle.Render(e.RunID) + "\n")
	}

	if info.Action != nil {
		d.WriteString(labelStyle.Render("  Current State: ") + valStyle.Render(info.Action.Actions.Summary()) + "\n")
	}

	if len(info.Findings) > 0 {
		d.WriteString("\n" + titleStyle.Render(fmt.Sprintf("  Findings (%d):", len(info.Findings))) + "\n")
		limit := dh - 10
		if limit < 3 {
			limit = 3
		}
		if limit > len(info.Findings) {
			limit = len(info.Findings)
		}
		for i := 0; i < limit; i++ {
			f := info.Findings[i]
			fSev := SeverityStyle(f.Severity).Render(fmt.Sprintf("%-8s", f.Severity))
			title := f.Title
			if len(title) > 70 {
				title = title[:67] + "..."
			}
			fmt.Fprintf(&d, "    %s %s", fSev, title)
			if f.Location != "" {
				loc := f.Location
				if len(loc) > 40 {
					loc = loc[:37] + "..."
				}
				d.WriteString(labelStyle.Render("  @ " + loc))
			}
			d.WriteString("\n")
		}
		if len(info.Findings) > limit {
			d.WriteString(labelStyle.Render(fmt.Sprintf("    ... and %d more\n", len(info.Findings)-limit)))
		}
	}

	if len(info.Related) > 1 {
		d.WriteString("\n" + titleStyle.Render("  Related Events:") + "\n")
		shown := 0
		for _, r := range info.Related {
			if r.ID == e.ID || shown >= 5 {
				continue
			}
			ts := r.Timestamp.Format("Jan 02 15:04")
			action := r.Action
			if len(action) > 18 {
				action = action[:15] + "..."
			}
			fmt.Fprintf(&d, "    %s  %-18s  %s\n",
				labelStyle.Render(ts),
				action,
				SeverityStyle(r.Severity).Render(r.Severity),
			)
			shown++
		}
	}

	d.WriteString(labelStyle.Render("  [Enter] close  [Esc] close"))

	return boxStyle.Render(d.String())
}

func (p *AuditPanel) colorAction(action string) string {
	lower := strings.ToLower(action)
	w := 14
	switch {
	case strings.Contains(lower, "block"):
		return p.theme.Blocked.Render(fmt.Sprintf("%-*s", w, "BLOCK"))
	case strings.Contains(lower, "allow"):
		return p.theme.Allowed.Render(fmt.Sprintf("%-*s", w, "ALLOW"))
	case strings.Contains(lower, "scan"):
		return p.theme.Low.Render(fmt.Sprintf("%-*s", w, "SCAN"))
	case strings.Contains(lower, "quarantine"):
		return p.theme.Quarantined.Render(fmt.Sprintf("%-*s", w, "QUARANTINE"))
	case strings.Contains(lower, "config") || strings.Contains(lower, "init"):
		return p.theme.Medium.Render(fmt.Sprintf("%-*s", w, "CONFIG"))
	case strings.Contains(lower, "dismiss"):
		return p.theme.Dimmed.Render(fmt.Sprintf("%-*s", w, "DISMISS"))
	default:
		return p.theme.Info.Render(fmt.Sprintf("%-*s", w, strings.ToUpper(action)))
	}
}
