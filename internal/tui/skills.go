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
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// skillListJSON mirrors a single object in `defenseclaw skill list --json`
// (see cli/defenseclaw/commands/cmd_skill.py::_print_skill_list_json).
// Catalog-first: everything the CLI surfaces is available, including
// the merged scan + enforcement metadata. We decode the whole shape
// into Go so later UI (details, correlation) doesn't need a second
// JSON pass.
type skillListJSON struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Source      string             `json:"source"`
	Status      string             `json:"status"`
	Eligible    bool               `json:"eligible"`
	Disabled    bool               `json:"disabled"`
	Bundled     bool               `json:"bundled"`
	Homepage    string             `json:"homepage,omitempty"`
	Scan        *skillScanJSON     `json:"scan,omitempty"`
	Actions     *audit.ActionState `json:"actions,omitempty"`
	Verdict     string             `json:"verdict,omitempty"`
}

type skillScanJSON struct {
	Target        string `json:"target"`
	Clean         bool   `json:"clean"`
	MaxSeverity   string `json:"max_severity"`
	TotalFindings int    `json:"total_findings"`
}

type skillItem struct {
	Name        string
	Status      string
	Actions     string
	Reason      string
	Time        string
	Description string
	Source      string
	Verdict     string
	Severity    string
}

type SkillDetailInfo struct {
	Item     skillItem
	Action   *audit.ActionEntry
	Findings []audit.FindingRow
	History  []audit.Event
	ScanInfo *audit.LatestScanInfo
}

type SkillsPanel struct {
	items          []skillItem
	filtered       []skillItem
	cursor         int
	width          int
	height         int
	store          *audit.Store
	message        string
	filter         string
	filtering      bool
	loaded         bool
	loading        bool
	detailOpen     bool
	detailCache    *SkillDetailInfo
	detailCacheIdx int
}

// SkillsLoadedMsg is sent when `defenseclaw skill list --json` completes.
// Modeled on PluginsLoadedMsg so the dispatch pattern is identical —
// adding a third is trivial if we ever split plugins/skills/mcps into
// more tabs.
type SkillsLoadedMsg struct {
	Items []skillItem
	Err   error
}

func NewSkillsPanel(store *audit.Store) SkillsPanel {
	return SkillsPanel{store: store}
}

// LoadCmd returns a tea.Cmd that invokes `defenseclaw skill list --json`
// in a subprocess and converts the output into skillItem rows. Matches
// PluginsPanel.LoadCmd in shape so the main Update loop wires them
// uniformly. We cap the subprocess at 15s so a hung sidecar cannot
// freeze the TUI.
func (p *SkillsPanel) LoadCmd() tea.Cmd {
	p.loading = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, resolveDefenseclawBin(), "skill", "list", "--json")
		out, err := cmd.Output()
		if err != nil {
			return SkillsLoadedMsg{Err: err}
		}
		var raw []skillListJSON
		if err := json.Unmarshal(out, &raw); err != nil {
			return SkillsLoadedMsg{Err: fmt.Errorf("parse skill list: %w", err)}
		}
		items := make([]skillItem, 0, len(raw))
		for _, s := range raw {
			items = append(items, skillListToItem(s))
		}
		return SkillsLoadedMsg{Items: items}
	}
}

// skillListToItem derives display fields from a single decoded entry.
// Status precedence mirrors cli/defenseclaw/commands/cmd_skill.py
// _skill_status_display:
//
//	disabled → quarantined → blocked → disabled → allowed →
//	scan-severity (CRITICAL/HIGH → rejected, MEDIUM/LOW → warning) →
//	eligible → removed → inactive
//
// The severity branch was originally absent in the Go TUI, which
// caused an "eligible" skill whose most recent scan was HIGH to
// render as `active` — the CLI would call out the same skill as
// `rejected`. The review flagged that gap; we keep the two
// implementations in lockstep here.
func skillListToItem(s skillListJSON) skillItem {
	severity := ""
	if s.Scan != nil {
		severity = s.Scan.MaxSeverity
	}
	// Mirror cmd_skill.py's branch: only consider scan severity
	// when there actually was a scan with findings. Python treats
	// "CLEAN" (the no-findings sentinel) as pass-through.
	scanMismatch := ""
	if s.Scan != nil && !s.Scan.Clean {
		switch strings.ToUpper(severity) {
		case "CRITICAL", "HIGH":
			scanMismatch = "rejected"
		case "MEDIUM", "LOW":
			scanMismatch = "warning"
		}
	}

	status := "active"
	actionsSummary := "-"
	switch {
	case s.Disabled:
		status = "disabled"
	case s.Actions != nil && s.Actions.File == "quarantine":
		status = "quarantined"
	case s.Actions != nil && s.Actions.Install == "block":
		status = "blocked"
	case s.Actions != nil && s.Actions.Runtime == "disable":
		status = "disabled"
	case s.Actions != nil && s.Actions.Install == "allow":
		status = "allowed"
	case s.Status == "blocked":
		status = "blocked"
	case s.Status == "disabled":
		status = "disabled"
	case scanMismatch != "":
		// Parity with Python: severity check precedes `eligible →
		// ready` so a skill with a dirty scan is visible as
		// rejected/warning even if no enforcement action has been
		// configured yet.
		status = scanMismatch
	case s.Eligible:
		status = "active"
	case s.Source == "enforcement" || s.Source == "scan-history":
		status = "removed"
	default:
		status = "inactive"
	}
	if s.Actions != nil && !s.Actions.IsEmpty() {
		actionsSummary = s.Actions.Summary()
	}
	return skillItem{
		Name:        s.Name,
		Status:      status,
		Actions:     actionsSummary,
		Reason:      "",
		Time:        "",
		Description: s.Description,
		Source:      s.Source,
		Verdict:     s.Verdict,
		Severity:    severity,
	}
}

// ApplyLoaded consumes a SkillsLoadedMsg and rebuilds p.items / p.filtered.
// Mirrors PluginsPanel.ApplyLoaded; keeps cursor in range.
func (p *SkillsPanel) ApplyLoaded(msg SkillsLoadedMsg) {
	p.loading = false
	if msg.Err != nil {
		p.message = fmt.Sprintf("Error loading skills: %v", msg.Err)
		return
	}
	p.items = msg.Items
	p.loaded = true
	p.message = ""
	p.applyFilter()
	p.detailCache = nil
}

// IsLoaded reports whether the panel has fetched data at least once.
// Used by app.go to decide whether to dispatch LoadCmd on tab switch.
func (p *SkillsPanel) IsLoaded() bool { return p.loaded }

// IsLoading reports whether a LoadCmd is in flight — used to render
// a hint while the async subprocess is running.
func (p *SkillsPanel) IsLoading() bool { return p.loading }

// Refresh re-applies the current text filter over the cached items.
// Kept as a lightweight pass so tests that pre-populate p.items still
// pass without dispatching a subprocess. The authoritative refresh
// path is LoadCmd.
func (p *SkillsPanel) Refresh() {
	p.applyFilter()
}

func (p *SkillsPanel) applyFilter() {
	if p.filter == "" {
		p.filtered = p.items
	} else {
		p.filtered = nil
		query := strings.ToLower(p.filter)
		for _, item := range p.items {
			text := strings.ToLower(item.Name + " " + item.Status + " " + item.Reason + " " + item.Description + " " + item.Source)
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

func (p *SkillsPanel) SetFilter(f string) {
	p.filter = f
	p.applyFilter()
}

func (p *SkillsPanel) IsFiltering() bool { return p.filtering }
func (p *SkillsPanel) StartFilter()      { p.filtering = true }
func (p *SkillsPanel) StopFilter()       { p.filtering = false }
func (p *SkillsPanel) ClearFilter() {
	p.filter = ""
	p.filtering = false
	p.applyFilter()
}
func (p *SkillsPanel) FilterText() string { return p.filter }

func (p *SkillsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *SkillsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}
func (p *SkillsPanel) CursorDown() {
	if p.cursor < len(p.filtered)-1 {
		p.cursor++
	}
}

func (p *SkillsPanel) Selected() *skillItem {
	if p.cursor >= 0 && p.cursor < len(p.filtered) {
		return &p.filtered[p.cursor]
	}
	return nil
}

// ToggleBlock is kept for backward compatibility with existing key
// handlers that bypass the CLI. New entry points should dispatch
// through the CLI executor so audit parity is preserved.
func (p *SkillsPanel) ToggleBlock() string {
	sel := p.Selected()
	if sel == nil || p.store == nil {
		return ""
	}
	if sel.Status == "blocked" {
		_ = p.store.SetActionField("skill", sel.Name, "install", "allow", "unblocked from TUI")
		p.Refresh()
		return fmt.Sprintf("Allowed skill: %s", sel.Name)
	}
	_ = p.store.SetActionField("skill", sel.Name, "install", "block", "blocked from TUI")
	p.Refresh()
	return fmt.Sprintf("Blocked skill: %s", sel.Name)
}

func (p *SkillsPanel) Count() int         { return len(p.items) }
func (p *SkillsPanel) FilteredCount() int { return len(p.filtered) }
func (p *SkillsPanel) CursorAt() int      { return p.cursor }

func (p *SkillsPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if maxVisible < 1 {
		maxVisible = 10
	}
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *SkillsPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.filtered) {
		i = len(p.filtered) - 1
	}
	p.cursor = i
}

func (p *SkillsPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
}

func (p *SkillsPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *SkillsPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

func (p *SkillsPanel) detailHeight() int {
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

func (p *SkillsPanel) listHeight() int {
	h := p.height - p.filterBarHeight() - 1 - p.detailHeight()
	if h < 3 {
		h = 3
	}
	return h
}

func (p *SkillsPanel) filterBarHeight() int {
	h := 2 // summary bar + separator
	if p.filter != "" {
		h++
	}
	if p.filtering {
		h++
	}
	return h
}

func (p *SkillsPanel) GetDetailInfo() *SkillDetailInfo {
	sel := p.Selected()
	if sel == nil {
		return nil
	}
	info := &SkillDetailInfo{Item: *sel}
	if p.store == nil {
		return info
	}
	action, err := p.store.GetAction("skill", sel.Name)
	if err == nil && action != nil {
		info.Action = action
	}
	history, _ := p.store.ListEventsByTarget(sel.Name, 10)
	info.History = history

	scans, _ := p.store.LatestScansByScanner("skill-scanner")
	for i := range scans {
		if scans[i].Target == sel.Name {
			info.ScanInfo = &scans[i]
			findings, _ := p.store.ListFindingsByScan(scans[i].ID)
			info.Findings = findings
			break
		}
	}
	return info
}

func (p *SkillsPanel) BlockedCount() int {
	n := 0
	for _, i := range p.items {
		if i.Status == "blocked" {
			n++
		}
	}
	return n
}

func statusBadge(status string) string {
	// Colors chosen to match what the CLI uses for the same labels:
	// rejected borrows the `blocked` red (the two are emotionally
	// the same signal — do not run), warning uses amber so it is
	// immediately distinguishable from allowed/active green.
	bg := lipgloss.Color("245")
	switch strings.ToLower(status) {
	case "blocked", "rejected":
		bg = lipgloss.Color("196")
	case "allowed", "active":
		bg = lipgloss.Color("46")
	case "quarantined":
		bg = lipgloss.Color("133")
	case "warning":
		bg = lipgloss.Color("208")
	case "disabled", "removed", "inactive":
		bg = lipgloss.Color("240")
	}
	fg := lipgloss.Color("16")
	label := fmt.Sprintf(" %-12s ", strings.ToUpper(status))
	return lipgloss.NewStyle().Background(bg).Foreground(fg).Bold(true).Render(label)
}

func (p *SkillsPanel) View() string {
	if p.message != "" {
		return p.message
	}
	if p.loading && len(p.items) == 0 {
		return lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("  Loading skills…")
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
		fmt.Fprintf(&b, "  / %s█\n", p.filter)
	}

	if len(p.filtered) == 0 {
		if p.filter != "" {
			return b.String() + StyleInfo.Render("  No skills match the filter.")
		}
		if !p.loaded {
			return b.String() + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
				"  Press \"r\" to load skills. Runs \"defenseclaw skill list --json\".")
		}
		return b.String() + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
			"  No skills found.\n  Install one with: defenseclaw skill install <name>")
	}

	header := fmt.Sprintf("  %-14s %-28s %-14s %-10s %-18s", "STATUS", "NAME", "SOURCE", "SEVERITY", "ACTIONS")
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
		name := item.Name
		if len(name) > 28 {
			name = name[:25] + "…"
		}
		source := item.Source
		if len(source) > 14 {
			source = source[:11] + "…"
		}
		severity := item.Severity
		if severity == "" {
			severity = "-"
		}
		actions := item.Actions
		if len(actions) > 18 {
			actions = actions[:15] + "…"
		}

		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		sev := severity
		if item.Severity != "" {
			sev = SeverityStyle(item.Severity).Render(fmt.Sprintf("%-10s", item.Severity))
		} else {
			sev = fmt.Sprintf("%-10s", "-")
		}

		line := fmt.Sprintf("%s%s %-28s %-14s %s %-18s", pointer, badge, name, source, sev, actions)

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

func (p *SkillsPanel) renderDetail() string {
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
	d.WriteString(titleStyle.Render(fmt.Sprintf("  %s  %s", statusBadge(info.Item.Status), info.Item.Name)))
	d.WriteString("\n")

	d.WriteString(labelStyle.Render("  Status: ") + valStyle.Render(strings.ToUpper(info.Item.Status)))
	if info.Item.Source != "" {
		d.WriteString(labelStyle.Render("    Source: ") + valStyle.Render(info.Item.Source))
	}
	if info.Item.Verdict != "" {
		d.WriteString(labelStyle.Render("    Verdict: ") + valStyle.Render(info.Item.Verdict))
	}
	d.WriteString("\n")

	if info.Item.Description != "" {
		desc := info.Item.Description
		if len(desc) > 120 {
			desc = desc[:117] + "…"
		}
		d.WriteString(labelStyle.Render("  Description: ") + valStyle.Render(desc) + "\n")
	}

	if info.Action != nil {
		if info.Action.SourcePath != "" {
			d.WriteString(labelStyle.Render("  Scan target: ") + valStyle.Render(info.Action.SourcePath) + "\n")
		}
		d.WriteString(labelStyle.Render("  Enforcement: ") + valStyle.Render(info.Action.Actions.Summary()))
		if info.Action.Reason != "" {
			d.WriteString(labelStyle.Render("  (") + valStyle.Render(info.Action.Reason) + labelStyle.Render(")"))
		}
		d.WriteString("\n")
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

	if info.ScanInfo != nil {
		d.WriteString(labelStyle.Render("  Last scanned: ") + valStyle.Render(info.ScanInfo.Timestamp.Format("2006-01-02 15:04:05")))
		if info.ScanInfo.MaxSeverity != "" {
			d.WriteString(labelStyle.Render("    Severity: ") + SeverityStyle(info.ScanInfo.MaxSeverity).Render(info.ScanInfo.MaxSeverity))
		}
		d.WriteString("\n")
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
			d.WriteString(labelStyle.Render(fmt.Sprintf("    ... and %d more findings\n", len(info.Findings)-limit)))
		}
	} else if info.ScanInfo != nil {
		d.WriteString("\n" + labelStyle.Render("  Last scan: ") + valStyle.Render("clean (no findings)") + "\n")
	}

	if len(info.History) > 0 {
		d.WriteString("\n" + titleStyle.Render("  Recent Activity:") + "\n")
		shown := 0
		for _, h := range info.History {
			if shown >= 5 {
				break
			}
			ts := h.Timestamp.Format("Jan 02 15:04")
			action := h.Action
			if len(action) > 18 {
				action = action[:15] + "..."
			}
			fmt.Fprintf(&d, "    %s  %-18s  %s\n",
				labelStyle.Render(ts),
				action,
				SeverityStyle(h.Severity).Render(h.Severity))
			shown++
		}
	}

	d.WriteString(labelStyle.Render("  [Enter] close  [o] actions  [Esc] close"))

	return boxStyle.Render(d.String())
}
