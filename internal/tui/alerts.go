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

// humanizeAlertDetails is a Go port of
// cli/defenseclaw/commands/cmd_alerts.py:_humanize_details. It turns
// a space-separated `key=value` audit details blob into a friendlier
// summary — e.g. `host=api port=443 mode=strict model=openai/gpt-4o`
// collapses to `api:443 strict gpt-4o`. P3-#20 ported this so the Go
// TUI's enriched detail pane has the same signal-to-noise ratio the
// retired Textual TUI had without having to shell back out to Python.
// Keeps the logic byte-for-byte aligned with the CLI so a later
// internal/tui/cli_parity_test.go can compare outputs directly.
func humanizeAlertDetails(raw string) string {
	if raw == "" {
		return ""
	}
	tokens := strings.Fields(raw)
	hasKV := false
	for _, t := range tokens {
		if strings.Contains(t, "=") {
			hasKV = true
			break
		}
	}
	if !hasKV {
		return raw
	}
	// Preserve insertion order so two events with the same keys
	// produce the same summary — critical for parity tests.
	type kvPair struct{ k, v string }
	var ordered []kvPair
	var plain []string
	seen := map[string]bool{}
	for _, tok := range tokens {
		if idx := strings.Index(tok, "="); idx >= 0 {
			k, v := tok[:idx], tok[idx+1:]
			if !seen[k] {
				ordered = append(ordered, kvPair{k, v})
				seen[k] = true
			}
		} else {
			plain = append(plain, tok)
		}
	}
	take := func(key string) (string, bool) {
		for i, p := range ordered {
			if p.k == key {
				ordered = append(ordered[:i], ordered[i+1:]...)
				delete(seen, key)
				return p.v, true
			}
		}
		return "", false
	}

	var parts []string
	host, hasHost := take("host")
	port, hasPort := take("port")
	switch {
	case hasHost && hasPort:
		parts = append(parts, host+":"+port)
	case hasPort:
		parts = append(parts, ":"+port)
	case hasHost:
		parts = append(parts, host)
	}
	for _, key := range []string{"mode", "environment", "status", "protocol", "scanner_mode"} {
		if v, ok := take(key); ok {
			parts = append(parts, v)
		}
	}
	if v, ok := take("model"); ok {
		// Model names are often vendor-prefixed (openai/gpt-4o,
		// anthropic/claude-3-sonnet). The summary takes the last
		// segment since that's the actionable identifier.
		if slash := strings.LastIndex(v, "/"); slash >= 0 && slash < len(v)-1 {
			v = v[slash+1:]
		}
		parts = append(parts, v)
	}
	// These keys add noise once the summary exists; drop them.
	for _, key := range []string{"max_severity", "scanner", "findings"} {
		_, _ = take(key)
	}
	for _, p := range ordered {
		parts = append(parts, p.k+"="+p.v)
	}
	parts = append(parts, plain...)
	return strings.Join(parts, " ")
}

// Severity filter constants matching button order in the summary bar.
const (
	sevFilterAll      = ""
	sevFilterCritical = "CRITICAL"
	sevFilterHigh     = "HIGH"
	sevFilterMedium   = "MEDIUM"
	sevFilterLow      = "LOW"
)

var sevFilterOrder = []string{sevFilterAll, sevFilterCritical, sevFilterHigh, sevFilterMedium, sevFilterLow}
var sevFilterLabels = []string{"All", "Critical", "High", "Medium", "Low"}

type AlertsPanel struct {
	items      []audit.Event
	filtered   []audit.Event
	cursor     int
	width      int
	height     int
	store      *audit.Store
	message    string
	filter     string // text search filter
	filtering  bool
	sevFilter  string          // severity quick-filter (one of sevFilter* constants)
	selected   map[string]bool // event ID -> selected for multi-select
	detailOpen bool            // inline detail pane visible
}

func NewAlertsPanel(store *audit.Store) AlertsPanel {
	return AlertsPanel{store: store, selected: make(map[string]bool)}
}

func (p *AlertsPanel) Refresh() {
	if p.store == nil {
		return
	}
	alerts, err := p.store.ListAlerts(500)
	if err != nil {
		p.message = fmt.Sprintf("Error: %v", err)
		return
	}
	p.items = alerts
	p.applyFilter()
	p.message = ""
	alive := make(map[string]bool)
	for _, e := range p.items {
		alive[e.ID] = true
	}
	for id := range p.selected {
		if !alive[id] {
			delete(p.selected, id)
		}
	}
}

func (p *AlertsPanel) applyFilter() {
	p.filtered = nil
	query := strings.ToLower(p.filter)
	for _, item := range p.items {
		if p.sevFilter != "" && item.Severity != p.sevFilter {
			continue
		}
		if query != "" {
			text := strings.ToLower(item.Severity + " " + item.Action + " " + item.Target + " " + item.Details)
			if !strings.Contains(text, query) {
				continue
			}
		}
		p.filtered = append(p.filtered, item)
	}
	if len(p.filtered) == 0 {
		p.cursor = 0
	} else if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
}

func (p *AlertsPanel) SetFilter(f string) {
	p.filter = f
	p.applyFilter()
}

func (p *AlertsPanel) SetSevFilter(sev string) {
	if p.sevFilter == sev {
		p.sevFilter = ""
	} else {
		p.sevFilter = sev
	}
	p.applyFilter()
}

func (p *AlertsPanel) SevFilter() string     { return p.sevFilter }
func (p *AlertsPanel) IsFiltering() bool      { return p.filtering }
func (p *AlertsPanel) StartFilter()           { p.filtering = true }
func (p *AlertsPanel) StopFilter()            { p.filtering = false }
func (p *AlertsPanel) FilterText() string     { return p.filter }
func (p *AlertsPanel) IsDetailOpen() bool     { return p.detailOpen }

func (p *AlertsPanel) ClearFilter() {
	p.filter = ""
	p.filtering = false
	p.applyFilter()
}

func (p *AlertsPanel) SetSize(w, h int) {
	p.width = w
	p.height = h
}

func (p *AlertsPanel) CursorUp() {
	if p.cursor > 0 {
		p.cursor--
	}
}

func (p *AlertsPanel) CursorDown() {
	if p.cursor < len(p.filtered)-1 {
		p.cursor++
	}
}

func (p *AlertsPanel) Selected() *audit.Event {
	if p.cursor >= 0 && p.cursor < len(p.filtered) {
		return &p.filtered[p.cursor]
	}
	return nil
}

func (p *AlertsPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
}

// ---------- Multi-select ----------

func (p *AlertsPanel) ToggleSelect() {
	sel := p.Selected()
	if sel == nil {
		return
	}
	if p.selected[sel.ID] {
		delete(p.selected, sel.ID)
	} else {
		p.selected[sel.ID] = true
	}
}

func (p *AlertsPanel) SelectAll() {
	for _, e := range p.filtered {
		p.selected[e.ID] = true
	}
}

func (p *AlertsPanel) DeselectAll() {
	p.selected = make(map[string]bool)
}

func (p *AlertsPanel) SelectionCount() int { return len(p.selected) }

func (p *AlertsPanel) SelectedIDs() []string {
	ids := make([]string, 0, len(p.selected))
	for id := range p.selected {
		ids = append(ids, id)
	}
	return ids
}

func (p *AlertsPanel) FilteredIDs() []string {
	ids := make([]string, 0, len(p.filtered))
	for _, e := range p.filtered {
		ids = append(ids, e.ID)
	}
	return ids
}

func (p *AlertsPanel) IsSelected(id string) bool { return p.selected[id] }

// ---------- Single dismiss ----------

func (p *AlertsPanel) Dismiss() string {
	sel := p.Selected()
	if sel == nil {
		return ""
	}
	if p.store != nil {
		_ = p.store.LogEvent(audit.Event{
			Action:   "dismiss-alert",
			Target:   sel.Target,
			Details:  fmt.Sprintf("dismissed alert %s", sel.ID),
			Severity: "INFO",
		})
	}
	p.Refresh()
	return fmt.Sprintf("Dismissed alert for %s", sel.Target)
}

// ---------- Counts and navigation ----------

func (p *AlertsPanel) Count() int        { return len(p.items) }
func (p *AlertsPanel) FilteredCount() int { return len(p.filtered) }
func (p *AlertsPanel) CursorAt() int     { return p.cursor }

func (p *AlertsPanel) CriticalCount() int {
	n := 0
	for _, item := range p.items {
		if item.Severity == "CRITICAL" || item.Severity == "HIGH" {
			n++
		}
	}
	return n
}

func (p *AlertsPanel) SevCounts() (crit, high, med, low int) {
	for _, e := range p.items {
		switch e.Severity {
		case "CRITICAL":
			crit++
		case "HIGH":
			high++
		case "MEDIUM":
			med++
		case "LOW":
			low++
		}
	}
	return
}

func (p *AlertsPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if maxVisible < 1 {
		maxVisible = 10
	}
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *AlertsPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.filtered) {
		i = len(p.filtered) - 1
	}
	if i < 0 {
		i = 0
	}
	p.cursor = i
}

func (p *AlertsPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.filtered) {
		p.cursor = len(p.filtered) - 1
	}
	if p.cursor < 0 {
		p.cursor = 0
	}
}

// ---------- Detail pane data ----------

// DetailInfo collects enriched info about the selected alert.
type DetailInfo struct {
	Event    audit.Event
	Findings []audit.FindingRow
	History  []audit.Event
}

func (p *AlertsPanel) GetDetailInfo() *DetailInfo {
	sel := p.Selected()
	if sel == nil {
		return nil
	}
	info := &DetailInfo{Event: *sel}
	if p.store == nil {
		return info
	}
	if sel.RunID != "" {
		findings, _ := p.store.ListFindingsByRunID(sel.RunID)
		info.Findings = findings
	}
	if sel.Target != "" {
		history, _ := p.store.ListEventsByTarget(sel.Target, 10)
		info.History = history
	}
	return info
}

// ---------- View ----------

func sevBadge(sev string) string {
	bg := lipgloss.Color("245")
	switch sev {
	case "CRITICAL":
		bg = lipgloss.Color("196")
	case "HIGH":
		bg = lipgloss.Color("208")
	case "MEDIUM":
		bg = lipgloss.Color("220")
	case "LOW":
		bg = lipgloss.Color("39")
	}
	label := fmt.Sprintf(" %-8s ", sev)
	return lipgloss.NewStyle().Background(bg).Foreground(lipgloss.Color("16")).Bold(true).Render(label)
}

// filterBarHeight returns lines consumed by the filter row + buttons row.
func (p *AlertsPanel) filterBarHeight() int {
	h := 2 // button row + separator
	if p.filter != "" {
		h++
	}
	if p.filtering {
		h++
	}
	return h
}

func (p *AlertsPanel) detailHeight() int {
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

func (p *AlertsPanel) listHeight() int {
	h := p.height - p.filterBarHeight() - 1 - p.detailHeight() // -1 for column header
	if h < 3 {
		h = 3
	}
	return h
}

// SevButtonPositions returns (startX, endX) for each severity filter button.
// Used by click handler in app.go.
func (p *AlertsPanel) SevButtonPositions() [][2]int {
	positions := make([][2]int, len(sevFilterOrder))
	x := 0
	for i, sev := range sevFilterOrder {
		label := sevFilterLabels[i]
		count := 0
		switch sev {
		case sevFilterCritical:
			count = p.countBySev("CRITICAL")
		case sevFilterHigh:
			count = p.countBySev("HIGH")
		case sevFilterMedium:
			count = p.countBySev("MEDIUM")
		case sevFilterLow:
			count = p.countBySev("LOW")
		default:
			count = len(p.items)
		}
		text := fmt.Sprintf(" %s %d ", label, count)
		w := lipgloss.Width(text)
		positions[i] = [2]int{x, x + w}
		x += w + 2 // button + gap
	}
	return positions
}

func (p *AlertsPanel) countBySev(sev string) int {
	n := 0
	for _, e := range p.items {
		if e.Severity == sev {
			n++
		}
	}
	return n
}

func (p *AlertsPanel) View() string {
	if p.message != "" {
		return p.message
	}

	var b strings.Builder

	// Row 0: Severity filter buttons
	critCount, highCount, medCount, lowCount := p.SevCounts()
	counts := []int{len(p.items), critCount, highCount, medCount, lowCount}
	colors := []string{"255", "196", "208", "220", "39"}

	for i, label := range sevFilterLabels {
		sev := sevFilterOrder[i]
		text := fmt.Sprintf(" %s %d ", label, counts[i])
		active := p.sevFilter == sev
		if active {
			style := lipgloss.NewStyle().
				Background(lipgloss.Color(colors[i])).
				Foreground(lipgloss.Color("16")).
				Bold(true)
			b.WriteString(style.Render(text))
		} else {
			style := lipgloss.NewStyle().
				Background(lipgloss.Color("237")).
				Foreground(lipgloss.Color(colors[i]))
			b.WriteString(style.Render(text))
		}
		b.WriteString("  ")
	}

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	selCount := p.SelectionCount()
	if selCount > 0 {
		b.WriteString("  " + lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render(
			fmt.Sprintf("%d selected", selCount)))
		b.WriteString("  " + dim.Render("x:ack  A:deselect"))
	} else {
		b.WriteString("  " + dim.Render("Space:select  a:all  c:clear"))
	}
	b.WriteString("\n")

	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("─", p.width)) + "\n")

	if p.filter != "" {
		b.WriteString(StyleInfo.Render(fmt.Sprintf("  Filter: %s (%d of %d)", p.filter, len(p.filtered), len(p.items))))
		b.WriteString("\n")
	}
	if p.filtering {
		fmt.Fprintf(&b, "  / %s█\n", p.filter)
	}

	if len(p.filtered) == 0 {
		if p.filter != "" || p.sevFilter != "" {
			return b.String() + StyleInfo.Render("  No alerts match the current filters.")
		}
		return b.String() + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("46")).Render("  No active alerts.")
	}

	header := fmt.Sprintf("  %-3s %-12s %-17s %-22s %-30s", "SEL", "SEVERITY", "TIME", "ACTION", "TARGET")
	b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("243")).Render(header))
	b.WriteString("\n")

	maxVisible := p.listHeight()
	start := 0
	if p.cursor >= maxVisible {
		start = p.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(p.filtered) {
		end = len(p.filtered)
	}

	checkOn := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("☑")
	checkOff := lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render("☐")

	for i := start; i < end; i++ {
		item := p.filtered[i]
		badge := sevBadge(item.Severity)
		ts := lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(item.Timestamp.Format("Jan 02 15:04"))
		target := item.Target
		if len(target) > 30 {
			target = target[:27] + "…"
		}
		action := item.Action
		if len(action) > 22 {
			action = action[:19] + "…"
		}

		pointer := "  "
		if i == p.cursor {
			pointer = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render("▸ ")
		}

		check := checkOff
		if p.IsSelected(item.ID) {
			check = checkOn
		}

		line := fmt.Sprintf("%s%s %s %s  %-22s %-30s", pointer, check, badge, ts, action, target)

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

	// Inline detail pane at bottom
	if p.detailOpen {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}

	return b.String()
}

func (p *AlertsPanel) renderDetail() string {
	info := p.GetDetailInfo()
	if info == nil {
		return ""
	}
	e := info.Event

	dh := p.detailHeight()
	borderColor := lipgloss.Color("62")
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Width(p.width - 4).
		MaxHeight(dh)
	titleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true)
	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	valStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	var d strings.Builder
	d.WriteString(titleStyle.Render(fmt.Sprintf("  %s  %s", sevBadge(e.Severity), e.Action)))
	d.WriteString("\n")
	d.WriteString(labelStyle.Render("  Target: ") + valStyle.Render(e.Target) + "\n")
	d.WriteString(labelStyle.Render("  Time:   ") + valStyle.Render(e.Timestamp.Format("2006-01-02 15:04:05")) + "\n")
	// P3-#20: enrichment — show a humanized key=value details line so
	// `host=... port=... mode=... model=openai/gpt-4o-mini` collapses
	// to `host:port mode gpt-4o-mini` the way the retired Textual TUI
	// used to. Raw details are kept below so nothing is hidden — the
	// operator can still copy-paste exact tokens into the audit log.
	if e.Details != "" {
		if human := humanizeAlertDetails(e.Details); human != "" && human != e.Details {
			d.WriteString(labelStyle.Render("  Summary: ") + valStyle.Render(human) + "\n")
		}
		d.WriteString(labelStyle.Render("  Details: ") + valStyle.Render(e.Details) + "\n")
	}
	if e.RunID != "" {
		d.WriteString(labelStyle.Render("  RunID:  ") + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(e.RunID) + "\n")
	}
	if e.TraceID != "" {
		d.WriteString(labelStyle.Render("  TraceID: ") + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(e.TraceID) + "\n")
	}
	if e.RequestID != "" {
		d.WriteString(labelStyle.Render("  ReqID:  ") + lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(e.RequestID) + "\n")
	}

	if len(info.Findings) > 0 {
		d.WriteString("\n" + titleStyle.Render(fmt.Sprintf("  Findings (%d):", len(info.Findings))) + "\n")
		limit := dh - 8
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
			if f.Scanner != "" {
				d.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render(" [" + f.Scanner + "]"))
			}
			if f.Location != "" {
				loc := f.Location
				if len(loc) > 40 {
					loc = loc[:37] + "..."
				}
				d.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("  @ " + loc))
			}
			d.WriteString("\n")
			// P3-#20: surface remediation inline when present —
			// the retired Textual TUI never showed this, but
			// operators asked for it repeatedly. Indented under
			// the finding so it doesn't visually split the list.
			if f.Remediation != "" {
				rem := f.Remediation
				if len(rem) > 120 {
					rem = rem[:117] + "..."
				}
				d.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("245")).Render("      ↳ fix: " + rem))
				d.WriteString("\n")
			}
		}
		if len(info.Findings) > limit {
			d.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(
				fmt.Sprintf("    ... and %d more findings\n", len(info.Findings)-limit)))
		}
	}

	if len(info.History) > 1 {
		d.WriteString("\n" + titleStyle.Render("  History:") + "\n")
		shown := 0
		for _, h := range info.History {
			if h.ID == e.ID {
				continue
			}
			if shown >= 5 {
				break
			}
			ts := h.Timestamp.Format("Jan 02 15:04")
			action := h.Action
			if len(action) > 20 {
				action = action[:17] + "…"
			}
			fmt.Fprintf(&d, "    %s  %-20s  %s\n",
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(ts),
				action,
				SeverityStyle(h.Severity).Render(h.Severity),
			)
			shown++
		}
	}

	d.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("  [Enter] close detail  [Esc] close"))

	return boxStyle.Render(d.String())
}
