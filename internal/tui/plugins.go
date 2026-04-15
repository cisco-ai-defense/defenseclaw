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
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type pluginItem struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Version     string     `json:"version"`
	Origin      string     `json:"origin"`
	Status      string     `json:"status"`
	Enabled     bool       `json:"enabled"`
	Verdict     string     `json:"verdict"`
	Scan        *pluginScan `json:"scan,omitempty"`
}

type pluginScan struct {
	Clean        bool   `json:"clean"`
	MaxSeverity  string `json:"max_severity"`
	TotalFindings int   `json:"total_findings"`
}

type PluginDetailInfo struct {
	Item    pluginItem
	Action  *audit.ActionEntry
	History []audit.Event
}

type PluginsPanel struct {
	theme          *Theme
	store          *audit.Store
	cursor         int
	items          []pluginItem
	loaded         bool
	loading        bool
	errMsg         string
	detailOpen     bool
	width          int
	height         int
	detailCache    *PluginDetailInfo
	detailCacheIdx int
}

// PluginsLoadedMsg is sent when plugin list completes.
type PluginsLoadedMsg struct {
	Items []pluginItem
	Err   error
}

func NewPluginsPanel(theme *Theme, store *audit.Store) PluginsPanel {
	return PluginsPanel{theme: theme, store: store}
}

// LoadCmd returns a tea.Cmd that loads plugins asynchronously.
func (p *PluginsPanel) LoadCmd() tea.Cmd {
	p.loading = true
	return func() tea.Msg {
		cmd := exec.Command("defenseclaw", "plugin", "list", "--json")
		out, err := cmd.Output()
		if err != nil {
			return PluginsLoadedMsg{Err: err}
		}
		var items []pluginItem
		if err := json.Unmarshal(out, &items); err != nil {
			return PluginsLoadedMsg{Err: err}
		}
		return PluginsLoadedMsg{Items: items}
	}
}

// ApplyLoaded updates the panel with loaded data.
func (p *PluginsPanel) ApplyLoaded(msg PluginsLoadedMsg) {
	p.loading = false
	if msg.Err != nil {
		p.errMsg = fmt.Sprintf("Error loading plugins: %v", msg.Err)
		return
	}
	p.items = msg.Items
	p.loaded = true
	p.errMsg = ""
	if p.cursor >= len(p.items) && len(p.items) > 0 {
		p.cursor = len(p.items) - 1
	}
}

func (p *PluginsPanel) CursorUp()   { if p.cursor > 0 { p.cursor-- } }
func (p *PluginsPanel) CursorDown() { if p.cursor < len(p.items)-1 { p.cursor++ } }

func (p *PluginsPanel) Selected() *pluginItem {
	if p.cursor >= 0 && p.cursor < len(p.items) {
		return &p.items[p.cursor]
	}
	return nil
}

func (p *PluginsPanel) Count() int        { return len(p.items) }
func (p *PluginsPanel) FilteredCount() int { return len(p.items) }
func (p *PluginsPanel) CursorAt() int     { return p.cursor }

func (p *PluginsPanel) ScrollOffset() int {
	maxVisible := p.listHeight()
	if p.cursor >= maxVisible {
		return p.cursor - maxVisible + 1
	}
	return 0
}

func (p *PluginsPanel) SetCursor(i int) {
	if i < 0 {
		i = 0
	}
	if i >= len(p.items) {
		i = len(p.items) - 1
	}
	p.cursor = i
}

func (p *PluginsPanel) ScrollBy(delta int) {
	p.cursor += delta
	if p.cursor < 0 {
		p.cursor = 0
	}
	if p.cursor >= len(p.items) {
		p.cursor = len(p.items) - 1
	}
}

func (p *PluginsPanel) IsDetailOpen() bool { return p.detailOpen }
func (p *PluginsPanel) ToggleDetail() {
	p.detailOpen = !p.detailOpen
	p.detailCache = nil
}

func (p *PluginsPanel) detailHeight() int {
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

func (p *PluginsPanel) listHeight() int {
	h := p.height - 1 - p.detailHeight() // header(1)
	if h < 3 {
		h = 3
	}
	return h
}

func (p *PluginsPanel) GetDetailInfo() *PluginDetailInfo {
	sel := p.Selected()
	if sel == nil {
		return nil
	}
	info := &PluginDetailInfo{Item: *sel}
	if p.store == nil {
		return info
	}
	name := sel.Name
	if name == "" {
		name = sel.ID
	}
	action, err := p.store.GetAction("plugin", sel.ID)
	if err == nil && action != nil {
		info.Action = action
	}
	history, _ := p.store.ListEventsByTarget(name, 10)
	if len(history) == 0 {
		history, _ = p.store.ListEventsByTarget(sel.ID, 10)
	}
	info.History = history
	return info
}

func (p *PluginsPanel) View(width, height int) string {
	p.width = width
	p.height = height
	if p.loading {
		return p.theme.HintText.Render("  Loading plugins...")
	}

	if p.errMsg != "" {
		return p.theme.Critical.Render("  " + p.errMsg)
	}

	if !p.loaded {
		return p.theme.Dimmed.Render("  Press \"r\" to load plugins. This runs \"defenseclaw plugin list\" to enumerate installed plugins.")
	}

	if len(p.items) == 0 {
		return p.theme.Dimmed.Render("  No plugins detected. Plugins extend OpenClaw with tools and hooks.\n  Use : then \"plugin install <name>\" to add one.")
	}

	var b strings.Builder
	header := fmt.Sprintf("  %-20s %-12s %-10s %-10s %-10s %-10s %-8s",
		"NAME", "VERSION", "ORIGIN", "STATUS", "VERDICT", "SEVERITY", "FINDINGS")
	b.WriteString(HeaderStyle.Render(header))
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
	if end > len(p.items) {
		end = len(p.items)
	}

	for i := start; i < end; i++ {
		item := p.items[i]
		verdict := p.verdictStyle(item.Verdict).Render(fmt.Sprintf("%-10s", item.Verdict))
		severity := p.theme.Dimmed.Render("—")
		findings := p.theme.Dimmed.Render("—")
		if item.Scan != nil {
			severity = SeverityStyle(item.Scan.MaxSeverity).Render(fmt.Sprintf("%-10s", item.Scan.MaxSeverity))
			findings = fmt.Sprintf("%-8d", item.Scan.TotalFindings)
		}

		name := item.Name
		if name == "" {
			name = item.ID
		}

		line := fmt.Sprintf("  %-20s %-12s %-10s %-10s %s %s %s",
			truncate(name, 20), truncate(item.Version, 12),
			truncate(item.Origin, 10), truncate(item.Status, 10),
			verdict, severity, findings)

		if i == p.cursor {
			line = SelectedStyle.Width(width).Render(line)
		}
		b.WriteString(line + "\n")
	}

	if len(p.items) > maxVisible {
		b.WriteString(p.theme.Dimmed.Render(fmt.Sprintf(
			"  showing %d-%d of %d", start+1, end, len(p.items))))
	}

	if p.detailOpen {
		b.WriteString("\n")
		b.WriteString(p.renderDetail())
	}

	return b.String()
}

func (p *PluginsPanel) renderDetail() string {
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

	name := info.Item.Name
	if name == "" {
		name = info.Item.ID
	}

	var d strings.Builder
	d.WriteString(titleStyle.Render("  PLUGIN: "+name) + "\n")

	d.WriteString(labelStyle.Render("  ID: ") + valStyle.Render(info.Item.ID))
	if info.Item.Version != "" {
		d.WriteString(labelStyle.Render("    Version: ") + valStyle.Render(info.Item.Version))
	}
	d.WriteString("\n")

	if info.Item.Origin != "" {
		d.WriteString(labelStyle.Render("  Origin: ") + valStyle.Render(info.Item.Origin))
	}
	if info.Item.Status != "" {
		d.WriteString(labelStyle.Render("    Status: ") + valStyle.Render(info.Item.Status))
	}
	d.WriteString("\n")

	if info.Item.Description != "" {
		desc := info.Item.Description
		if len(desc) > 80 {
			desc = desc[:77] + "..."
		}
		d.WriteString(labelStyle.Render("  Desc: ") + valStyle.Render(desc) + "\n")
	}

	if info.Item.Verdict != "" {
		d.WriteString(labelStyle.Render("  Verdict: ") + valStyle.Render(info.Item.Verdict))
	}
	if info.Item.Scan != nil {
		d.WriteString(labelStyle.Render("    Severity: ") +
			SeverityStyle(info.Item.Scan.MaxSeverity).Render(info.Item.Scan.MaxSeverity))
		d.WriteString(labelStyle.Render(fmt.Sprintf("    Findings: %d", info.Item.Scan.TotalFindings)))
	}
	d.WriteString("\n")

	if info.Action != nil {
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
		if info.Action.Reason != "" {
			d.WriteString(labelStyle.Render("  Reason: ") + valStyle.Render(info.Action.Reason) + "\n")
		}
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

	d.WriteString(labelStyle.Render("  [Enter] close  [Esc] close"))

	return boxStyle.Render(d.String())
}

func (p *PluginsPanel) verdictStyle(verdict string) Style {
	switch verdict {
	case "blocked":
		return p.theme.Blocked
	case "warning":
		return p.theme.Medium
	case "clean", "allowed":
		return p.theme.Clean
	default:
		return p.theme.Disabled
	}
}
