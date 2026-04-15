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
	"os/exec"
	"strings"
	"time"

	"charm.land/lipgloss/v2"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const asciiLogo = `    ____        ____                   ______
   / __ \___   / __/__  ____  _____ _/ ____/ /__ _      __
  / / / / _ \ / /_/ _ \/ __ \/ ___// __/ / / __ \ | /| / /
 / /_/ /  __// __/  __/ / / (__  )/ /___/ / /_/ / |/ |/ /
/_____/\___//_/  \___/_/ /_/____//_____/_/\__,_/|__/|__/`

// OverviewPanel renders the dashboard home screen.
type OverviewPanel struct {
	theme   *Theme
	cfg     *config.Config
	version string
	health  *HealthSnapshot

	blockedSkills int
	allowedSkills int
	blockedMCPs   int
	allowedMCPs   int
	totalScans    int
	activeAlerts  int

	notices []notice
	scroll  int
}

// ScrollBy adjusts the overview scroll for mouse wheel.
func (p *OverviewPanel) ScrollBy(delta int) {
	p.scroll += delta
	if p.scroll < 0 {
		p.scroll = 0
	}
}

type notice struct {
	level   string
	message string
}

func NewOverviewPanel(theme *Theme, cfg *config.Config, version string) OverviewPanel {
	return OverviewPanel{theme: theme, cfg: cfg, version: version}
}

func (p *OverviewPanel) SetHealth(h *HealthSnapshot) {
	p.health = h
	p.buildNotices()
}

func (p *OverviewPanel) SetEnforcementCounts(store *audit.Store) error {
	counts, err := store.GetCounts()
	if err != nil {
		return err
	}
	p.blockedSkills = counts.BlockedSkills
	p.allowedSkills = counts.AllowedSkills
	p.blockedMCPs = counts.BlockedMCPs
	p.allowedMCPs = counts.AllowedMCPs
	p.totalScans = counts.TotalScans
	p.activeAlerts = counts.Alerts
	return nil
}

func (p *OverviewPanel) buildNotices() {
	p.notices = nil

	gatewayOff := p.health == nil || p.health.Gateway.State != "running"
	guardrailOff := p.cfg == nil || !p.cfg.Guardrail.Enabled
	_, scannerErr := exec.LookPath("skill-scanner")

	if gatewayOff && guardrailOff && scannerErr != nil {
		p.notices = append(p.notices, notice{"info", "First time? Head to the Setup tab (press 0) to configure DefenseClaw."})
	}

	if gatewayOff {
		p.notices = append(p.notices, notice{"error", "Gateway is offline — press : then \"start\" to launch"})
	}
	if p.cfg != nil && guardrailOff {
		p.notices = append(p.notices, notice{"warn", "LLM guardrail not configured — press [g] to set up"})
	}
	if scannerErr != nil {
		p.notices = append(p.notices, notice{"warn", "skill-scanner not on PATH — run: pip install skill-scanner"})
	}
}

func (p *OverviewPanel) View(width, height int) string {
	var b strings.Builder

	// ASCII logo with gradient coloring
	logoStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("62")).
		Bold(true)
	b.WriteString(logoStyle.Render(asciiLogo))
	b.WriteString("\n")
	tagline := lipgloss.NewStyle().
		Foreground(lipgloss.Color("243")).
		Italic(true).
		Render(fmt.Sprintf("  Enterprise AI Governance  v%s", p.version))
	b.WriteString(tagline)
	b.WriteString("\n\n")

	// Smart notices
	for _, n := range p.notices {
		var icon, style string
		switch n.level {
		case "error":
			icon = " [!] "
			style = p.theme.Critical.Render(icon + n.message)
		case "warn":
			icon = " [*] "
			style = p.theme.High.Render(icon + n.message)
		case "info":
			icon = " [>] "
			style = lipgloss.NewStyle().Foreground(lipgloss.Color("62")).Bold(true).Render(icon + n.message)
		default:
			icon = " [-] "
			style = p.theme.Clean.Render(icon + n.message)
		}
		b.WriteString(" " + style + "\n")
	}
	if len(p.notices) > 0 {
		b.WriteString("\n")
	}

	colWidth := width / 2
	if colWidth < 40 {
		colWidth = 40
	}

	// Left column: Services + Config
	var leftCol strings.Builder
	leftCol.WriteString(p.renderServicesBox(colWidth - 4))
	leftCol.WriteString("\n")
	leftCol.WriteString(p.renderConfigBox(colWidth - 4))

	// Right column: Stats + Scanners
	var rightCol strings.Builder
	rightCol.WriteString(p.renderStatsBox(colWidth - 4))
	rightCol.WriteString("\n")
	rightCol.WriteString(p.renderScannersBox(colWidth - 4))

	leftStr := leftCol.String()
	rightStr := rightCol.String()
	columns := lipgloss.JoinHorizontal(lipgloss.Top, leftStr, "  ", rightStr)
	b.WriteString(columns)
	b.WriteString("\n\n")

	// Quick actions bar
	b.WriteString(p.renderQuickActions(width))

	content := b.String()
	if p.scroll > 0 {
		lines := strings.Split(content, "\n")
		if p.scroll >= len(lines) {
			p.scroll = len(lines) - 1
		}
		content = strings.Join(lines[p.scroll:], "\n")
	}
	return content
}

func (p *OverviewPanel) renderServicesBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("SERVICES")
	var content strings.Builder
	content.WriteString(title + "\n")

	services := []struct{ name, key string }{
		{"Gateway", "gateway"},
		{"Watchdog", "watcher"},
		{"Guardrail", "guardrail"},
		{"API", "api"},
		{"Splunk", "splunk"},
		{"Telemetry", "telemetry"},
		{"Sandbox", "sandbox"},
	}

	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	errStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("196"))

	for _, svc := range services {
		state := p.subsystemState(p.health, svc.key)
		dot := p.theme.StateDot(state)
		stateStr := p.theme.StateColor(state).Render(state)
		detail := ""
		switch svc.key {
		case "gateway":
			detail = p.gatewayDetail()
		case "watcher":
			detail = p.watchdogDetail()
		case "guardrail":
			detail = p.guardrailDetail()
		case "api":
			detail = p.apiDetail()
		}
		if detail != "" {
			detail = dim.Render(" " + detail)
		}

		sinceStr := ""
		lastErr := ""
		if sh := p.subsystemHealth(svc.key); sh != nil {
			if sh.Since != "" {
				sinceStr = dim.Render(" since " + truncate(sh.Since, 16))
			}
			if state != "running" && sh.LastError != "" {
				lastErr = errStyle.Render(" " + truncate(sh.LastError, 40))
			}
		}
		fmt.Fprintf(&content, " %s %-11s %-12s%s%s%s\n", dot, svc.name, stateStr, detail, sinceStr, lastErr)
	}

	return box.Render(content.String())
}

func (p *OverviewPanel) renderConfigBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("CONFIGURATION")
	var content strings.Builder
	content.WriteString(title + "\n")

	dimLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	if p.cfg != nil {
		rows := [][2]string{
			{"Mode", string(p.cfg.Claw.Mode)},
			{"Environment", p.cfg.Environment},
			{"Policy dir", p.cfg.PolicyDir},
			{"Data dir", p.cfg.DataDir},
		}
		if p.cfg.InspectLLM.Provider != "" {
			rows = append(rows, [2]string{"LLM Provider", p.cfg.InspectLLM.Provider})
		}
		if p.cfg.InspectLLM.Model != "" {
			rows = append(rows, [2]string{"LLM Model", p.cfg.InspectLLM.Model})
		}
		if p.cfg.CiscoAIDefense.Endpoint != "" {
			rows = append(rows, [2]string{"AI Defense", p.cfg.CiscoAIDefense.Endpoint})
		}
		for _, r := range rows {
			fmt.Fprintf(&content, " %s  %s\n", dimLabel.Render(fmt.Sprintf("%-14s", r[0])), r[1])
		}
	} else {
		content.WriteString(dimLabel.Render(" (config not loaded)") + "\n")
	}

	return box.Render(content.String())
}

func (p *OverviewPanel) renderStatsBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("ENFORCEMENT")
	var content strings.Builder
	content.WriteString(title + "\n")

	// Alerts with bar visualization
	alertBar := p.miniBar(p.activeAlerts, 500, 20)
	alertNum := fmt.Sprintf("%d", p.activeAlerts)
	if p.activeAlerts > 0 {
		alertNum = p.theme.Critical.Render(alertNum)
	} else {
		alertNum = p.theme.Clean.Render(alertNum)
	}
	fmt.Fprintf(&content, " Alerts      %s %s\n", alertNum, alertBar)

	// Scans
	scanBar := p.miniBar(p.totalScans, 1000, 20)
	fmt.Fprintf(&content, " Total scans %s %s\n", p.theme.Clean.Render(fmt.Sprintf("%d", p.totalScans)), scanBar)

	content.WriteString(" ─────────────────────────\n")

	fmt.Fprintf(&content, " Skills  %s blocked  %s allowed\n",
		p.colorCount(p.blockedSkills, true), p.colorCount(p.allowedSkills, false))
	fmt.Fprintf(&content, " MCPs    %s blocked  %s allowed\n",
		p.colorCount(p.blockedMCPs, true), p.colorCount(p.allowedMCPs, false))

	return box.Render(content.String())
}

func (p *OverviewPanel) renderScannersBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("SCANNERS")
	var content strings.Builder
	content.WriteString(title + "\n")

	scanners := []struct{ name, kind string }{
		{"skill-scanner", "external"},
		{"mcp-scanner", "external"},
		{"aibom", "built-in"},
		{"codeguard", "built-in"},
	}

	for _, s := range scanners {
		if s.kind == "built-in" {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotRunning, s.name,
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("built-in"))
		} else if _, err := exec.LookPath(s.name); err == nil {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotRunning, s.name,
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render("installed"))
		} else {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotError, s.name,
				p.theme.Critical.Render("not found"))
		}
	}

	// LLM info
	if p.cfg != nil && p.cfg.Guardrail.Enabled {
		mode := p.cfg.Guardrail.Mode
		if mode == "" {
			mode = "observe"
		}
		model := p.cfg.Guardrail.Model
		if model == "" {
			model = p.cfg.InspectLLM.Model
		}
		if model != "" {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotRunning, "guardrail",
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(mode+"/"+model))
		}
	}

	return box.Render(content.String())
}

func (p *OverviewPanel) renderQuickActions(width int) string {
	actionStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238")).
		Padding(0, 1).
		Width(width - 4)

	key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	actions := []string{
		key.Render("[s]") + dim.Render(" Scan all"),
		key.Render("[d]") + dim.Render(" Doctor"),
		key.Render("[i]") + dim.Render(" Inventory"),
		key.Render("[g]") + dim.Render(" Guardrail"),
		key.Render("[l]") + dim.Render(" Logs"),
		key.Render("[u]") + dim.Render(" Upgrade"),
		key.Render("[?]") + dim.Render(" Help"),
	}

	return actionStyle.Render("  " + strings.Join(actions, "    "))
}

func (p *OverviewPanel) miniBar(value, max, barWidth int) string {
	if max <= 0 {
		max = 1
	}
	filled := value * barWidth / max
	if filled > barWidth {
		filled = barWidth
	}
	if filled < 0 {
		filled = 0
	}
	empty := barWidth - filled

	filledColor := lipgloss.Color("62")
	if value > max/2 {
		filledColor = lipgloss.Color("208")
	}
	if value > max*3/4 {
		filledColor = lipgloss.Color("196")
	}

	bar := lipgloss.NewStyle().Foreground(filledColor).Render(strings.Repeat("█", filled))
	bar += lipgloss.NewStyle().Foreground(lipgloss.Color("238")).Render(strings.Repeat("░", empty))
	return bar
}

func (p *OverviewPanel) colorCount(n int, warnIfNonZero bool) string {
	s := fmt.Sprintf("%-3d", n)
	if warnIfNonZero && n > 0 {
		return p.theme.Critical.Render(s)
	}
	return p.theme.Clean.Render(s)
}

func (p *OverviewPanel) subsystemState(h *HealthSnapshot, name string) string {
	if h == nil {
		return "unknown"
	}
	switch name {
	case "gateway":
		return h.Gateway.State
	case "watcher":
		return h.Watcher.State
	case "guardrail":
		return h.Guardrail.State
	case "splunk":
		return h.Splunk.State
	case "telemetry":
		return h.Telemetry.State
	case "api":
		return h.API.State
	case "sandbox":
		if h.Sandbox != nil {
			return h.Sandbox.State
		}
		return "disabled"
	default:
		return "unknown"
	}
}

func (p *OverviewPanel) subsystemHealth(name string) *SubsystemHealth {
	h := p.health
	if h == nil {
		return nil
	}
	switch name {
	case "gateway":
		return &h.Gateway
	case "watcher":
		return &h.Watcher
	case "guardrail":
		return &h.Guardrail
	case "splunk":
		return &h.Splunk
	case "telemetry":
		return &h.Telemetry
	case "api":
		return &h.API
	case "sandbox":
		return h.Sandbox
	default:
		return nil
	}
}

func (p *OverviewPanel) gatewayDetail() string {
	if p.health == nil {
		return ""
	}
	uptime := time.Duration(p.health.UptimeMS) * time.Millisecond
	if uptime > 0 {
		return fmt.Sprintf("up %s", formatDuration(uptime))
	}
	return ""
}

func (p *OverviewPanel) watchdogDetail() string {
	if p.health == nil {
		return ""
	}
	d := p.health.Watcher.Details
	if d == nil {
		return ""
	}
	parts := []string{}
	if dirs, ok := d["skill_dirs"]; ok {
		parts = append(parts, fmt.Sprintf("%v skill dirs", dirs))
	}
	if dirs, ok := d["plugin_dirs"]; ok {
		parts = append(parts, fmt.Sprintf("%v plugin dirs", dirs))
	}
	if len(parts) > 0 {
		return strings.Join(parts, ", ")
	}
	return ""
}

func (p *OverviewPanel) guardrailDetail() string {
	if p.cfg == nil || !p.cfg.Guardrail.Enabled {
		return ""
	}
	parts := []string{}
	if p.cfg.Guardrail.Mode != "" {
		parts = append(parts, p.cfg.Guardrail.Mode)
	}
	if p.cfg.Guardrail.Port > 0 {
		parts = append(parts, fmt.Sprintf("port %d", p.cfg.Guardrail.Port))
	}
	return strings.Join(parts, ", ")
}

func (p *OverviewPanel) apiDetail() string {
	if p.health == nil {
		return ""
	}
	if addr, ok := p.health.API.Details["addr"]; ok {
		return fmt.Sprintf("%v", addr)
	}
	return ""
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm", h, m)
	}
	if m > 0 {
		return fmt.Sprintf("%dm", m)
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}
