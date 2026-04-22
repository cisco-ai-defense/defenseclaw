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
	// silentBypass is the count of passthrough egress events in the
	// last 5 minutes whose payload still looked like an LLM call.
	// It's the one indicator that can flag "our guardrail doesn't
	// know about this provider yet" before policy gets wrong. See
	// SetSilentBypassCount + internal/tui/egress.go.
	silentBypass int

	// doctor is a cached copy of the most recent `defenseclaw
	// doctor --json-output` run, loaded by the owning Model from
	// data_dir on startup and refreshed in the background after
	// Ctrl-R or the quick-action key. It is rendered as a
	// compact status box on the home screen so operators can
	// see "all green" (or top failures) at a glance without
	// re-running the full probe each time. See P3-#21.
	doctor *DoctorCache

	notices      []notice
	scroll       int
	quickActionY int // line offset (pre-scroll) of the quick actions row, set by View
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

// SetDoctorCache plugs in (or clears) the cached doctor snapshot.
// The Overview renderer treats nil and IsEmpty() equivalently —
// both show the "not yet run" placeholder — so callers don't need
// to guard their loads. Rebuilds notices because a "doctor reports
// N failures" line can be surfaced up top when helpful.
func (p *OverviewPanel) SetDoctorCache(c *DoctorCache) {
	p.doctor = c
	p.buildNotices()
}

// DoctorCache returns the currently cached doctor result, or nil
// if none has been loaded yet. Primarily exposed for tests and
// parity with SetDoctorCache.
func (p *OverviewPanel) DoctorCache() *DoctorCache {
	return p.doctor
}

// SetSilentBypassCount plugs in the current window count of
// allowed-but-not-triaged LLM egress events. Populated from
// CountRecentSilentBypass in internal/tui/egress.go, which counts
// the union of:
//
//	branch=passthrough + looks_like_llm=true + decision=allow
//	branch=shape                              + decision=allow
//
// A non-zero value lights up a warning tile on the Overview panel so
// operators see "unknown LLM provider slipped past" at a glance
// without scrolling through the Alerts timeline.
func (p *OverviewPanel) SetSilentBypassCount(n int) {
	if n < 0 {
		n = 0
	}
	p.silentBypass = n
}

// SilentBypassCount returns the currently rendered silent-bypass
// count. Exposed primarily for tests.
func (p *OverviewPanel) SilentBypassCount() int { return p.silentBypass }

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

	// Surface cached doctor failures up top so they aren't
	// buried in the side panel. We only raise this when we
	// actually have data — an un-run doctor is already covered
	// by the "first time?" info notice, and spamming both would
	// be noise.
	if p.doctor != nil && !p.doctor.IsEmpty() {
		if p.doctor.Failed > 0 {
			p.notices = append(p.notices, notice{
				"error",
				fmt.Sprintf("Doctor found %d failure(s) — see the DOCTOR panel or run: defenseclaw doctor", p.doctor.Failed),
			})
		} else if p.doctor.IsStale() {
			// Only nudge about staleness if there are zero
			// failures; a failing cache speaks for itself.
			p.notices = append(p.notices, notice{
				"info",
				"Doctor cache is stale — press [d] on Overview to re-probe",
			})
		}

		// Call out missing required API keys explicitly so they
		// don't get buried inside the generic "N failure(s)"
		// count. This is the single most common reason a fresh
		// install can't reach an upstream provider, and the
		// remediation is a one-liner — surface it right at the
		// top with the exact CLI to run.
		if missing := p.doctor.MissingRequiredCredentials(); len(missing) > 0 {
			preview := missing
			if len(preview) > 2 {
				preview = preview[:2]
			}
			msg := fmt.Sprintf(
				"Missing required API key(s): %s%s — run: defenseclaw keys fill-missing",
				strings.Join(preview, ", "),
				keysOverflowSuffix(len(missing), len(preview)),
			)
			p.notices = append(p.notices, notice{"error", msg})
		}
	}
}

// keysOverflowSuffix renders a compact " (+N more)" tail when the
// missing-keys list is longer than what we chose to preview. Split
// out of buildNotices so the conditional is readable and testable.
func keysOverflowSuffix(total, shown int) string {
	if total <= shown {
		return ""
	}
	return fmt.Sprintf(" (+%d more)", total-shown)
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

	// Right column: Stats + Scanners + Doctor
	var rightCol strings.Builder
	rightCol.WriteString(p.renderStatsBox(colWidth - 4))
	rightCol.WriteString("\n")
	rightCol.WriteString(p.renderScannersBox(colWidth - 4))
	rightCol.WriteString("\n")
	rightCol.WriteString(p.renderDoctorBox(colWidth - 4))

	leftStr := leftCol.String()
	rightStr := rightCol.String()
	columns := lipgloss.JoinHorizontal(lipgloss.Top, leftStr, "  ", rightStr)
	b.WriteString(columns)
	b.WriteString("\n\n")

	// Quick actions bar — record pre-scroll line offset for mouse hit-testing
	preQA := strings.Count(b.String(), "\n")
	b.WriteString(p.renderQuickActions(width))

	content := b.String()
	p.quickActionY = preQA
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
		{"Sinks", "sinks"},
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
		// Prefer the unified llm: block for the Overview header. This
		// is what Config.ResolveLLM(...) returns by default, so it
		// matches what guardrail, MCP scanner, skill scanner, and
		// plugin scanner actually use. Fall back to the legacy
		// inspect_llm fields only when the unified block is empty
		// (load-time migration should normally populate it).
		llmProvider := p.cfg.LLM.Provider
		if llmProvider == "" {
			llmProvider = p.cfg.InspectLLM.Provider
		}
		llmModel := p.cfg.LLM.Model
		if llmModel == "" {
			llmModel = p.cfg.InspectLLM.Model
		}
		if llmProvider != "" {
			rows = append(rows, [2]string{"LLM Provider", llmProvider})
		}
		if llmModel != "" {
			rows = append(rows, [2]string{"LLM Model", llmModel})
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

	// Silent-bypass (shape/path-matching egress left uninspected).
	// Only render when > 0 so a healthy install doesn't get an
	// extra line of noise.
	if p.silentBypass > 0 {
		fmt.Fprintf(&content, " %s %s %s\n",
			p.theme.Medium.Render("Silent bypass"),
			p.theme.Critical.Render(fmt.Sprintf("%d", p.silentBypass)),
			p.theme.Dimmed.Render("(see Alerts → egress)"),
		)
	}

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
		// Guardrail model resolution: prefer the explicit
		// guardrail.model override for transparency (it's what's on
		// the wire), then fall back to the unified llm: block, and
		// finally to the legacy inspect_llm: block for operators
		// still on v4 config files.
		model := p.cfg.Guardrail.Model
		if model == "" {
			model = p.cfg.LLM.Model
		}
		if model == "" {
			model = p.cfg.InspectLLM.Model
		}
		if model != "" {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotRunning, "guardrail",
				lipgloss.NewStyle().Foreground(lipgloss.Color("243")).Render(mode+"/"+model))
		}
	}

	// API-key status row — derived entirely from the cached
	// doctor snapshot so we don't re-probe the registry on
	// every repaint. Two states only: green "all required set"
	// (including when no required credentials exist for the
	// current config) and red "N missing: FOO, BAR". The full
	// roster of OPTIONAL/NOT_USED entries lives behind
	// ``defenseclaw keys`` — this line is a smoke signal.
	if p.doctor != nil && !p.doctor.IsEmpty() {
		missing := p.doctor.MissingRequiredCredentials()
		dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
		if len(missing) == 0 {
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotRunning, "keys",
				dim.Render("all required set"))
		} else {
			preview := missing
			if len(preview) > 2 {
				preview = preview[:2]
			}
			tail := keysOverflowSuffix(len(missing), len(preview))
			fmt.Fprintf(&content, " %s %-16s %s\n",
				p.theme.DotError, "keys",
				p.theme.Critical.Render(fmt.Sprintf(
					"%d missing: %s%s",
					len(missing),
					strings.Join(preview, ", "),
					tail,
				)))
		}
	}

	return box.Render(content.String())
}

// renderDoctorBox paints the Overview "Doctor" status panel.
// Intentionally minimal: the summary line, a freshness hint, and
// the top 3 failures/warnings. The full list lives in the Doctor
// CLI output / future detail modal — this box is a smoke signal,
// not a report viewer.
func (p *OverviewPanel) renderDoctorBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62")).Render("DOCTOR")
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	warn := lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	crit := p.theme.Critical
	ok := p.theme.Clean

	var content strings.Builder
	content.WriteString(title + "\n")

	if p.doctor == nil || p.doctor.IsEmpty() {
		content.WriteString(" " + dim.Render("not yet run — press [d] to probe") + "\n")
		return box.Render(content.String())
	}

	// Summary line with colored counts so the eye can triage at
	// a glance. Keep units plain-text to avoid relying on emoji
	// or icons that don't render uniformly across terminals.
	var parts []string
	if p.doctor.Passed > 0 {
		parts = append(parts, ok.Render(fmt.Sprintf("%d pass", p.doctor.Passed)))
	}
	if p.doctor.Failed > 0 {
		parts = append(parts, crit.Render(fmt.Sprintf("%d fail", p.doctor.Failed)))
	}
	if p.doctor.Warned > 0 {
		parts = append(parts, warn.Render(fmt.Sprintf("%d warn", p.doctor.Warned)))
	}
	if p.doctor.Skipped > 0 {
		parts = append(parts, dim.Render(fmt.Sprintf("%d skip", p.doctor.Skipped)))
	}
	summary := strings.Join(parts, "  ")

	age := FormatAge(p.doctor.Age())
	staleSuffix := ""
	if p.doctor.IsStale() {
		staleSuffix = warn.Render(" (stale — [d] to rerun)")
	}
	fmt.Fprintf(&content, " %s %s%s\n", summary, dim.Render("· "+age), staleSuffix)

	// Show the top 3 fail/warn checks inline so the overview
	// answers "what's broken?" without a panel switch.
	top := p.doctor.TopFailures(3)
	if len(top) > 0 {
		content.WriteString(" " + dim.Render("─────────────────────────") + "\n")
		for _, ck := range top {
			var badge string
			switch ck.Status {
			case "fail":
				badge = crit.Render("[FAIL]")
			case "warn":
				badge = warn.Render("[WARN]")
			default:
				badge = dim.Render("[" + strings.ToUpper(ck.Status) + "]")
			}
			label := truncate(ck.Label, 32)
			detail := ""
			if ck.Detail != "" {
				// Keep the combined line under the box width
				// so lipgloss doesn't word-wrap awkwardly.
				budget := w - 4 /*padding*/ - 8 /*badge*/ - len(label) - 3
				if budget < 8 {
					budget = 8
				}
				detail = dim.Render("  " + truncate(ck.Detail, budget))
			}
			fmt.Fprintf(&content, " %s %s%s\n", badge, label, detail)
		}
	} else {
		content.WriteString(" " + ok.Render("all green") + dim.Render(" — safe to proceed") + "\n")
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
		key.Render("[p]") + dim.Render(" Policy"),
		key.Render("[l]") + dim.Render(" Logs"),
		key.Render("[u]") + dim.Render(" Upgrade"),
		key.Render("[?]") + dim.Render(" Help"),
	}

	return actionStyle.Render("  " + strings.Join(actions, "    "))
}

// quickActionDefs defines the overview quick actions in display order.
// Each entry is (key-char, label-plaintext-width-including-brackets-and-space).
var quickActionDefs = []struct {
	key   string
	width int // len("[x] Label")
}{
	{"s", 12}, // "[s] Scan all"
	{"d", 10}, // "[d] Doctor"
	{"i", 13}, // "[i] Inventory"
	{"g", 13}, // "[g] Guardrail"
	{"p", 10}, // "[p] Policy"
	{"l", 8},  // "[l] Logs"
	{"u", 11}, // "[u] Upgrade"
	{"?", 8},  // "[?] Help"
}

// QuickActionHitTest returns the key character of the quick action at
// horizontal position x within the quick actions row, or "" if none matched.
// The caller should account for the border/padding offset (typically 3-4 cols).
func (p *OverviewPanel) QuickActionHitTest(x int) string {
	pos := 4 // border (1) + padding (1) + leading spaces (2)
	for _, a := range quickActionDefs {
		if x >= pos && x < pos+a.width {
			return a.key
		}
		pos += a.width + 4 // 4 spaces between actions
	}
	return ""
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
	case "sinks":
		return h.Sinks.State
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
	case "sinks":
		return &h.Sinks
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
	strategy := p.cfg.Guardrail.EffectiveStrategy("")
	parts = append(parts, strategy)
	if p.cfg.Guardrail.Judge.Enabled && p.cfg.Guardrail.Judge.Model != "" {
		parts = append(parts, "judge:"+p.cfg.Guardrail.Judge.Model)
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
