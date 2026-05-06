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

	// aiUsage is the most recent snapshot pulled from the sidecar's
	// /api/v1/ai-usage endpoint. nil until the first poll completes
	// (or when AI discovery is disabled). The DISCOVERED AI AGENTS
	// panel reads this directly; we deliberately keep the old
	// snapshot around on transient fetch errors so the panel
	// doesn't flap during gateway restarts. See pollAIUsage in
	// internal/tui/app.go and SetAIUsage below.
	aiUsage *AIUsageSnapshot

	// aiUsageSorted is a precomputed, sort-by-priority view of
	// aiUsage.Signals so the View() path does not pay an O(n log n)
	// (or worse, a per-frame O(n^2)) sort cost every time the
	// dashboard repaints. SetAIUsage rebuilds this slice when the
	// snapshot changes; View() walks it in O(min(n, maxRows)).
	aiUsageSorted []AIUsageSignal

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

// SetAIUsage plugs in (or clears) the latest AI discovery snapshot
// pulled from the sidecar. Passing nil clears the cache and the
// DISCOVERED AI AGENTS panel reverts to its "ai discovery offline"
// placeholder; this is intentional for unit tests but Update never
// calls SetAIUsage(nil) on its own — see the aiUsageUpdateMsg
// branch in internal/tui/app.go which keeps the prior snapshot on
// transient fetch errors.
func (p *OverviewPanel) SetAIUsage(s *AIUsageSnapshot) {
	p.aiUsage = s
	if s == nil {
		p.aiUsageSorted = nil
		return
	}
	// Precompute the sorted view here so View() can skip the work
	// on every repaint. This was a measurable hot path for
	// workspaces with hundreds of detected signals.
	p.aiUsageSorted = sortAIDiscoverySignalsForOverview(s.Signals)
}

// AIUsage returns the currently rendered AI discovery snapshot,
// or nil if none has been received yet. Exposed primarily for
// tests so they can assert what the renderer is pulling from.
func (p *OverviewPanel) AIUsage() *AIUsageSnapshot { return p.aiUsage }

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

	// "Broken" means the operator should care: stopped/error/reconnecting
	// all imply the sidecar tried to bring up the gateway and failed.
	// "Disabled" is intentional standalone mode (hook-only connectors,
	// codex/claudecode + loopback host, or `gateway.fleet_mode: disabled`) — the gateway
	// dial loop short-circuits to StateDisabled by design, and the
	// rest of the pipeline (proxy, hooks, audit, watcher local
	// enforcement) is fully functional. Treating disabled as
	// "offline" produced a misleading red error notice on every
	// hook-only dev box. See sidecar.go::runGatewayLoop standalone
	// short-circuit + gatewayShouldConnectForConfiguredConnector.
	gatewayBroken := p.health == nil || gatewayHealthIsBroken(p.health.Gateway.State)
	gatewayStandalone := p.health != nil && strings.EqualFold(p.health.Gateway.State, "disabled")
	guardrailOff := p.cfg == nil || !p.cfg.Guardrail.Enabled
	_, scannerErr := exec.LookPath("skill-scanner")

	if gatewayBroken && guardrailOff && scannerErr != nil {
		p.notices = append(p.notices, notice{"info", "First time? Head to the Setup tab (press 0) to configure DefenseClaw."})
	}

	if gatewayBroken {
		p.notices = append(p.notices, notice{"error", "Gateway is offline — press : then \"start\" to launch"})
	} else if gatewayStandalone {
		// Intentional standalone — surface a single info-level breadcrumb
		// so an operator who mis-set `gateway.fleet_mode: disabled` on
		// a fleet box can spot it, but nothing screams "broken".
		hint := p.gatewayStandaloneHint()
		if hint != "" {
			p.notices = append(p.notices, notice{"info", hint})
		}
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
		// Count failures that live /health doesn't already disprove.
		// This is the same reconciliation renderDoctorBox does so the
		// "Doctor found N failure(s)" notice and the DOCTOR summary
		// agree. A common case: the user restarted the sidecar after
		// yesterday's probe, and the cached "[FAIL] Sidecar API" no
		// longer reflects reality. Without this, we'd shout about a
		// failure that the SERVICES box right below shows as RUNNING.
		_, contradicted := partitionDoctorChecks(p.doctor.Checks, p.health)
		effectiveFailed := p.doctor.Failed
		for _, ck := range contradicted {
			if ck.Status == "fail" {
				effectiveFailed--
			}
		}
		if effectiveFailed < 0 {
			effectiveFailed = 0
		}

		if effectiveFailed > 0 {
			p.notices = append(p.notices, notice{
				"error",
				fmt.Sprintf("Doctor found %d failure(s) — see the DOCTOR panel or run: defenseclaw doctor", effectiveFailed),
			})
		} else if len(contradicted) > 0 {
			// All cached failures are now contradicted by /health —
			// the world recovered since the last probe. Nudge the
			// user to refresh the cache so the panel can go green.
			p.notices = append(p.notices, notice{
				"info",
				fmt.Sprintf("Doctor cache shows %d stale failure(s) that /health disagrees with — press [d] to refresh", len(contradicted)),
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

	// Connector drift / no-traffic notices. Both rely on a live
	// /health snapshot, so skip when health is nil — the operator
	// is already seeing "(configured, not connected)" on the Agent
	// row and we don't want to double-warn.
	if p.health != nil && p.health.Connector != nil && p.cfg != nil {
		live := strings.TrimSpace(p.health.Connector.Name)
		configured := strings.TrimSpace(string(p.cfg.Claw.Mode))
		if live != "" && configured != "" && live != configured {
			p.notices = append(p.notices, notice{
				"warn",
				fmt.Sprintf(
					"Connector drift: configured %s but gateway is routing for %s — restart the sidecar after editing claw.mode",
					FriendlyConnectorName(configured),
					FriendlyConnectorName(live),
				),
			})
		}
		// Quiet-channel detector: if the gateway has been up for
		// over a minute and the active connector hasn't seen a
		// single request, the agent is probably not actually
		// connecting through us. Common causes: wrong port in the
		// agent config, an env var that bypasses the proxy, or a
		// dropped websocket. Surface as info — this is informational
		// for the typical "I configured DefenseClaw but my agent
		// keeps talking to the upstream directly" debug path.
		uptime := time.Duration(p.health.UptimeMS) * time.Millisecond
		if p.health.Connector.Requests == 0 && uptime > 60*time.Second {
			p.notices = append(p.notices, notice{
				"info",
				zeroConnectorRequestsNotice(p.cfg, live, uptime),
			})
		}
	}
}

func zeroConnectorRequestsNotice(cfg *config.Config, connectorName string, uptime time.Duration) string {
	name := FriendlyConnectorName(connectorName)
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "codex":
		if cfg != nil && !cfg.Guardrail.CodexEnforcementEnabled {
			return fmt.Sprintf(
				"%s connector has seen 0 hook events after %s — normal until Codex emits a hook/notify event; verify ~/.codex hooks if this persists",
				name,
				formatDuration(uptime),
			)
		}
	case "claudecode":
		if cfg != nil && !cfg.Guardrail.ClaudeCodeEnforcementEnabled {
			return fmt.Sprintf(
				"%s connector has seen 0 hook events after %s — normal until Claude Code emits a hook event; verify Claude Code hooks if this persists",
				name,
				formatDuration(uptime),
			)
		}
	case "hermes", "cursor", "windsurf", "geminicli", "copilot":
		return fmt.Sprintf(
			"%s connector has seen 0 hook events after %s — normal until the agent emits a supported hook; verify connector hook setup if this persists",
			name,
			formatDuration(uptime),
		)
	}
	return fmt.Sprintf(
		"%s connector has seen 0 requests after %s — verify your agent is dialing the gateway port (gateway.port)",
		name,
		formatDuration(uptime),
	)
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

	// Full-width DISCOVERED AI AGENTS row. We deliberately render
	// this beneath the two-column SERVICES/CONFIG/STATS/SCANNERS/
	// DOCTOR grid so a sparse agent list doesn't unbalance the
	// columns and a dense one (10+ agents on a developer box) can
	// stretch horizontally without truncating vendor names. The
	// inner table still caps the row count itself — see
	// renderAIDiscoveryBox.
	b.WriteString(p.renderAIDiscoveryBox(width - 4))
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
		{"Agent", "agent"},
		{"Watchdog", "watcher"},
		{"Guardrail", "guardrail"},
		{"API", "api"},
		{"Sinks", "sinks"},
		{"Telemetry", "telemetry"},
		{"AI Visibility", "ai_discovery"},
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
		case "agent":
			detail = p.agentDetail()
		case "watcher":
			detail = p.watchdogDetail()
		case "guardrail":
			detail = p.guardrailDetail()
		case "api":
			detail = p.apiDetail()
		case "ai_discovery":
			detail = p.aiDiscoveryDetail()
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
	const labelWidth = 17

	if p.cfg != nil {
		modeRaw := string(p.cfg.Claw.Mode)
		modeLabel := FriendlyConnectorName(modeRaw)
		if modeRaw != "" && !strings.EqualFold(modeRaw, modeLabel) {
			modeLabel = fmt.Sprintf("%s (%s)", modeLabel, modeRaw)
		}
		rows := [][2]string{
			{"Agent", modeLabel},
			{"Redaction", p.redactionStatusText()},
			{"Policy posture", p.policyPostureText()},
			{"Enforcement", p.connectorEnforcementText()},
			{"Human approval", p.hiltStatusText()},
			{"Approval support", p.hiltSupportText()},
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
			fmt.Fprintf(&content, " %s  %s\n", dimLabel.Render(fmt.Sprintf("%-*s", labelWidth, r[0])), r[1])
		}
	} else {
		content.WriteString(dimLabel.Render(" (config not loaded)") + "\n")
		fmt.Fprintf(&content, " %s  %s\n", dimLabel.Render(fmt.Sprintf("%-*s", labelWidth, "Redaction")), p.redactionStatusText())
		fmt.Fprintf(&content, " %s  %s\n", dimLabel.Render(fmt.Sprintf("%-*s", labelWidth, "Human approval")), p.hiltStatusText())
	}

	return box.Render(content.String())
}

func (p *OverviewPanel) redactionStatusText() string {
	if p.redactionDisabled() {
		return p.theme.Critical.Render("OFF (RAW)")
	}
	return p.theme.Clean.Render("ON (redacted)")
}

func (p *OverviewPanel) redactionDisabled() bool {
	if redactionDisabledForLogsBadge() {
		return true
	}
	return p.cfg != nil && p.cfg.Privacy.DisableRedaction
}

func (p *OverviewPanel) hiltStatusText() string {
	if p.cfg == nil || !p.cfg.Guardrail.HILT.Enabled {
		return p.theme.Dimmed.Render("OFF")
	}

	minSeverity := strings.ToUpper(strings.TrimSpace(p.cfg.Guardrail.HILT.MinSeverity))
	if minSeverity == "" {
		minSeverity = "HIGH"
	}
	mode := strings.ToLower(strings.TrimSpace(p.cfg.Guardrail.Mode))
	if mode == "" {
		mode = "observe"
	}
	confirmRange := minSeverity
	if minSeverity != "HIGH" {
		confirmRange += "+"
	}
	label := fmt.Sprintf("ON %s", confirmRange)
	if mode != "action" {
		return p.theme.Medium.Render(label + " (inactive)")
	}
	return p.theme.High.Render(label + " (CRIT blocks)")
}

func (p *OverviewPanel) policyPostureText() string {
	if p.cfg == nil {
		return p.theme.Dimmed.Render("unknown")
	}

	profile := guardrailProfileName(p.cfg.Guardrail.RulePackDir)
	switch profile {
	case "strict":
		return p.theme.High.Render("strict: block MEDIUM+")
	case "permissive":
		return p.theme.Clean.Render("permissive: block CRITICAL")
	default:
		return p.theme.Medium.Render("balanced: block CRIT, alert MED+")
	}
}

func guardrailProfileName(rulePackDir string) string {
	profile := strings.ToLower(strings.TrimSpace(rulePackDir))
	if profile == "" {
		return "balanced"
	}
	parts := strings.FieldsFunc(profile, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if len(parts) > 0 {
		profile = parts[len(parts)-1]
	}
	if profile == "default" {
		return "balanced"
	}
	return profile
}

func (p *OverviewPanel) connectorEnforcementText() string {
	if p.cfg == nil {
		return p.theme.Dimmed.Render("unknown")
	}
	if !p.cfg.Guardrail.Enabled {
		return p.theme.Dimmed.Render("disabled")
	}

	connector := p.activeConnectorName()
	switch connector {
	case "codex":
		if p.cfg.Guardrail.CodexEnforcementEnabled {
			return p.theme.High.Render("Codex proxy enforcement")
		}
		return p.theme.Medium.Render("Codex observe-only hooks")
	case "claudecode":
		if p.cfg.Guardrail.ClaudeCodeEnforcementEnabled {
			return p.theme.High.Render("Claude Code proxy enforcement")
		}
		return p.theme.Medium.Render("Claude Code observe-only hooks")
	case "zeptoclaw":
		return p.theme.High.Render("ZeptoClaw proxy-gated")
	case "openclaw":
		return p.theme.High.Render("OpenClaw proxy enforcement")
	case "hermes", "cursor", "windsurf", "geminicli", "copilot":
		return p.theme.Medium.Render(FriendlyConnectorName(connector) + " observe-only hooks")
	default:
		return p.theme.Medium.Render(FriendlyConnectorName(connector) + " connector")
	}
}

func (p *OverviewPanel) hiltSupportText() string {
	if p.cfg == nil || !p.cfg.Guardrail.HILT.Enabled {
		return p.theme.Dimmed.Render("disabled")
	}

	var label string
	switch p.activeConnectorName() {
	case "openclaw":
		label = "supported: brokered approval"
	case "claudecode":
		label = "supported: PreToolUse ask"
	case "copilot":
		label = "supported: preToolUse ask"
	case "cursor":
		label = "partial: documented ask events"
	case "codex", "zeptoclaw":
		label = "no native ask: alert fallback"
	case "hermes", "windsurf", "geminicli":
		label = "no native ask: alert fallback"
	default:
		label = "unknown connector support"
	}

	if !strings.EqualFold(strings.TrimSpace(p.cfg.Guardrail.Mode), "action") {
		label += " (inactive)"
	}
	if strings.HasPrefix(label, "supported:") {
		return p.theme.Clean.Render(label)
	}
	return p.theme.Medium.Render(label)
}

func (p *OverviewPanel) activeConnectorName() string {
	if p.cfg == nil {
		return "openclaw"
	}
	if name := strings.ToLower(strings.TrimSpace(p.cfg.Guardrail.Connector)); name != "" {
		return name
	}
	if mode := strings.ToLower(strings.TrimSpace(string(p.cfg.Claw.Mode))); mode != "" {
		return mode
	}
	return "openclaw"
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

	// Reconcile the cached doctor numbers against the live /health
	// snapshot. When the cache is older than the world (the user
	// brought the sidecar back up since the last `defenseclaw doctor`
	// run) we don't want a red "3 fail" claiming the sidecar is down
	// while the SERVICES box right next to it shows it RUNNING. We
	// reclassify those rows as STALE and subtract them from the fail
	// count so the summary tells the truth.
	_, contradicted := partitionDoctorChecks(p.doctor.Checks, p.health)
	contradictedFails := 0
	contradictedWarns := 0
	for _, ck := range contradicted {
		switch ck.Status {
		case "fail":
			contradictedFails++
		case "warn":
			contradictedWarns++
		}
	}
	effectiveFailed := p.doctor.Failed - contradictedFails
	if effectiveFailed < 0 {
		effectiveFailed = 0
	}
	effectiveWarned := p.doctor.Warned - contradictedWarns
	if effectiveWarned < 0 {
		effectiveWarned = 0
	}

	// Summary line with colored counts so the eye can triage at
	// a glance. Keep units plain-text to avoid relying on emoji
	// or icons that don't render uniformly across terminals.
	var parts []string
	if p.doctor.Passed > 0 {
		parts = append(parts, ok.Render(fmt.Sprintf("%d pass", p.doctor.Passed)))
	}
	if effectiveFailed > 0 {
		parts = append(parts, crit.Render(fmt.Sprintf("%d fail", effectiveFailed)))
	}
	if effectiveWarned > 0 {
		parts = append(parts, warn.Render(fmt.Sprintf("%d warn", effectiveWarned)))
	}
	staleCount := contradictedFails + contradictedWarns
	if staleCount > 0 {
		parts = append(parts, dim.Render(fmt.Sprintf("%d stale", staleCount)))
	}
	if p.doctor.Skipped > 0 {
		parts = append(parts, dim.Render(fmt.Sprintf("%d skip", p.doctor.Skipped)))
	}
	summary := strings.Join(parts, "  ")

	age := FormatAge(p.doctor.Age())
	staleSuffix := ""
	if p.doctor.IsStale() {
		staleSuffix = warn.Render(" (stale — [d] to rerun)")
	} else if staleCount > 0 {
		// Cache is fresh enough by clock standards but live /health
		// disagrees with it — the sidecar likely came back up since
		// the last probe. Tell the user explicitly so they don't
		// chase a phantom failure.
		staleSuffix = dim.Render(" (live state recovered — [d] to refresh)")
	}
	fmt.Fprintf(&content, " %s %s%s\n", summary, dim.Render("· "+age), staleSuffix)

	// Show the top 3 fail/warn checks inline so the overview
	// answers "what's broken?" without a panel switch.
	top := p.doctor.TopFailures(3)
	if len(top) > 0 {
		content.WriteString(" " + dim.Render("─────────────────────────") + "\n")
		for _, ck := range top {
			var badge string
			isStale := liveHealthContradicts(ck, p.health)
			switch {
			case isStale:
				// Don't paint contradicted rows red — that was
				// the regression. Render them dim with a STALE
				// badge so the user can still see what doctor
				// thinks but knows /health disagrees.
				badge = dim.Render("[STALE]")
			case ck.Status == "fail":
				badge = crit.Render("[FAIL]")
			case ck.Status == "warn":
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
				detailText := ck.Detail
				if isStale {
					detailText += " (live state OK)"
				}
				detail = dim.Render("  " + truncate(detailText, budget))
			}
			rowLabel := label
			if isStale {
				rowLabel = dim.Render(label)
			}
			fmt.Fprintf(&content, " %s %s%s\n", badge, rowLabel, detail)
		}
	} else {
		content.WriteString(" " + ok.Render("all green") + dim.Render(" — safe to proceed") + "\n")
	}

	return box.Render(content.String())
}

// maxAIDiscoveryRows caps the DISCOVERED AI AGENTS table at this
// many rows so a developer box with dozens of detected tools
// doesn't push the quick-actions bar off-screen. The full list
// remains accessible via `defenseclaw agent discover` and the
// Inventory panel ([i]); the Overview row is a smoke signal, not
// a report viewer.
const maxAIDiscoveryRows = 8

// renderAIDiscoveryBox paints the Overview's "DISCOVERED AI
// AGENTS" panel — the snapshot of AI tools/CLIs/IDE extensions
// the sidecar's continuous discovery service has fingerprinted.
// Behaviour:
//
//   - If aiUsage is nil (first paint, or sidecar unreachable),
//     show a one-line offline placeholder.
//   - If aiUsage.Enabled is false (config has ai_discovery.enabled
//     false), show an enable hint pointing at the canonical CLI.
//   - Otherwise, render a header summary line ("3 active, 1 new,
//     scanned 12s ago") followed by up to maxAIDiscoveryRows
//     signals, sorted with new-then-changed first so the
//     just-discovered agents are on top, and overflow truncated
//     to a "(+N more — defenseclaw agent discover)" tail.
//
// Width is the inner content width (already minus the box border
// + padding); we let lipgloss wrap if it overflows but try not to
// rely on that — long vendor names are truncated explicitly.
func (p *OverviewPanel) renderAIDiscoveryBox(w int) string {
	box := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("62")).
		Padding(0, 1).
		Width(w)

	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("62")).
		Render("DISCOVERED AI AGENTS")
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))

	var content strings.Builder
	content.WriteString(title + "\n")

	// Offline placeholder. We don't know whether the user has just
	// not booted the sidecar yet or the discovery service errored
	// — point them at the same place either way (`agent discovery
	// status` is the diagnostic command of choice).
	if p.aiUsage == nil {
		content.WriteString(" " + dim.Render(
			"ai discovery offline — run: defenseclaw agent discovery status",
		) + "\n")
		return box.Render(content.String())
	}

	// Disabled. The CLI command is the canonical enable path; the
	// TUI offers it via the command palette (Ctrl-K → "agent
	// discovery enable") but the breadcrumb here is plain text so
	// it works in any terminal without keybinding hints.
	if !p.aiUsage.Enabled {
		content.WriteString(" " + dim.Render(
			"disabled — run: defenseclaw agent discovery enable",
		) + "\n")
		return box.Render(content.String())
	}

	// Header summary line. We surface counts that map 1:1 to the
	// fields the sidecar publishes on /health → ai_discovery.details
	// so the SERVICES row's "3 active, 1 new" is identical to the
	// summary printed below the title here. Operators frequently
	// cross-reference the two when debugging "why does my new
	// agent not show up?".
	summary := p.aiUsage.Summary
	parts := []string{
		fmt.Sprintf("%d active", summary.ActiveSignals),
	}
	if summary.NewSignals > 0 {
		parts = append(parts, p.theme.Clean.Render(fmt.Sprintf("%d new", summary.NewSignals)))
	}
	if summary.ChangedSignals > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", summary.ChangedSignals))
	}
	if summary.GoneSignals > 0 {
		parts = append(parts, fmt.Sprintf("%d gone", summary.GoneSignals))
	}
	freshness := ""
	if !summary.ScannedAt.IsZero() {
		freshness = " " + dim.Render("scanned "+formatScanAge(summary.ScannedAt))
	}
	mode := ""
	if summary.PrivacyMode != "" {
		mode = " " + dim.Render("mode "+summary.PrivacyMode)
	}
	fmt.Fprintf(&content, " %s%s%s\n", strings.Join(parts, ", "), freshness, mode)

	if len(p.aiUsage.Signals) == 0 {
		content.WriteString(" " + dim.Render(
			"no AI agents detected yet — try: defenseclaw agent discover",
		) + "\n")
		return box.Render(content.String())
	}

	rows := p.aiUsageSorted
	if rows == nil {
		// Defensive fallback when SetAIUsage was not called (legacy
		// callers / tests that mutate p.aiUsage directly).
		rows = sortAIDiscoverySignalsForOverview(p.aiUsage.Signals)
	}
	limit := maxAIDiscoveryRows
	overflow := 0
	if len(rows) > limit {
		overflow = len(rows) - limit
		rows = rows[:limit]
	}

	for _, sig := range rows {
		stateBadge := renderAIDiscoveryStateBadge(p.theme, sig.State)
		name := truncate(displayAIDiscoveryName(sig), 22)
		vendor := truncate(displayAIDiscoveryVendor(sig), 18)
		conf := fmt.Sprintf("%3d%%", clampPercent(sig.Confidence*100))
		seen := dim.Render("seen " + formatScanAge(sig.LastSeen))
		fmt.Fprintf(&content, " %s %-22s %s %s %s\n",
			stateBadge,
			name,
			dim.Render(fmt.Sprintf("%-18s", vendor)),
			dim.Render(conf),
			seen,
		)
	}
	if overflow > 0 {
		fmt.Fprintf(&content, " %s\n", dim.Render(fmt.Sprintf(
			"… +%d more — defenseclaw agent discover",
			overflow,
		)))
	}

	return box.Render(content.String())
}

// renderAIDiscoveryStateBadge renders the colored "[NEW]"/"[CHG]"/
// "[OK ]"/"[GONE]" prefix for a signal row. Kept short and
// fixed-width so the table aligns regardless of which states
// appear. Defaults to a dimmed "[OK ]" for unrecognised states
// rather than blanking — if the sidecar adds a new state value
// we'd rather show *something* than silently drop the row.
func renderAIDiscoveryStateBadge(theme *Theme, state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "new":
		return theme.Clean.Render("[NEW]")
	case "changed":
		return theme.Medium.Render("[CHG]")
	case "gone":
		return theme.Dimmed.Render("[GONE]")
	default:
		// "active" / "" / unknown — render as plain so the eye is
		// drawn to the new/changed rows on top.
		dim := lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
		return dim.Render("[OK ]")
	}
}

// displayAIDiscoveryName picks the most useful identifier for the
// signal row: prefer the human Name from the signature catalog,
// fall back to Product, then SignatureID, then SignalID. Empty
// names render as "(unknown)" so a malformed signature doesn't
// produce a blank row that looks like a render bug.
func displayAIDiscoveryName(sig AIUsageSignal) string {
	for _, candidate := range []string{sig.Name, sig.Product, sig.SignatureID, sig.SignalID} {
		if v := strings.TrimSpace(candidate); v != "" {
			return v
		}
	}
	return "(unknown)"
}

// displayAIDiscoveryVendor renders the Vendor cell, with a couple
// of contextual annotations folded in: the SupportedConnector hint
// when present (so an operator can see at a glance that the
// detected agent has a first-party connector), and the version
// suffix when known.
func displayAIDiscoveryVendor(sig AIUsageSignal) string {
	var b strings.Builder
	vendor := strings.TrimSpace(sig.Vendor)
	if vendor == "" {
		vendor = strings.TrimSpace(sig.Category)
	}
	if vendor == "" {
		vendor = "—"
	}
	b.WriteString(vendor)
	if v := strings.TrimSpace(sig.Version); v != "" {
		b.WriteString(" ")
		b.WriteString(v)
	}
	if c := strings.TrimSpace(sig.SupportedConnector); c != "" {
		b.WriteString(" (")
		b.WriteString(c)
		b.WriteString(")")
	}
	return b.String()
}

// sortAIDiscoverySignalsForOverview returns a copy of the input
// sorted with new/changed signals first (so they're never pushed
// off the end of the truncated list), then by descending
// confidence, then by last-seen recency, then by name for
// determinism. Returning a copy avoids mutating the model's
// snapshot — multiple panels may end up reading p.aiUsage.Signals
// in the future and we don't want this renderer to surprise them.
func sortAIDiscoverySignalsForOverview(in []AIUsageSignal) []AIUsageSignal {
	if len(in) == 0 {
		return nil
	}
	out := make([]AIUsageSignal, len(in))
	copy(out, in)

	stateRank := func(state string) int {
		switch strings.ToLower(strings.TrimSpace(state)) {
		case "new":
			return 0
		case "changed":
			return 1
		case "active", "":
			return 2
		case "gone":
			return 3
		default:
			return 4
		}
	}

	sortAIUsageSignals(out, func(a, b AIUsageSignal) bool {
		ra, rb := stateRank(a.State), stateRank(b.State)
		if ra != rb {
			return ra < rb
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return strings.ToLower(displayAIDiscoveryName(a)) < strings.ToLower(displayAIDiscoveryName(b))
	})
	return out
}

// sortAIUsageSignals is a tiny insertion-sort that avoids pulling
// in sort.Slice for a slice this small (typical n is 1..20). It's
// stable enough for the deterministic tiebreaker chain above.
func sortAIUsageSignals(in []AIUsageSignal, less func(a, b AIUsageSignal) bool) {
	for i := 1; i < len(in); i++ {
		j := i
		for j > 0 && less(in[j], in[j-1]) {
			in[j-1], in[j] = in[j], in[j-1]
			j--
		}
	}
}

// formatScanAge renders a scan/last-seen timestamp as a compact
// "12s ago" / "3m ago" / "2h ago" string. The Overview panel uses
// this both for the summary line ("scanned 12s ago") and for each
// signal row ("seen 3m ago"). Returns "—" for the zero value so
// rows from a freshly-imported state file don't render as a
// nonsensical "55 years ago".
func formatScanAge(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	if d < 0 {
		// Future timestamp (clock skew between sidecar and TUI).
		// Don't render a negative; just say "now".
		return "now"
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours())/24)
	}
}

// clampPercent rounds a 0..100-ish float into a plain int and
// clamps to [0,100]. Defensive: the wire format documents 0..1
// for confidence but we'd rather render a sane "100%" than a
// broken "143%" if a future sidecar surfaces an out-of-range
// value.
func clampPercent(v float64) int {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return int(v + 0.5)
}

func (p *OverviewPanel) renderQuickActions(width int) string {
	actionStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("238")).
		Padding(0, 1).
		Width(width - 4)

	key := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("62"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	dangerKey := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	dangerText := lipgloss.NewStyle().Foreground(lipgloss.Color("203"))

	actions := []string{
		key.Render("[s]") + dim.Render(" Scan all"),
		key.Render("[d]") + dim.Render(" Doctor"),
		key.Render("[i]") + dim.Render(" Inventory"),
		key.Render("[g]") + dim.Render(" Guardrail"),
		key.Render("[m]") + dim.Render(" Mode"),
		key.Render("[p]") + dim.Render(" Policy"),
		key.Render("[l]") + dim.Render(" Logs"),
		key.Render("[R]") + dim.Render(" Redaction"),
		key.Render("[u]") + dim.Render(" Upgrade"),
		dangerKey.Render("[X]") + dangerText.Render(" Uninstall"),
		key.Render("[?]") + dim.Render(" Help"),
	}

	return actionStyle.Render("  " + strings.Join(actions, "    "))
}

// quickActionDefs defines the overview quick actions in display order.
// Each entry is (key-char, label-plaintext-width-including-brackets-and-space).
//
// The width column has to match the rendered "[x] Label" string
// exactly because QuickActionHitTest walks left-to-right summing
// these widths to map a click x-coordinate back to a key. If you
// change the label, recount the width.
var quickActionDefs = []struct {
	key   string
	width int // len("[x] Label")
}{
	{"s", 12}, // "[s] Scan all"
	{"d", 10}, // "[d] Doctor"
	{"i", 13}, // "[i] Inventory"
	{"g", 13}, // "[g] Guardrail"
	{"m", 8},  // "[m] Mode"
	{"p", 10}, // "[p] Policy"
	{"l", 8},  // "[l] Logs"
	{"R", 13}, // "[R] Redaction"
	{"u", 11}, // "[u] Upgrade"
	{"X", 13}, // "[X] Uninstall"
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
	case "agent":
		// Live connector reported by the sidecar's /health → connector
		// block. When the sidecar has not yet initialised a connector
		// (guardrail disabled, proxy not booted) we still want the
		// row to render — fall back to the configured mode in
		// agentDetail() and signal "unknown" here so the dot is
		// neutral rather than green.
		if h.Connector != nil {
			if h.Connector.State == "" {
				return "unknown"
			}
			return h.Connector.State
		}
		return "unknown"
	case "watcher":
		return h.Watcher.State
	case "guardrail":
		return h.Guardrail.State
	case "sinks":
		return h.Sinks.State
	case "telemetry":
		return h.Telemetry.State
	case "ai_discovery":
		return h.AIDiscovery.State
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
	case "ai_discovery":
		return &h.AIDiscovery
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
	// In standalone mode (no OpenClaw fleet) we replace the uptime
	// counter with the human-readable summary the sidecar publishes
	// in health.Gateway.Details. Showing "up 4m23s" alongside
	// state=disabled was confusing — operators read it as "the
	// gateway is up but the sidecar thinks it's disabled, something
	// is wrong" when the truth is "the dial loop never started by
	// design". The summary string is set in
	// runGatewayLoop's standalone branch.
	if strings.EqualFold(p.health.Gateway.State, "disabled") {
		if s := stringDetail(p.health.Gateway.Details, "summary"); s != "" {
			return s
		}
	}
	uptime := time.Duration(p.health.UptimeMS) * time.Millisecond
	if uptime > 0 {
		return fmt.Sprintf("up %s", formatDuration(uptime))
	}
	return ""
}

// gatewayStandaloneHint returns a short user-facing breadcrumb shown
// when the gateway is in StateDisabled. Pulls from health.Gateway.Details
// so the message is consistent with whatever the sidecar emitted in
// runGatewayLoop's short-circuit (e.g. "telemetry continues via
// hooks + local audit; point gateway.host at a real OpenClaw upstream
// and restart to enable fleet integration"). Returning "" suppresses
// the notice entirely — used when the snapshot is missing or the
// sidecar didn't supply a hint, since a bare "Gateway: disabled"
// row in the SERVICES box already conveys the state.
func (p *OverviewPanel) gatewayStandaloneHint() string {
	if p.health == nil {
		return ""
	}
	if hint := stringDetail(p.health.Gateway.Details, "hint"); hint != "" {
		return hint
	}
	return stringDetail(p.health.Gateway.Details, "summary")
}

// gatewayHealthIsBroken returns true for states that imply the sidecar
// tried to bring up the gateway and failed — `error`, `reconnecting`,
// `stopped`, `unknown`, etc. Returns false for `running` (healthy) and
// `disabled` (intentional standalone). The split exists so the TUI's
// red "Gateway is offline" notice fires only when something is
// actually broken, not when a hook connector is correctly running
// without an OpenClaw fleet. Mirrors the health classification used
// by `defenseclaw doctor` so the two surfaces don't disagree.
func gatewayHealthIsBroken(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "running", "disabled":
		return false
	default:
		return true
	}
}

// stringDetail safely extracts a string field from a SubsystemHealth.Details
// map. Returns "" on any type mismatch / missing key. Used by the
// standalone-hint helpers above so a malformed health snapshot can't
// panic the TUI.
func stringDetail(details map[string]interface{}, key string) string {
	if details == nil {
		return ""
	}
	if v, ok := details[key]; ok {
		if s, ok := v.(string); ok {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// agentDetail renders the CONNECTED-AGENT row detail in the SERVICES
// box: a friendly connector name plus a compact tool-inspection /
// request-count summary. When the sidecar hasn't initialised a
// connector yet we fall back to the *configured* mode and append
// "(configured, not connected)" so operators know the row reflects
// intent, not live state.
func (p *OverviewPanel) agentDetail() string {
	configuredMode := ""
	if p.cfg != nil {
		configuredMode = string(p.cfg.Claw.Mode)
	}

	if p.health == nil || p.health.Connector == nil {
		if configuredMode == "" {
			return ""
		}
		return FriendlyConnectorName(configuredMode) + " (configured, not connected)"
	}

	c := p.health.Connector
	parts := []string{FriendlyConnectorName(c.Name)}
	if c.ToolInspectionMode != "" {
		parts = append(parts, c.ToolInspectionMode)
	}
	if c.Requests > 0 {
		parts = append(parts, fmt.Sprintf("%d req", c.Requests))
	}
	if c.ToolBlocks > 0 {
		parts = append(parts, fmt.Sprintf("%d tool blocks", c.ToolBlocks))
	}
	if c.SubprocessBlocks > 0 {
		parts = append(parts, fmt.Sprintf("%d subprocess blocks", c.SubprocessBlocks))
	}
	return strings.Join(parts, " · ")
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

func (p *OverviewPanel) aiDiscoveryDetail() string {
	if p.health == nil || p.health.AIDiscovery.Details == nil {
		return ""
	}
	d := p.health.AIDiscovery.Details
	parts := []string{}
	if active, ok := d["active_signals"]; ok {
		parts = append(parts, fmt.Sprintf("%v active", active))
	}
	if newSignals, ok := d["new_signals"]; ok {
		parts = append(parts, fmt.Sprintf("%v new", newSignals))
	}
	if mode, ok := d["mode"]; ok {
		parts = append(parts, fmt.Sprintf("%v", mode))
	}
	return strings.Join(parts, ", ")
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
