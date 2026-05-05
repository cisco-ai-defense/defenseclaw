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
	"time"
)

// HintEngine generates contextual tips based on current panel, selection,
// and system state.
type HintEngine struct {
	tipIndex int
	lastTick time.Time
}

// NewHintEngine creates a new hint engine.
func NewHintEngine() *HintEngine {
	return &HintEngine{lastTick: time.Now()}
}

// SystemState captures health/config info used to generate smart hints.
type SystemState struct {
	GatewayRunning   bool
	GuardrailEnabled bool
	GuardrailMode    string
	CriticalAlerts   int
	UnscannedSkills  int
	TotalAlerts      int
	CommandRunning   bool
	CommandsRun      int
	LogsPaused       bool
	NewLinesSince    int
	FilterActive     string
	AuditCount       int
}

var rotatingTips = []string{
	"Press Ctrl+K to open the command palette from anywhere. You can run any DefenseClaw command.",
	"The Audit panel (8) shows every action DefenseClaw has ever taken — blocks, scans, config changes.",
	"Use \"scan aibom\" to generate a full component inventory of the active connector.",
	"Skills with policy verdict \"warning\" are installed but have medium/low findings. Review in Skills (3).",
	"The guardrail proxy can run in \"observe\" mode to log LLM traffic without blocking. Try \"setup guardrail\".",
	"Press / on any list to filter. Works in Alerts, Skills, MCPs, Plugins, Logs, and Audit.",
	"Press ? for the full keybinding reference. Every shortcut is documented.",
	"The Logs panel (7) shows live gateway and watchdog logs — no separate terminal needed.",
}

// HintForPanel returns a contextual hint for the given panel and state.
func (h *HintEngine) HintForPanel(panel int, state SystemState) string {
	switch panel {
	case PanelOverview:
		return h.overviewHint(state)
	case PanelAlerts:
		return h.alertsHint(state)
	case PanelSkills:
		return h.skillsHint(state)
	case PanelMCPs:
		return h.mcpsHint(state)
	case PanelPlugins:
		return h.pluginsHint(state)
	case PanelInventory:
		return h.inventoryHint(state)
	case PanelLogs:
		return h.logsHint(state)
	case PanelAudit:
		return h.auditHint(state)
	case PanelActivity:
		return h.activityHint(state)
	case PanelTools:
		return h.toolsHint(state)
	default:
		return "Press : or Ctrl+K to open the command palette. Press ? for help."
	}
}

func (h *HintEngine) overviewHint(state SystemState) string {
	if !state.GatewayRunning {
		return "Gateway is offline. Press : then type \"start\" to launch it, or run \"doctor\" to diagnose."
	}
	if !state.GuardrailEnabled {
		return "LLM guardrail is not configured. Press \"g\" to set it up — it intercepts and scans LLM traffic."
	}
	if state.CriticalAlerts > 0 {
		return fmt.Sprintf("%d critical alert(s) need attention. Press 2 to jump to Alerts, or : then \"scan skill --all\".", state.CriticalAlerts)
	}
	if state.UnscannedSkills > 0 {
		return fmt.Sprintf("%d skills haven't been scanned. Press \"s\" to scan all, or go to Skills (3).", state.UnscannedSkills)
	}

	now := time.Now()
	if now.Sub(h.lastTick) > 10*time.Second {
		h.lastTick = now
		h.tipIndex = (h.tipIndex + 1) % len(rotatingTips)
	}
	return rotatingTips[h.tipIndex]
}

func (h *HintEngine) alertsHint(state SystemState) string {
	if state.TotalAlerts == 0 {
		return "No active alerts. DefenseClaw is monitoring — alerts appear when scans find issues."
	}
	if state.CriticalAlerts > 0 {
		return fmt.Sprintf("%d critical alert(s) at top. Press Enter for details, \"b\" to block the target immediately.", state.CriticalAlerts)
	}
	if state.FilterActive != "" {
		return fmt.Sprintf("Filtered to: %s. Press Esc to clear filter, or / to change.", state.FilterActive)
	}
	return "j/k navigate, Enter detail, 1-5 severity, Space select, \"x\" ack, \"c\" clear filtered, \"y\" copy."
}

func (h *HintEngine) skillsHint(state SystemState) string {
	if state.UnscannedSkills > 0 {
		return fmt.Sprintf("%d skills unscanned. Press \"s\" on a skill to scan, or : then \"scan skill --all\".", state.UnscannedSkills)
	}
	return "j/k nav · o actions (block/allow/disable/enable/quarantine/restore/install) · s scan · r refresh · Enter detail."
}

func (h *HintEngine) mcpsHint(_ SystemState) string {
	return "j/k nav · o actions (block/allow/unblock/unset) · s scan · n add server · r refresh · Enter detail."
}

func (h *HintEngine) pluginsHint(_ SystemState) string {
	return "j/k nav · o actions (scan/block/allow/disable/enable/quarantine/restore/remove) · s scan · r refresh · Enter details."
}

// toolsHint is the one-line guide at the bottom of the Tools panel.
// Keep it action-first: tools are a policy-mutation surface, so the
// hint tells operators what keys exist rather than what a tool is.
func (h *HintEngine) toolsHint(_ SystemState) string {
	return "j/k nav · o actions (block/allow/unblock) · r refresh · Enter detail · : tool block <name>."
}

func (h *HintEngine) inventoryHint(_ SystemState) string {
	return "Left/Right to switch sub-tabs (Skills, Plugins, MCPs, Agents, Models, Tools, Memory). \"r\" to refresh, \"o\" toggles fast scope (skills+plugins+mcp)."
}

func (h *HintEngine) logsHint(state SystemState) string {
	if state.LogsPaused {
		return fmt.Sprintf("Paused. Space to resume. New lines since pause: +%d. Press G to jump to end.", state.NewLinesSince)
	}
	return "Streaming live. Space to pause, / to search, \"e\" for errors only, \"w\" for warnings+."
}

func (h *HintEngine) auditHint(state SystemState) string {
	if state.AuditCount == 0 {
		return "No audit events yet. Events are recorded when you scan, block, allow, or configure DefenseClaw."
	}
	if state.FilterActive != "" {
		return fmt.Sprintf("Showing: %s. Press Esc to clear filter. Use /scan to switch to scans.", state.FilterActive)
	}
	return "Full action history. / to filter (e.g. /block, /scan, /critical). Enter for details. \"e\" to export."
}

func (h *HintEngine) activityHint(state SystemState) string {
	if state.CommandRunning {
		return "Command running. Press Ctrl+C to cancel. Output streams here in real-time."
	}
	if state.CommandsRun == 0 {
		return "No commands run yet. Press : or Ctrl+K to open the command palette. Try: \"doctor\", \"status\"."
	}
	return fmt.Sprintf("%d command(s) run this session. Press Enter to expand output. Press ! to re-run the last one.", state.CommandsRun)
}
