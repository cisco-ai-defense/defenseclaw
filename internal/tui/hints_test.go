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
	"strings"
	"testing"
)

func TestHintEngine(t *testing.T) {
	engine := NewHintEngine()

	t.Run("overview_gateway_offline", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{GatewayRunning: false})
		if !strings.Contains(hint, "offline") && !strings.Contains(hint, "Gateway") {
			t.Errorf("expected gateway offline hint, got: %s", hint)
		}
	})

	t.Run("overview_guardrail_disabled", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: false,
		})
		if !strings.Contains(hint, "guardrail") && !strings.Contains(hint, "LLM") {
			t.Errorf("expected guardrail hint, got: %s", hint)
		}
	})

	t.Run("overview_critical_alerts", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: true,
			CriticalAlerts:   3,
		})
		if !strings.Contains(hint, "critical") && !strings.Contains(hint, "3") {
			t.Errorf("expected critical alert hint, got: %s", hint)
		}
	})

	t.Run("overview_unscanned_skills", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: true,
			UnscannedSkills:  5,
		})
		if !strings.Contains(hint, "scanned") || !strings.Contains(hint, "5") {
			t.Errorf("expected unscanned skills hint, got: %s", hint)
		}
	})

	t.Run("overview_all_healthy_returns_tip", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: true,
		})
		if hint == "" {
			t.Error("expected a rotating tip, got empty string")
		}
	})

	t.Run("alerts_no_alerts", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAlerts, SystemState{TotalAlerts: 0})
		if !strings.Contains(hint, "No active alerts") {
			t.Errorf("expected empty state hint, got: %s", hint)
		}
	})

	t.Run("alerts_critical", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAlerts, SystemState{TotalAlerts: 3, CriticalAlerts: 1})
		if !strings.Contains(hint, "critical") {
			t.Errorf("expected critical alert hint, got: %s", hint)
		}
	})

	t.Run("alerts_with_filter", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAlerts, SystemState{TotalAlerts: 5, FilterActive: "critical"})
		if !strings.Contains(hint, "critical") || !strings.Contains(hint, "Filtered") {
			t.Errorf("expected filter hint, got: %s", hint)
		}
	})

	t.Run("skills_unscanned", func(t *testing.T) {
		hint := engine.HintForPanel(PanelSkills, SystemState{UnscannedSkills: 4})
		if !strings.Contains(hint, "4") || !strings.Contains(hint, "unscanned") {
			t.Errorf("expected unscanned skills hint, got: %s", hint)
		}
	})

	t.Run("skills_normal", func(t *testing.T) {
		hint := engine.HintForPanel(PanelSkills, SystemState{})
		if !strings.Contains(hint, "navigate") {
			t.Errorf("expected navigation hint, got: %s", hint)
		}
	})

	t.Run("mcps_normal", func(t *testing.T) {
		hint := engine.HintForPanel(PanelMCPs, SystemState{})
		if hint == "" {
			t.Error("expected MCP hint, got empty string")
		}
	})

	t.Run("plugins_normal", func(t *testing.T) {
		hint := engine.HintForPanel(PanelPlugins, SystemState{})
		// Must surface the actions shortcut (PluginActions menu is
		// the whole point of P0-#2) and at least one verb so
		// operators know what `o` unlocks without reading the
		// source.
		if !strings.Contains(hint, "actions") || !strings.Contains(hint, "scan") {
			t.Errorf("expected plugins hint to advertise 'actions' shortcut and scan verb, got: %s", hint)
		}
	})

	t.Run("inventory_normal", func(t *testing.T) {
		hint := engine.HintForPanel(PanelInventory, SystemState{})
		if !strings.Contains(hint, "sub-tab") || !strings.Contains(hint, "refresh") {
			t.Errorf("expected inventory hint, got: %s", hint)
		}
	})

	t.Run("logs_streaming", func(t *testing.T) {
		hint := engine.HintForPanel(PanelLogs, SystemState{LogsPaused: false})
		if !strings.Contains(hint, "Streaming") || !strings.Contains(hint, "live") {
			t.Errorf("expected streaming hint, got: %s", hint)
		}
	})

	t.Run("logs_paused", func(t *testing.T) {
		hint := engine.HintForPanel(PanelLogs, SystemState{LogsPaused: true, NewLinesSince: 14})
		if !strings.Contains(hint, "Paused") || !strings.Contains(hint, "14") {
			t.Errorf("expected paused hint, got: %s", hint)
		}
	})

	t.Run("audit_empty", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAudit, SystemState{AuditCount: 0})
		if !strings.Contains(hint, "No audit events") {
			t.Errorf("expected empty audit hint, got: %s", hint)
		}
	})

	t.Run("audit_with_filter", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAudit, SystemState{AuditCount: 10, FilterActive: "blocks"})
		if !strings.Contains(hint, "blocks") {
			t.Errorf("expected filtered audit hint, got: %s", hint)
		}
	})

	t.Run("audit_normal", func(t *testing.T) {
		hint := engine.HintForPanel(PanelAudit, SystemState{AuditCount: 50})
		if !strings.Contains(hint, "history") || !strings.Contains(hint, "filter") {
			t.Errorf("expected audit hint with filter info, got: %s", hint)
		}
	})

	t.Run("activity_running", func(t *testing.T) {
		hint := engine.HintForPanel(PanelActivity, SystemState{CommandRunning: true})
		if !strings.Contains(hint, "running") || !strings.Contains(hint, "Ctrl+C") {
			t.Errorf("expected running command hint, got: %s", hint)
		}
	})

	t.Run("activity_empty", func(t *testing.T) {
		hint := engine.HintForPanel(PanelActivity, SystemState{CommandsRun: 0})
		if !strings.Contains(hint, "No commands") || !strings.Contains(hint, "palette") {
			t.Errorf("expected empty activity hint, got: %s", hint)
		}
	})

	t.Run("activity_with_history", func(t *testing.T) {
		hint := engine.HintForPanel(PanelActivity, SystemState{CommandsRun: 5})
		if !strings.Contains(hint, "5") {
			t.Errorf("expected command count in hint, got: %s", hint)
		}
	})

	t.Run("unknown_panel_returns_default", func(t *testing.T) {
		hint := engine.HintForPanel(99, SystemState{})
		if hint == "" {
			t.Error("expected a default hint for unknown panel")
		}
	})
}

func TestHintForPanelPriorityOrder(t *testing.T) {
	engine := NewHintEngine()

	t.Run("overview_priority_gateway_first", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   false,
			GuardrailEnabled: false,
			CriticalAlerts:   5,
		})
		if !strings.Contains(hint, "Gateway") || !strings.Contains(hint, "offline") {
			t.Errorf("gateway offline should take priority, got: %s", hint)
		}
	})

	t.Run("overview_priority_guardrail_before_critical", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: false,
			CriticalAlerts:   5,
		})
		if !strings.Contains(hint, "guardrail") {
			t.Errorf("guardrail should take priority over alerts, got: %s", hint)
		}
	})

	t.Run("overview_priority_critical_before_unscanned", func(t *testing.T) {
		hint := engine.HintForPanel(PanelOverview, SystemState{
			GatewayRunning:   true,
			GuardrailEnabled: true,
			CriticalAlerts:   2,
			UnscannedSkills:  10,
		})
		if !strings.Contains(hint, "critical") {
			t.Errorf("critical alerts should take priority over unscanned, got: %s", hint)
		}
	})
}

func TestRotatingTipsNotEmpty(t *testing.T) {
	if len(rotatingTips) == 0 {
		t.Fatal("rotatingTips should not be empty")
	}
	for i, tip := range rotatingTips {
		if tip == "" {
			t.Errorf("rotatingTips[%d] is empty", i)
		}
	}
}
