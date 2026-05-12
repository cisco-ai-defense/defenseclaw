// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func TestOverview_ConfigurationBox_RedactionStatus(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(false)

	p := newOverviewForTest()
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "Redaction") {
		t.Fatalf("expected Overview configuration to include Redaction row, got:\n%s", out)
	}
	if !strings.Contains(out, "ON (redacted)") {
		t.Fatalf("expected default redacted state in Overview, got:\n%s", out)
	}

	p.cfg.Privacy.DisableRedaction = true
	out = stripANSI(p.View(120, 40))
	if !strings.Contains(out, "OFF (RAW)") {
		t.Fatalf("expected raw state from config in Overview, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_RedactionStatusHonorsRuntimeOverride(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	p := newOverviewForTest()
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "OFF (RAW)") {
		t.Fatalf("expected raw state from runtime override in Overview, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_RedactionStatusWithoutConfig(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(false)

	p := NewOverviewPanel(DefaultTheme(), nil, "test")
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "Redaction") {
		t.Fatalf("expected Overview to show Redaction row even without config, got:\n%s", out)
	}
	if !strings.Contains(out, "ON (redacted)") {
		t.Fatalf("expected default redacted state without config, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_HILTStatus(t *testing.T) {
	p := newOverviewForTest()
	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "Human approval") {
		t.Fatalf("expected Overview configuration to include Human approval row, got:\n%s", out)
	}
	if !strings.Contains(out, "OFF") {
		t.Fatalf("expected default HILT off state in Overview, got:\n%s", out)
	}

	p.cfg.Guardrail.Mode = "action"
	p.cfg.Guardrail.HILT.Enabled = true
	p.cfg.Guardrail.HILT.MinSeverity = "HIGH"
	out = stripANSI(p.View(120, 40))
	if !strings.Contains(out, "ON HIGH (CRIT blocks)") {
		t.Fatalf("expected enabled HILT severity in Overview, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_HILTObserveInactive(t *testing.T) {
	p := newOverviewForTest()
	p.cfg.Guardrail.Mode = "observe"
	p.cfg.Guardrail.HILT.Enabled = true
	p.cfg.Guardrail.HILT.MinSeverity = "MEDIUM"

	out := stripANSI(p.View(120, 40))
	if !strings.Contains(out, "ON MEDIUM+ (inactive)") {
		t.Fatalf("expected HILT observe-mode inactive state in Overview, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_PolicyPostureAndEnforcement(t *testing.T) {
	p := newOverviewForTest()
	p.cfg.Guardrail.Enabled = true
	p.cfg.Guardrail.Mode = "action"
	p.cfg.Guardrail.RulePackDir = "/tmp/policies/guardrail/default"
	p.cfg.Guardrail.Connector = "codex"

	out := stripANSI(p.View(132, 44))
	for _, want := range []string{
		"Policy posture",
		"balanced: block CRIT, alert MED+",
		"Enforcement",
		"Codex observe-only hooks",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected Overview configuration to include %q, got:\n%s", want, out)
		}
	}

	p.cfg.Guardrail.CodexEnforcementEnabled = true
	out = stripANSI(p.View(132, 44))
	if !strings.Contains(out, "Codex proxy enforcement") {
		t.Fatalf("expected enabled Codex enforcement state in Overview, got:\n%s", out)
	}
}

func TestOverview_ConfigurationBox_HILTSupportByConnector(t *testing.T) {
	p := newOverviewForTest()
	p.cfg.Guardrail.Enabled = true
	p.cfg.Guardrail.Mode = "action"
	p.cfg.Guardrail.HILT.Enabled = true
	p.cfg.Guardrail.HILT.MinSeverity = "HIGH"
	p.cfg.Guardrail.Connector = "claudecode"

	out := stripANSI(p.View(132, 44))
	if !strings.Contains(out, "Approval support") || !strings.Contains(out, "supported: PreToolUse ask") {
		t.Fatalf("expected Claude Code HILT support in Overview, got:\n%s", out)
	}

	p.cfg.Guardrail.Connector = "zeptoclaw"
	out = stripANSI(p.View(132, 44))
	if !strings.Contains(out, "no native ask: alert fallback") {
		t.Fatalf("expected ZeptoClaw non-native HILT support in Overview, got:\n%s", out)
	}

	p.cfg.Guardrail.Connector = "cursor"
	out = stripANSI(p.View(132, 44))
	if !strings.Contains(out, "partial: documented ask events") {
		t.Fatalf("expected Cursor event-scoped HILT support in Overview, got:\n%s", out)
	}

	p.cfg.Guardrail.Connector = "copilot"
	out = stripANSI(p.View(132, 44))
	if !strings.Contains(out, "supported: preToolUse ask") {
		t.Fatalf("expected Copilot native HILT support in Overview, got:\n%s", out)
	}

	p.cfg.Guardrail.Connector = "geminicli"
	out = stripANSI(p.View(132, 44))
	if !strings.Contains(out, "no native ask: alert fallback") {
		t.Fatalf("expected Gemini CLI fallback HILT support in Overview, got:\n%s", out)
	}
}
