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

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGuardrailRuntimeActionBalanced(t *testing.T) {
	cfg := &config.Config{}
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "alert" {
		t.Fatalf("HIGH balanced action = %q, want alert", got)
	}
	if got := guardrailRuntimeAction(cfg, "CRITICAL", true); got != "block" {
		t.Fatalf("CRITICAL balanced action = %q, want block", got)
	}
}

func TestGuardrailRuntimeActionHILT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "confirm" {
		t.Fatalf("HIGH HILT confirmable action = %q, want confirm", got)
	}
	if got := guardrailRuntimeAction(cfg, "HIGH", false); got != "alert" {
		t.Fatalf("HIGH HILT unsupported action = %q, want alert", got)
	}
	if got := guardrailRuntimeAction(cfg, "CRITICAL", true); got != "block" {
		t.Fatalf("CRITICAL HILT action = %q, want block", got)
	}
}

func TestGuardrailRuntimeActionStrictBlocksBeforeHILT(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/tmp/policies/guardrail/strict"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	if got := guardrailRuntimeAction(cfg, "MEDIUM", true); got != "block" {
		t.Fatalf("MEDIUM strict action = %q, want block", got)
	}
	if got := guardrailRuntimeAction(cfg, "HIGH", true); got != "block" {
		t.Fatalf("HIGH strict action = %q, want block", got)
	}
}

// TestGuardrailRuntimeActionPerConnectorPosture pins the per-connector
// rule-pack posture: a connector with a permissive override must enforce
// the permissive threshold (CRITICAL-only) while a connector inheriting the
// global strict pack still blocks MEDIUM+. This is the multi-connector parity
// guarantee — the pack IS the posture, resolved per connector.
func TestGuardrailRuntimeActionPerConnectorPosture(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.RulePackDir = "/tmp/policies/guardrail/strict" // global = strict
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {RulePackDir: "/tmp/policies/guardrail/permissive"},
	}

	// codex has no override → inherits global strict → MEDIUM/HIGH block.
	if got := guardrailRuntimeActionForConnector(cfg, "codex", "MEDIUM", true); got != "block" {
		t.Fatalf("codex (strict) MEDIUM = %q, want block", got)
	}
	if got := guardrailRuntimeActionForConnector(cfg, "codex", "HIGH", true); got != "block" {
		t.Fatalf("codex (strict) HIGH = %q, want block", got)
	}

	// claudecode override → permissive → HIGH is alert (not block), but
	// CRITICAL still blocks.
	if got := guardrailRuntimeActionForConnector(cfg, "claudecode", "HIGH", true); got != "alert" {
		t.Fatalf("claudecode (permissive) HIGH = %q, want alert", got)
	}
	if got := guardrailRuntimeActionForConnector(cfg, "claudecode", "MEDIUM", true); got != "allow" {
		t.Fatalf("claudecode (permissive) MEDIUM = %q, want allow", got)
	}
	if got := guardrailRuntimeActionForConnector(cfg, "claudecode", "CRITICAL", true); got != "block" {
		t.Fatalf("claudecode (permissive) CRITICAL = %q, want block", got)
	}

	// Empty connector resolves to the global pack (single-connector parity).
	if got := guardrailRuntimeActionForConnector(cfg, "", "MEDIUM", true); got != "block" {
		t.Fatalf("empty connector MEDIUM = %q, want block (global strict)", got)
	}
}

// TestResolveHookBlockReason pins the block-message wiring: a configured
// block message (per-connector override → global) replaces the user-facing
// reason on block verdicts only, while non-block actions, the no-config case,
// and the no-message case pass the original verdict reason through unchanged.
func TestResolveHookBlockReason(t *testing.T) {
	gc := &config.GuardrailConfig{BlockMessage: "global msg"}
	gc.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex": {BlockMessage: "codex msg"},
	}

	cases := []struct {
		name      string
		gc        *config.GuardrailConfig
		connector string
		action    string
		reason    string
		want      string
	}{
		{"per-connector override on block", gc, "codex", "block", "rule X matched", "codex msg"},
		{"global block message when no override", gc, "claudecode", "block", "rule Y matched", "global msg"},
		{"empty connector uses global", gc, "", "block", "rule Z", "global msg"},
		{"non-block action keeps verdict reason", gc, "codex", "confirm", "needs approval", "needs approval"},
		{"alert keeps verdict reason", gc, "codex", "alert", "flagged", "flagged"},
		{"nil config passes reason through", nil, "codex", "block", "rule X", "rule X"},
		{
			"no configured message keeps verdict reason",
			&config.GuardrailConfig{}, "codex", "block", "rule X", "rule X",
		},
	}
	for _, tc := range cases {
		if got := resolveHookBlockReason(tc.gc, tc.connector, tc.action, tc.reason); got != tc.want {
			t.Errorf("%s: resolveHookBlockReason(%q,%q,%q)=%q want %q",
				tc.name, tc.connector, tc.action, tc.reason, got, tc.want)
		}
	}
}

// TestGuardrailRuntimeActionPerConnectorHILT pins per-connector
// human-in-the-loop resolution: a connector's hilt override
// (guardrail.connectors[X].hilt) must take precedence over the global HILT
// block at decision time, while connectors without an override and the
// empty (single-connector) path keep using the global HILT. Guards the
// EffectiveHILT(connector) wiring in hiltEnabled/hiltMinRank.
func TestGuardrailRuntimeActionPerConnectorHILT(t *testing.T) {
	cfg := &config.Config{}
	// Global HILT: ON, confirm at HIGH+. (Balanced pack: alert=HIGH, block=CRITICAL.)
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"

	hiltOff := config.HILTConfig{Enabled: false}
	hiltMedium := config.HILTConfig{Enabled: true, MinSeverity: "MEDIUM"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"codex":       {HILT: &hiltOff},    // override: HILT disabled
		"antigravity": {HILT: &hiltMedium}, // override: confirm at MEDIUM+
	}

	// claudecode has no hilt override → inherits global ON@HIGH.
	if got := guardrailRuntimeActionForConnector(cfg, "claudecode", "HIGH", true); got != "confirm" {
		t.Fatalf("claudecode (inherit HILT) HIGH = %q, want confirm", got)
	}
	// Global min is HIGH, so MEDIUM stays below the confirm threshold and
	// falls through to the balanced pack's alert tier (NOT confirm).
	if got := guardrailRuntimeActionForConnector(cfg, "claudecode", "MEDIUM", true); got != "alert" {
		t.Fatalf("claudecode (inherit HILT) MEDIUM = %q, want alert", got)
	}

	// codex override disables HILT → HIGH confirmable falls through to alert.
	if got := guardrailRuntimeActionForConnector(cfg, "codex", "HIGH", true); got != "alert" {
		t.Fatalf("codex (HILT off) HIGH = %q, want alert", got)
	}
	// HILT off must NOT disable hard blocks: CRITICAL still blocks.
	if got := guardrailRuntimeActionForConnector(cfg, "codex", "CRITICAL", true); got != "block" {
		t.Fatalf("codex (HILT off) CRITICAL = %q, want block", got)
	}

	// antigravity override lowers the confirm threshold to MEDIUM.
	if got := guardrailRuntimeActionForConnector(cfg, "antigravity", "MEDIUM", true); got != "confirm" {
		t.Fatalf("antigravity (HILT@MEDIUM) MEDIUM = %q, want confirm", got)
	}

	// Empty connector resolves to the global HILT (single-connector parity).
	if got := guardrailRuntimeActionForConnector(cfg, "", "HIGH", true); got != "confirm" {
		t.Fatalf("empty connector HIGH = %q, want confirm (global HILT)", got)
	}
}

// TestClampPromptDirectionAction locks in the prompt-surface UX contract at
// the lowest level: the pure helper that every other clamp callsite
// composes with. The contract has three rules:
//
//  1. Prompt direction + (block|confirm)         → alert + demoted=true
//  2. Prompt direction + anything else (or empty) → unchanged + demoted=false
//  3. Non-prompt direction                       → unchanged + demoted=false
//
// Direction matching is case-insensitive and ignores surrounding whitespace
// so callers don't have to normalize before invoking the helper.
func TestClampPromptDirectionAction(t *testing.T) {
	tests := []struct {
		name        string
		direction   string
		action      string
		wantAction  string
		wantDemoted bool
	}{
		{"prompt block demoted", "prompt", guardrailActionBlock, guardrailActionAlert, true},
		{"prompt confirm demoted", "prompt", guardrailActionConfirm, guardrailActionAlert, true},
		{"prompt alert untouched", "prompt", guardrailActionAlert, guardrailActionAlert, false},
		{"prompt allow untouched", "prompt", guardrailActionAllow, guardrailActionAllow, false},
		{"prompt empty untouched", "prompt", "", "", false},
		{"completion block preserved", "completion", guardrailActionBlock, guardrailActionBlock, false},
		{"completion confirm preserved", "completion", guardrailActionConfirm, guardrailActionConfirm, false},
		{"tool-call block preserved", "tool-call", guardrailActionBlock, guardrailActionBlock, false},
		{"empty direction preserved", "", guardrailActionBlock, guardrailActionBlock, false},
		{"PROMPT uppercase still clamped", "PROMPT", guardrailActionBlock, guardrailActionAlert, true},
		{"prompt with whitespace still clamped", "  prompt  ", guardrailActionConfirm, guardrailActionAlert, true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotAction, gotDemoted := clampPromptDirectionAction(tc.direction, tc.action)
			if gotAction != tc.wantAction {
				t.Errorf("action = %q, want %q", gotAction, tc.wantAction)
			}
			if gotDemoted != tc.wantDemoted {
				t.Errorf("demoted = %v, want %v", gotDemoted, tc.wantDemoted)
			}
		})
	}
}

// TestClampPromptDirectionVerdict verifies the ScanVerdict wrapper enforces
// the two-tier prompt-surface contract:
//
//   - HIGH and below: block/confirm demoted to alert with audit marker
//   - CRITICAL: untouched (operators expect categorical rejection)
//   - non-prompt directions: untouched at any severity
//
// Demotions also preserve Severity, Findings, and the original Reason so
// canonical event readers can search for the original (more aggressive) policy
// decision via the "policy-action=<original>" marker.
func TestClampPromptDirectionVerdict(t *testing.T) {
	t.Run("nil verdict is a no-op", func(t *testing.T) {
		// The chokepoint may receive a nil verdict from a scanner
		// that legitimately found nothing — must not panic.
		clampPromptDirectionVerdict(nil, "prompt")
	})

	t.Run("prompt high block demoted with audit marker", func(t *testing.T) {
		v := &ScanVerdict{
			Action:   guardrailActionBlock,
			Severity: "HIGH",
			Reason:   "matched: CMD-NETCAT-LISTEN:Netcat listener",
			Findings: []string{"CMD-NETCAT-LISTEN"},
		}
		clampPromptDirectionVerdict(v, "prompt")
		if v.Action != guardrailActionAlert {
			t.Errorf("Action = %q, want %q", v.Action, guardrailActionAlert)
		}
		if v.Severity != "HIGH" {
			t.Errorf("Severity = %q, want HIGH preserved (alerts must keep detection severity for SLO/audit)", v.Severity)
		}
		if len(v.Findings) != 1 || v.Findings[0] != "CMD-NETCAT-LISTEN" {
			t.Errorf("Findings = %v, want preserved", v.Findings)
		}
		// Reason must keep the original match text AND add the
		// audit marker — otherwise operators who grep for the
		// rule ID lose the original signal.
		if !strings.Contains(v.Reason, "CMD-NETCAT-LISTEN:Netcat listener") {
			t.Errorf("original reason lost; got %q", v.Reason)
		}
		if !strings.Contains(v.Reason, "policy-action=block") {
			t.Errorf("audit marker missing; got %q", v.Reason)
		}
	})

	t.Run("prompt critical block preserved (escape hatch)", func(t *testing.T) {
		// CRITICAL severity is the explicit escape hatch from the
		// prompt-surface clamp: regardless of the absent modal,
		// CRITICAL prompts (clear injection chains, exfil payloads,
		// known credential dumps) get the [DefenseClaw] block
		// response. The Reason is not annotated because no demotion
		// occurred — operators reading the canonical event see the raw
		// rule match exactly as the scanner produced it.
		v := &ScanVerdict{
			Action:   guardrailActionBlock,
			Severity: "CRITICAL",
			Reason:   "matched: CMD-RM-RF:Recursive root deletion",
			Findings: []string{"CMD-RM-RF"},
		}
		clampPromptDirectionVerdict(v, "prompt")
		if v.Action != guardrailActionBlock {
			t.Errorf("CRITICAL Action mutated to %q; CRITICAL must bypass the prompt-surface clamp", v.Action)
		}
		if strings.Contains(v.Reason, "policy-action=") {
			t.Errorf("audit marker leaked onto CRITICAL verdict (no demotion happened); got %q", v.Reason)
		}
	})

	t.Run("prompt critical confirm preserved", func(t *testing.T) {
		// Sanity: the escape hatch covers confirm too, in case the
		// policy ever maps a CRITICAL verdict through HILT.
		v := &ScanVerdict{
			Action:   guardrailActionConfirm,
			Severity: "CRITICAL",
			Reason:   "matched: SOMETHING-CRITICAL",
		}
		clampPromptDirectionVerdict(v, "prompt")
		if v.Action != guardrailActionConfirm {
			t.Errorf("CRITICAL confirm mutated to %q; CRITICAL must bypass the clamp regardless of action", v.Action)
		}
	})

	t.Run("completion direction untouched", func(t *testing.T) {
		v := &ScanVerdict{
			Action:   guardrailActionBlock,
			Severity: "HIGH",
			Reason:   "matched: SECRET-AWS",
		}
		clampPromptDirectionVerdict(v, "completion")
		if v.Action != guardrailActionBlock {
			t.Errorf("completion Action mutated to %q; tool/completion surfaces must keep full enforcement", v.Action)
		}
		if strings.Contains(v.Reason, "policy-action=") {
			t.Errorf("audit marker leaked onto non-prompt verdict; got %q", v.Reason)
		}
	})

	t.Run("prompt allow untouched", func(t *testing.T) {
		v := &ScanVerdict{Action: guardrailActionAllow, Severity: "NONE"}
		clampPromptDirectionVerdict(v, "prompt")
		if v.Action != guardrailActionAllow {
			t.Errorf("allow verdict mutated to %q", v.Action)
		}
		if v.Reason != "" {
			t.Errorf("reason mutated for allow verdict; got %q", v.Reason)
		}
	})
}

func TestSignalStrengthToSeverity(t *testing.T) {
	cases := []struct {
		unambiguous bool
		highImpact  bool
		want        string
	}{
		{true, true, "CRITICAL"},
		{true, false, "HIGH"},
		{false, true, "MEDIUM"},
		{false, false, "LOW"},
	}
	for _, c := range cases {
		got := SignalStrengthToSeverity(c.unambiguous, c.highImpact)
		if got != c.want {
			t.Errorf("SignalStrengthToSeverity(%v, %v) = %q, want %q",
				c.unambiguous, c.highImpact, got, c.want)
		}
	}
}

func TestSeverityCriteriaCoversAllLevels(t *testing.T) {
	for _, level := range SeverityOrder {
		desc, ok := SeverityCriteria[level]
		if !ok {
			t.Errorf("SeverityCriteria missing entry for %q", level)
			continue
		}
		if strings.TrimSpace(desc) == "" {
			t.Errorf("SeverityCriteria[%q] is empty", level)
		}
	}
	if len(SeverityCriteria) != len(SeverityOrder) {
		t.Errorf("SeverityCriteria size %d != SeverityOrder size %d — entries drifted",
			len(SeverityCriteria), len(SeverityOrder))
	}
}

func TestSeverityOrderMatchesRanks(t *testing.T) {
	// Ensure SeverityOrder aligns with the iota-based ranks so that
	// index(SeverityOrder, label) matches guardrailSeverityRank(label).
	for i, label := range SeverityOrder {
		rank := guardrailSeverityRank(label)
		if rank != i {
			t.Errorf("SeverityOrder[%d]=%q rank=%d, want %d", i, label, rank, i)
		}
	}
}
