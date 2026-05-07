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
// gateway.jsonl readers can grep for the original (more aggressive) policy
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
		// occurred — operators reading gateway.jsonl see the raw
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
