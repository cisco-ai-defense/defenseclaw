// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP1269PermissivePromptPasswordStillAlerts: rel-1-0-10:GAP-1269. On
// rel a credential its proxy secret regexes read in a prompt was a
// HIGH_SIGNAL triage signal (TRIAGE-SECRET-REGEX) for the default strategy
// regex_judge, so the permissive posture (alert from HIGH) alerted on a
// password assignment. GAP-0210 removed those regexes and the signal with
// them, and SEC-PASSWORD-ASSIGN is MEDIUM: permissive allowed the prompt.
// secretRuleTriageSignals lifts the pack's credential findings in a prompt
// again. The default and strict tiers already alert and block at MEDIUM.
func TestGAP1269PermissivePromptPasswordStillAlerts(t *testing.T) {
	gap1266WantAtLeast(t, []string{"R01", "R02", "R03", "R04", "S01", "W01", "I01", "N01", "W13", "S03"}, []string{"prompt-rj"},
		map[string]string{"permissive": "alert", "default": "alert", "strict": "block"})
}

// TestGAP1269CompletionKeepsTheRuleSeverity: the lift is for a prompt only;
// in a completion the rule finding is the verdict, as on rel, so permissive
// still allows a MEDIUM password finding in a model response.
func TestGAP1269CompletionKeepsTheRuleSeverity(t *testing.T) {
	ctx := gap0210WeakPasswordTiers[1].context(t)
	rj := NewGuardrailInspector("local", nil, nil)
	rj.SetDetectionStrategy("regex_judge", "", "", "", false)
	rj.SetPosture("permissive")
	v := rj.Inspect(ctx, "completion", gap1266Rows["S01"], nil, "model", "action")
	if v.Action != "allow" || v.Severity != "MEDIUM" {
		t.Errorf("permissive completion: %s %s %v, want allow MEDIUM", v.Action, v.Severity, v.Findings)
	}
}
