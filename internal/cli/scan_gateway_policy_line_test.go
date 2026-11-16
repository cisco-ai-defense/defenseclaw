// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-2635: the administrator's scan skill|plugin prints the admission
// result as a "policy:" line; MCP scans and older gateways send none.
func TestGatewayScanPolicyLine(t *testing.T) {
	for verdict, want := range map[string]string{
		"rejected": "rejected - the policy would refuse this skill at install (max severity CRITICAL triggers block per policy); this scan blocked nothing",
		"blocked":  "rejected - the policy would refuse this skill at install (max severity CRITICAL triggers block per policy); this scan blocked nothing",
		"allowed":  "accepted - the policy would admit this skill at install (max severity CRITICAL triggers block per policy)",
		"warning":  "accepted with a warning - the policy would admit this skill at install (max severity CRITICAL triggers block per policy)",
		"scan":     "",
	} {
		got := gatewayScanPolicyLine("skill", &gatewayScanAdmission{Verdict: verdict, Reason: "max severity CRITICAL triggers block per policy"})
		if got != want {
			t.Errorf("%s: got %q, want %q", verdict, got, want)
		}
	}
	if got := gatewayScanPolicyLine("plugin", &gatewayScanAdmission{Verdict: "clean"}); !strings.HasPrefix(got, "accepted - the policy would admit this plugin at install") {
		t.Errorf("clean plugin: %q", got)
	}
	if got := gatewayScanPolicyLine("mcp", nil); got != "" {
		t.Errorf("no admission result: %q", got)
	}
}
