// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-10:GAP-0851, GAP-0962 (owner ruling 2026-11-21): a call whose
// only finding is the evaluation bound (ACTION-COMPOUND-LIMIT: the reader
// stopped at a cap, no target is proven) is MEDIUM, and its action is the
// truncated row of the pack's tier table on every route: an alert in the
// default and permissive packs, a block in strict. In 1.0.10 the bound
// finding was CRITICAL (so that strict blocked it), every route reported a
// CRITICAL verdict, and the content surface, which had no truncated row,
// blocked it in every pack.
func TestGAP0851BoundOnlyCallIsMediumOnEveryRoute(t *testing.T) {
	limit := trustedActionLimitFindings(true)
	if got := HighestSeverity(limit); got != "MEDIUM" {
		t.Errorf("verdict severity of a bound-only call: %s, want MEDIUM", got)
	}
	if got := HighestConfidence(limit, HighestSeverity(limit)); got != 1 {
		t.Errorf("verdict confidence of a bound-only call: %v, want 1", got)
	}
	for posture, want := range map[string]string{"default": guardrailActionAlert, "permissive": guardrailActionAlert, "strict": guardrailActionBlock} {
		dir := filepath.Join(guardrailPoliciesRoot(t), posture)
		cfg := &config.Config{}
		cfg.Guardrail.RulePackDir = dir
		gc := &config.GuardrailConfig{RulePackDir: dir}
		for route, got := range map[string]string{
			"hook":    singleProfileActionForFindings(cfg, "claudecode", limit, true, false),
			"content": guardrailContentActionForFindings(cfg, "claudecode", limit, false),
			"proxy":   guardrailActionForGuardrailFindings(gc, "", limit, false),
		} {
			if got != want {
				t.Errorf("%s pack, %s route: %s, want %s", posture, route, got, want)
			}
		}
	}
	// A proven finding beside the bound keeps its own severity.
	keys := RuleFinding{RuleID: "persistence.ssh_authorized_keys_command", Severity: "CRITICAL"}
	if got := HighestSeverity(append(trustedActionLimitFindings(true), keys)); got != "CRITICAL" {
		t.Errorf("verdict severity of a bound beside a keys write: %s, want CRITICAL", got)
	}
}
