// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The install-time skill scan applies the pack a connector's scope selects, and
// adds nothing on a default install (GAP-0065).
func TestInstallScanRulePackFollowsTheConnectorScope(t *testing.T) {
	global, codex := &guardrail.RulePack{}, &guardrail.RulePack{}
	cfg := &config.Config{}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {RulePack: "strict"}}
	previous := liveGeneration.Load()
	t.Cleanup(func() { liveGeneration.Store(previous) })
	liveGeneration.Store(&Generation{
		Config:    cfg,
		RulePacks: map[string]*guardrail.RulePack{"global": global, "conn:codex": codex},
	})

	if got := installScanRulePack("claudecode"); got != nil {
		t.Fatalf("a connector that selects no pack got %p, want none", got)
	}
	if got := installScanRulePack("Codex"); got != codex {
		t.Fatalf("codex's own pack = %p, want %p", got, codex)
	}
	cfg.Guardrail.RulePack = "default"
	if got := installScanRulePack("claudecode"); got != global {
		t.Fatalf("a connector under the global pack got %p, want %p", got, global)
	}
	cfg.Guardrail.RulePack = ""
	cfg.Guardrail.Rules.Disable = []string{"SEC-AWS-KEY"}
	if got := installScanRulePack("claudecode"); got != global {
		t.Fatalf("guardrail.rules alone must select the composed global pack, got %p", got)
	}
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(false) })
	if got := installScanRulePack("claudecode"); got != nil {
		t.Fatalf("Secure Client scans with Cisco AI Defense alone, got %p", got)
	}
}
