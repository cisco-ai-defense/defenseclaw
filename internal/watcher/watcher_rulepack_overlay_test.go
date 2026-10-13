// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// The install-time skill scan applies the owning connector's rule pack, so a
// secret `defenseclaw skill scan` rejects is not allowed at install (GAP-0065).
func TestSkillScanAppliesTheConnectorRulePack(t *testing.T) {
	pack, err := guardrail.LoadRulePack(filepath.Join("..", "..", "policies", "guardrail", "default"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte(`KEY = "AKIAIOSFODNN7EXAMPLE"`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := New(&config.Config{}, nil, nil, nil, nil, nil, nil)
	inner := &countingScanner{name: "skill-scanner"}
	evt := InstallEvent{Type: InstallSkill, Connector: "codex"}

	if got := w.withRulePackOverlay(inner, evt); got != scanner.Scanner(inner) {
		t.Fatal("a watcher with no rule pack source must scan with the skill scanner alone")
	}
	var asked string
	w.SetRulePackSource(func(connector string) *guardrail.RulePack { asked = connector; return pack })
	result, err := w.withRulePackOverlay(inner, evt).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if asked != "codex" || result.MaxSeverity() != scanner.SeverityCritical {
		t.Fatalf("asked %q, max severity %s: want codex's pack and CRITICAL (%+v)", asked, result.MaxSeverity(), result.Findings)
	}

	w.SetRulePackSource(func(string) *guardrail.RulePack { return nil })
	if got := w.withRulePackOverlay(inner, evt); got != scanner.Scanner(inner) {
		t.Fatal("a connector whose scope selects no pack must scan with the skill scanner alone")
	}
}

func TestMCPScannerUsesReloadedRulePack(t *testing.T) {
	startup := &config.Config{}
	startup.Guardrail.Rules.Disable = []string{"OLD"}
	live := &config.Config{}
	live.Guardrail.Rules.Disable = []string{"NEW"}
	w := New(startup, nil, nil, nil, nil, nil, nil)
	w.SetConfigSource(func() *config.Config { return live })
	got, ok := w.scannerFor(InstallEvent{Type: InstallMCP, Connector: "codex"}).(*scanner.MCPScanner)
	if !ok {
		t.Fatal("MCP event did not create an MCP scanner")
	}
	if !reflect.DeepEqual(got.RulePack.Rules, live.EffectiveRulesForConnector("codex")) {
		t.Fatalf("MCP rule layers = %+v, want live layers", got.RulePack.Rules)
	}
}
