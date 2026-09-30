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
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// secretRulePackDir writes a rule pack whose secret category is one rule.
func secretRulePackDir(t *testing.T, ruleID, token string) string {
	t.Helper()
	dir := t.TempDir()
	writeRulePackFixtureFile(t, dir, "rules/secret.yaml", `version: 1
category: secret
rules:
  - id: `+ruleID+`
    pattern: '`+token+`'
    title: fixture rule
    severity: HIGH
    confidence: 0.9
    tags: [test]
`)
	return dir
}

// sandboxHarnessConfig is one host connector (claudecode) with its own pack
// and the codex harness enabled only for OpenShell sandboxes.
func sandboxHarnessConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.RulePackDir = secretRulePackDir(t, "GLOBAL-RULE", "dcglobal_token")
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": {RulePackDir: secretRulePackDir(t, "HOST-RULE", "dchost_token")},
	}
	cfg.OpenShell.Enabled = true
	cfg.OpenShell.Harnesses = []string{"codex", "Claude-Code"}
	return cfg
}

func TestSandboxHarnessRulePackConnectors(t *testing.T) {
	cfg := sandboxHarnessConfig(t)
	if got, want := sandboxHarnessRulePackConnectors(cfg), []string{"codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox harness connectors = %v, want %v (claudecode is a host connector)", got, want)
	}
	if got, want := ruleManagedConnectors(cfg), []string{"claudecode", "codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reload-managed connectors = %v, want %v", got, want)
	}

	for name, edit := range map[string]func(*config.Config){
		"sandboxes off": func(c *config.Config) { c.OpenShell.Enabled = false },
		"guardrail off": func(c *config.Config) { c.Guardrail.Enabled = false },
		// A guardrail.connectors entry makes the harness a host connector,
		// whose setup owns its pack.
		"harness is a host connector": func(c *config.Config) {
			c.Guardrail.Connectors["codex"] = config.PerConnectorGuardrailConfig{}
		},
	} {
		c := sandboxHarnessConfig(t)
		edit(c)
		if got := sandboxHarnessRulePackConnectors(c); len(got) != 0 {
			t.Errorf("%s: sandbox harness connectors = %v, want none", name, got)
		}
	}
	if got := sandboxHarnessRulePackConnectors(nil); got != nil {
		t.Fatalf("nil config: %v", got)
	}
}

// A sandbox-only harness scans with its own effective pack (the global one
// here), not the single host connector's, from cold start and after reloads.
func TestSandboxHarnessScansWithItsOwnRulePack(t *testing.T) {
	resetConnectorRuleCategories(t)
	cfg := sandboxHarnessConfig(t)

	candidate, err := preflightSidecarRulePacks(cfg)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if candidate.connectors["codex"] == nil || candidate.connectorRules["codex"] == nil {
		t.Fatalf("preflight left out the sandbox harness: connectors=%v", candidate.connectors)
	}
	if candidate.active != candidate.connectors["claudecode"] {
		t.Fatal("the single host connector's pack must stay the active pack")
	}
	// The host connector's pack is the active (fallback) set.
	publishRulePackOverrides(candidate.activeRules)
	publishConnectorRulePackGeneration(nil, candidate.connectorRules)
	if ids := ruleIDsForConnector("codex", "dcglobal_token"); !containsRuleID(ids, "GLOBAL-RULE") {
		t.Fatalf("codex findings = %v, want its own (global) pack", ids)
	}
	if ids := ruleIDsForConnector("codex", "dchost_token"); containsRuleID(ids, "HOST-RULE") {
		t.Fatalf("codex scanned with the host connector's pack: %v", ids)
	}

	// Removing the harness retires its entry on the next reload.
	next := sandboxHarnessConfig(t)
	next.Guardrail = cfg.Guardrail
	next.OpenShell.Harnesses = nil
	nextCandidate, err := preflightSidecarRulePacks(next)
	if err != nil {
		t.Fatalf("preflight without the harness: %v", err)
	}
	publishConnectorRulePackGeneration(ruleManagedConnectors(cfg), nextCandidate.connectorRules)
	ruleCategoriesMu.RLock()
	_, retained := connectorRuleCategories["codex"]
	ruleCategoriesMu.RUnlock()
	if retained {
		t.Fatal("a removed sandbox harness kept its rule set")
	}

	// Cold start publishes the same set.
	initial := prepareInitialSandboxHarnessRules(cfg)
	if len(initial) != 1 || initial["codex"] == nil {
		t.Fatalf("cold-start harness rules = %v, want codex", initial)
	}
}

func TestSandboxHarnessRulePackFailures(t *testing.T) {
	cfg := sandboxHarnessConfig(t)
	cfg.ApplicationProtection.Enabled = true
	cfg.ApplicationProtection.Guardrail.RulePackDir = invalidRulePackDir(t)

	// A reload candidate with a broken harness pack is refused.
	if _, err := preflightSidecarRulePacks(cfg); err == nil || !strings.Contains(err.Error(), "sandbox harness codex rule pack") {
		t.Fatalf("preflight error = %v, want the harness pack failure", err)
	}
	// Cold start keeps running; the harness scans with the active pack.
	if initial := prepareInitialSandboxHarnessRules(cfg); len(initial) != 0 {
		t.Fatalf("cold start published a broken harness pack: %v", initial)
	}
}
