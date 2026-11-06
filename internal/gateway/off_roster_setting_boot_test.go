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
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestOffRosterSettingKeepsTheBootedConnectorsPolicyAndWatcher pins GAP-0588 and
// GAP-0707. A stored setting for another connector (one guardrail.connectors
// key, which the CLI writes without selecting that connector) must not move the
// active rule pack or the per-user watcher set away from the connector the
// gateway boots.
func TestOffRosterSettingKeepsTheBootedConnectorsPolicyAndWatcher(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.PolicyDir = filepath.Join(cwd, "..", "..", "policies")
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "kiro"
	cfg.Guardrail.RulePack = "strict"
	cfg.Guardrail.RulePackDir = ""
	cfg.Guardrail.Connectors = nil

	before, err := preflightSidecarRulePacks(cfg)
	if err != nil {
		t.Fatalf("preflight before: %v", err)
	}

	raw := fmt.Sprintf("config_version: 9\ndata_dir: %q\npolicy_dir: %q\nguardrail:\n  enabled: true\n  connector: kiro\n  rule_pack: strict\n  connectors:\n    codex:\n      rule_pack: permissive\n", cfg.DataDir, cfg.PolicyDir)
	parsed, err := config.LoadRuntimeV8CandidateFromBytes(filepath.Join(cfg.DataDir, "config.yaml"), []byte(raw))
	if err != nil {
		t.Fatalf("config with a stored off-roster setting did not load: %v", err)
	}
	if name := configuredConnectorName(parsed); name != "kiro" {
		t.Fatalf("booted connector = %q, want kiro", name)
	}
	if names := parsed.ActiveConnectors(); len(names) != 1 || names[0] != "kiro" {
		t.Fatalf("ActiveConnectors() = %v, want [kiro]", names)
	}
	watchers := watcherConnectors(connector.NewDefaultRegistry(), parsed)
	if len(watchers) != 1 || watchers[0].Name() != "kiro" {
		t.Fatalf("watcher connectors = %v, want [kiro]", watchers)
	}
	after, err := preflightSidecarRulePacks(parsed)
	if err != nil {
		t.Fatalf("preflight after: %v", err)
	}
	if before.active.Summary().Digest != after.active.Summary().Digest {
		t.Fatal("the active rule pack changed after a stored setting for another connector")
	}
	if activeRulePackKey(cfg) != activeRulePackKey(parsed) {
		t.Fatal("the composed pack key changed after a stored setting for another connector")
	}
	hasStrictOnly := func(p *sidecarRulePackCandidate) bool {
		for _, file := range p.active.RuleFiles {
			for _, rule := range file.Rules {
				if rule.ID == "SEC-ENV-DUMP-REQUEST" {
					return true
				}
			}
		}
		return false
	}
	if !hasStrictOnly(before) || !hasStrictOnly(after) {
		t.Fatalf("strict-only protective rule before=%t after=%t, want true true", hasStrictOnly(before), hasStrictOnly(after))
	}
}

// Benign twin: two roster entries still select the multi-connector boot and
// watch both connectors.
func TestTwoEntryRosterStillWatchesBothConnectors(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Connector = "kiro"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"kiro": {}, "codex": {}}
	names := []string{}
	for _, c := range watcherConnectors(connector.NewDefaultRegistry(), cfg) {
		names = append(names, c.Name())
	}
	if len(names) != 2 {
		t.Fatalf("watcher connectors = %v, want kiro and codex", names)
	}
}
