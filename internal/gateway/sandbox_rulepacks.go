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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// sandboxHarnessRulePackConnectors lists the connectors whose rule packs the
// gateway serves only for OpenShell sandboxes: the harnesses in
// Config.PolicyConnectors that are not active host connectors, with the
// sandbox integration and their guardrail enabled. Such a harness runs in a
// sandbox without its connector being set up on the host, so no connector
// setup publishes its pack; without an entry of its own, its hooks would scan
// with the active pack, which is the single host connector's when exactly one
// is active. Host connectors keep their setup-owned lifecycle.
func sandboxHarnessRulePackConnectors(cfg *config.Config) []string {
	if cfg == nil || !cfg.OpenShell.Enabled || !cfg.Guardrail.Enabled {
		return nil
	}
	host := make(map[string]struct{})
	for _, name := range cfg.ActiveConnectors() {
		host[canonicalConnectorRulePackKey(name)] = struct{}{}
	}
	var names []string
	for _, raw := range cfg.PolicyConnectors() {
		name := canonicalConnectorRulePackKey(raw)
		if _, active := host[name]; name == "" || active || !cfg.Guardrail.EffectiveEnabled(name) {
			continue
		}
		names = append(names, name)
	}
	return names
}

// ruleManagedConnectors lists the connectors whose entries a config reload
// replaces (publishConnectorRulePackGeneration): the active host connectors
// and the sandbox harness connectors.
func ruleManagedConnectors(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	return append(cfg.ActiveConnectors(), sandboxHarnessRulePackConnectors(cfg)...)
}

// loadSandboxHarnessRulePack loads and validates a sandbox harness
// connector's effective rule pack.
func loadSandboxHarnessRulePack(cache *guardrail.RulePackCache, cfg *config.Config, name string) (*guardrail.RulePack, error) {
	return loadConnectorRulePack(cache, cfg, name, "sandbox harness "+name)
}

// prepareInitialSandboxHarnessRules compiles the cold-start rule sets of the
// sandbox harness connectors. As a host connector's bad pack fails only that
// connector's setup, a harness pack that does not load is skipped with a log
// line: the harness scans with the active pack until a reload succeeds.
func prepareInitialSandboxHarnessRules(cfg *config.Config) map[string]*compiledRulePackCategories {
	cache := guardrail.NewRulePackCache()
	rules := make(map[string]*compiledRulePackCategories)
	for _, name := range sandboxHarnessRulePackConnectors(cfg) {
		rp, err := loadSandboxHarnessRulePack(cache, cfg, name)
		var compiled *compiledRulePackCategories
		if err == nil {
			compiled, err = compileRulePackCategories(rp)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] sandbox harness %s keeps the active rule pack: %v\n", name, err)
			continue
		}
		rules[name] = compiled
	}
	return rules
}
