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

package config

import (
	"path/filepath"
	"strings"
)

// Rule-pack selection for one connector: which pack (guardrail.rule_pack, a
// built-in name or a custom_packs key, or the v8 rule_pack_dir) and which
// guardrail.rules layers apply to it. The gateway composes the result in
// memory once per generation.

// BuiltinRulePacks are the rule-pack names config.yaml can select without a
// custom_packs entry; each is <policy_dir>/guardrail/<name>.
var BuiltinRulePacks = []string{"default", "strict", "permissive"}

// IsBuiltinRulePack reports whether name is a built-in rule pack.
func IsBuiltinRulePack(name string) bool {
	for _, builtin := range BuiltinRulePacks {
		if name == builtin {
			return true
		}
	}
	return false
}

// RulePackRef is the base pack a connector scans with: Name (rule_pack) or
// Dir (the v8 rule_pack_dir). Both empty selects the embedded defaults.
type RulePackRef struct {
	Name string
	Dir  string
}

// Key identifies the reference for caching and digests.
func (r RulePackRef) Key() string {
	if r.Name != "" {
		return "name:" + r.Name
	}
	return "dir:" + strings.TrimSpace(r.Dir)
}

func rulePackRefOf(pc PerConnectorGuardrailConfig) (RulePackRef, bool) {
	if name := strings.TrimSpace(pc.RulePack); name != "" {
		return RulePackRef{Name: name}, true
	}
	if dir := strings.TrimSpace(pc.RulePackDir); dir != "" {
		return RulePackRef{Dir: dir}, true
	}
	return RulePackRef{}, false
}

// EffectiveRulePackRefForConnector resolves the connector's pack with the
// precedence of EffectiveRulePackDirForConnector: the application_protection
// overlay (for a connector not configured manually), then the connector's
// guardrail.connectors entry (and, on a profile-derived configuration, the
// profile's connectors entry), then the global pack. At one scope rule_pack
// wins over rule_pack_dir.
func (c *Config) EffectiveRulePackRefForConnector(connector string) RulePackRef {
	if c == nil {
		return RulePackRef{}
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok {
		if ref, set := rulePackRefOf(pc); set {
			return ref
		}
	}
	return c.Guardrail.EffectiveRulePackRef(connector)
}

// EffectiveRulePackRef is EffectiveRulePackRefForConnector for a caller that
// holds only the guardrail block: the connector's entry (and a derived
// profile's connectors entry), else the global pack.
func (g *GuardrailConfig) EffectiveRulePackRef(connector string) RulePackRef {
	if g == nil {
		return RulePackRef{}
	}
	if pc, ok := g.policyOverride(connector); ok {
		if ref, set := rulePackRefOf(pc); set {
			return ref
		}
	}
	ref, _ := rulePackRefOf(PerConnectorGuardrailConfig{RulePack: g.RulePack, RulePackDir: g.RulePackDir})
	return ref
}

// ResolveRulePackDir returns the directory a reference loads from: a
// built-in name is <policy_dir>/guardrail/<name>, a custom_packs name its
// path, and a v8 rule_pack_dir itself. An unknown name resolves to "" (the
// gateway's generation build rejects it before anything loads).
func (c *Config) ResolveRulePackDir(ref RulePackRef) string {
	if c == nil {
		return ""
	}
	if ref.Name == "" {
		return strings.TrimSpace(ref.Dir)
	}
	if custom, ok := c.Guardrail.CustomPacks[ref.Name]; ok {
		return strings.TrimSpace(custom.Path)
	}
	if IsBuiltinRulePack(ref.Name) && strings.TrimSpace(c.PolicyDir) != "" {
		return filepath.Join(c.PolicyDir, "guardrail", ref.Name)
	}
	return ""
}

// EffectiveRulesForConnector returns the guardrail.rules layers that apply
// to the connector, broadest first: guardrail.rules, the connector's
// guardrail.connectors entry, then on a profile-derived configuration the
// profile's rules and its connectors entry. Empty layers are left out.
func (c *Config) EffectiveRulesForConnector(connector string) []GuardrailRulesConfig {
	if c == nil {
		return nil
	}
	g := &c.Guardrail
	var layers []GuardrailRulesConfig
	add := func(rules *GuardrailRulesConfig) {
		if rules != nil && !rules.IsZero() {
			layers = append(layers, *rules)
		}
	}
	add(&g.Rules)
	if strings.TrimSpace(connector) != "" {
		if pc, ok := g.connectorOverride(connector); ok {
			add(pc.Rules)
		}
	}
	add(g.profileRules)
	if strings.TrimSpace(connector) != "" && len(g.profileConnectors) > 0 {
		if pc, ok := g.profileConnectors[normalizeConnectorKey(connector)]; ok {
			add(pc.Rules)
		}
	}
	return layers
}

// Cisco AI Defense trust levels (guardrail.cisco_trust_level).
const (
	CiscoTrustFull     = "full"
	CiscoTrustAdvisory = "advisory"
	CiscoTrustNone     = "none"
)

// EffectiveCiscoTrustLevel returns guardrail.cisco_trust_level, defaulting to
// full.
func (g *GuardrailConfig) EffectiveCiscoTrustLevel() string {
	if g == nil {
		return CiscoTrustFull
	}
	switch level := strings.ToLower(strings.TrimSpace(g.CiscoTrustLevel)); level {
	case CiscoTrustAdvisory, CiscoTrustNone:
		return level
	default:
		return CiscoTrustFull
	}
}
