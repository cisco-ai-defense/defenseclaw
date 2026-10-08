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
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
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
// path, and a v8 rule_pack_dir itself. On the Linux and macOS standalone
// layout a built-in name whose policy_dir folder does not exist is the
// shipped vendor pack, as the implicit default pack is
// (standaloneRulePackDefault). An unknown name resolves to "" (the
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
		dir := filepath.Join(c.PolicyDir, "guardrail", ref.Name)
		if vendor := c.vendorRulePackDir(ref.Name); vendor != "" {
			if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
				return vendor
			}
		}
		return dir
	}
	return ""
}

// vendorRulePackDir is the shipped built-in pack name of the Linux or macOS
// standalone layout this config is read from, "" elsewhere.
func (c *Config) vendorRulePackDir(name string) string {
	if !c.StandaloneEnterprise() {
		return ""
	}
	layout, ok := standaloneUnixLayoutForConfig(c.ConfigFilePath)
	if !ok {
		return ""
	}
	return path.Join(layout.VendorPolicyDir, "guardrail", name)
}

// ReferencedRulePackDirs maps every rule-pack setting the gateway can load
// to the directory it resolves to, keyed by the config path an
// administrator wrote: the global pack, each connector, each guardrail
// profile and its connectors, automatic-protection overlays, and every
// custom_packs entry. A v8
// rule_pack_dir is labelled as such; an empty directory selects the
// embedded packs.
func (c *Config) ReferencedRulePackDirs() map[string]string {
	out := map[string]string{}
	if c == nil {
		return out
	}
	g := &c.Guardrail
	label := func(prefix string, pc PerConnectorGuardrailConfig) string {
		if strings.TrimSpace(pc.RulePack) != "" {
			return prefix + ".rule_pack"
		}
		return prefix + ".rule_pack_dir"
	}
	out[label("guardrail", PerConnectorGuardrailConfig{RulePack: g.RulePack})] = c.ResolveRulePackDir(g.EffectiveRulePackRef(""))
	for name, pc := range g.Connectors {
		out[label("guardrail.connectors."+name, pc)] = c.EffectiveRulePackDirForConnector(name)
	}
	for name, profile := range g.Profiles {
		prefix := "guardrail.profiles." + name
		own := PerConnectorGuardrailConfig{RulePack: profile.RulePack, RulePackDir: profile.RulePackDir}
		if ref, ok := rulePackRefOf(own); ok {
			out[label(prefix, own)] = c.ResolveRulePackDir(ref)
		}
		for connector, pc := range profile.Connectors {
			if ref, ok := rulePackRefOf(pc); ok {
				out[label(prefix+".connectors."+connector, pc)] = c.ResolveRulePackDir(ref)
			}
		}
	}
	if ref, ok := rulePackRefOf(c.ApplicationProtection.Guardrail); ok {
		out[label("application_protection.guardrail", c.ApplicationProtection.Guardrail)] = c.ResolveRulePackDir(ref)
	}
	for connector, pc := range c.ApplicationProtection.Connectors {
		if ref, ok := rulePackRefOf(pc.Guardrail); ok {
			out[label("application_protection.connectors."+connector+".guardrail", pc.Guardrail)] = c.ResolveRulePackDir(ref)
		}
	}
	for name, pack := range g.CustomPacks {
		out["guardrail.custom_packs."+name+".path"] = strings.TrimSpace(pack.Path)
	}
	return out
}

// cleanCustomPackPaths writes every absolute guardrail.custom_packs path in
// its clean form, so one pack has one effective policy digest however its
// path is spelled (/etc/p/guardrail/../guardrail/acme, a trailing slash):
// the digest covers the loaded config, and two spellings of one pack gave
// two digests (GAP-0548). Windows paths are left as written: Clean there
// also turns forward slashes into backslashes.
func cleanCustomPackPaths(cfg *Config) {
	if runtime.GOOS == "windows" {
		return
	}
	for name, pack := range cfg.Guardrail.CustomPacks {
		path := strings.TrimSpace(pack.Path)
		if !filepath.IsAbs(path) {
			continue
		}
		if clean := filepath.Clean(path); clean != pack.Path {
			pack.Path = clean
			cfg.Guardrail.CustomPacks[name] = pack
		}
	}
}

// RulePackCheckOrder orders the keys of ReferencedRulePackDirs for a check:
// the global setting first (guardrail.rule_pack, else guardrail.rule_pack_dir),
// then every other setting whose pack differs from it, by key. A connector
// that only inherits the global pack is not checked again, so a refusal names
// the key the administrator wrote. It used to name
// guardrail.connectors.amp.rule_pack_dir, which sorts first, for a config
// that never set it (GAP-1193, GAP-0039).
func RulePackCheckOrder(dirs map[string]string) []string {
	global := "guardrail.rule_pack_dir"
	if _, ok := dirs["guardrail.rule_pack"]; ok {
		global = "guardrail.rule_pack"
	}
	globalDir, hasGlobal := dirs[global]
	globalDir = strings.TrimSpace(globalDir)
	labels := make([]string, 0, len(dirs))
	for label := range dirs {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	order := []string{}
	if hasGlobal {
		order = append(order, global)
	}
	for _, label := range labels {
		if label == global {
			continue
		}
		if dir := strings.TrimSpace(dirs[label]); hasGlobal && globalDir != "" && filepath.Clean(dir) == filepath.Clean(globalDir) {
			continue
		}
		order = append(order, label)
	}
	return order
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
