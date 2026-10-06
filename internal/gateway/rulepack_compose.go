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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// Effective rule packs: the selected pack (guardrail.rule_pack, a
// custom_packs entry pinned by digest, or the v8 rule_pack_dir) with every
// guardrail.rules layer that applies to the scope composed in memory
// (guardrail.Compose). Every gateway load site goes through here, so a
// connector, profile or sandbox harness scans with the same composed pack
// the generation digests.

// protectionPackSource serves the built-in protection packs embedded in the
// binary (policies/guardrail-use-cases).
func protectionPackSource(name string) ([]guardrail.ProtectionRuleFile, error) {
	files, err := policyassets.ProtectionPackRules(name)
	if err != nil {
		return nil, err
	}
	out := make([]guardrail.ProtectionRuleFile, 0, len(files))
	for _, file := range files {
		out = append(out, guardrail.ProtectionRuleFile{Name: file.Path, Data: file.Data})
	}
	return out, nil
}

// globalRulePackRef is the global scope's pack: guardrail.rule_pack, else
// guardrail.rule_pack_dir. Unlike a connector it never takes an
// application_protection overlay.
func globalRulePackRef(cfg *config.Config) config.RulePackRef {
	if name := strings.TrimSpace(cfg.Guardrail.RulePack); name != "" {
		return config.RulePackRef{Name: name}
	}
	return config.RulePackRef{Dir: strings.TrimSpace(cfg.Guardrail.RulePackDir)}
}

// rulePackScope is one resolved scope: its pack reference and directory and
// the rules layers to compose.
type rulePackScope struct {
	ref    config.RulePackRef
	dir    string
	layers []config.GuardrailRulesConfig
}

func globalRulePackScope(cfg *config.Config) rulePackScope {
	ref := globalRulePackRef(cfg)
	return rulePackScope{ref: ref, dir: cfg.ResolveRulePackDir(ref), layers: cfg.EffectiveRulesForConnector("")}
}

func connectorRulePackScope(cfg *config.Config, connector string) rulePackScope {
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	return rulePackScope{ref: ref, dir: cfg.ResolveRulePackDir(ref), layers: cfg.EffectiveRulesForConnector(connector)}
}

// key identifies the composed pack of a scope: the directory plus the rules
// layers, so scopes sharing both share one composed pack.
func (s rulePackScope) key() string {
	if len(s.layers) == 0 {
		return profileRulePackKey(s.dir)
	}
	raw, _ := json.Marshal(s.layers)
	sum := sha256.Sum256(raw)
	return profileRulePackKey(s.dir) + "#rules=" + hex.EncodeToString(sum[:8])
}

// effectiveRulePackKey is the composed-pack key of connector's scope in cfg.
func effectiveRulePackKey(cfg *config.Config, connector string) string {
	if cfg == nil {
		return ""
	}
	return connectorRulePackScope(cfg, connector).key()
}

// loadGlobalRulePack loads and composes the global scope's pack.
func loadGlobalRulePack(cache *guardrail.RulePackCache, cfg *config.Config, scope string) (*guardrail.RulePack, error) {
	return loadScopedRulePack(cache, cfg, globalRulePackScope(cfg), scope)
}

// loadConnectorRulePack loads and composes connector's pack.
func loadConnectorRulePack(cache *guardrail.RulePackCache, cfg *config.Config, connector, scope string) (*guardrail.RulePack, error) {
	return loadScopedRulePack(cache, cfg, connectorRulePackScope(cfg, connector), scope)
}

func loadScopedRulePack(cache *guardrail.RulePackCache, cfg *config.Config, s rulePackScope, scope string) (*guardrail.RulePack, error) {
	if s.ref.Name != "" && s.dir == "" {
		if config.IsBuiltinRulePack(s.ref.Name) {
			return nil, fmt.Errorf("%s rule pack %q: policy_dir is not set", scope, s.ref.Name)
		}
		return nil, fmt.Errorf("%s rule pack %q is neither built in (%s) nor a guardrail.custom_packs entry",
			scope, s.ref.Name, strings.Join(config.BuiltinRulePacks, ", "))
	}
	base, err := loadValidatedRulePack(cache, s.dir, scope)
	if err != nil {
		return nil, err
	}
	if custom, ok := cfg.Guardrail.CustomPacks[s.ref.Name]; ok && s.ref.Name != "" {
		// The pin covers the pack's own files (FilesDigest), not the
		// embedded defaults it inherits for missing components.
		got := "sha256:" + base.FilesDigest()
		if !strings.EqualFold(strings.TrimSpace(custom.Digest), got) {
			return nil, fmt.Errorf("%s rule pack %q: digest %s does not match guardrail.custom_packs.%s.digest",
				scope, s.ref.Name, got, s.ref.Name)
		}
	}
	rememberPackPosture(s.dir, guardrail.ReadPackPosture(s.dir))
	if len(s.layers) == 0 {
		return base, nil
	}
	composed, err := guardrail.Compose(base, protectionPackSource, guardrailCustomizations(s.layers)...)
	if err != nil {
		return nil, fmt.Errorf("%s rule pack %q: %w", scope, s.dir, err)
	}
	return composed, nil
}

func guardrailCustomizations(layers []config.GuardrailRulesConfig) []guardrail.Customization {
	out := make([]guardrail.Customization, 0, len(layers))
	for _, layer := range layers {
		c := guardrail.Customization{
			Protections:       layer.Protections,
			Enable:            layer.Enable,
			Disable:           layer.Disable,
			SeverityOverrides: layer.SeverityOverrides,
		}
		for _, s := range layer.Suppressions {
			c.Suppressions = append(c.Suppressions, guardrail.FindingSuppression{
				ID:             s.ID,
				FindingPattern: s.FindingPattern,
				EntityPattern:  s.EntityPattern,
				Reason:         s.Reason,
			})
		}
		for _, t := range layer.SensitiveTools {
			c.SensitiveTools = append(c.SensitiveTools, guardrail.SensitiveToolOverride{
				Name:                t.Name,
				ResultInspection:    t.ResultInspection,
				JudgeResult:         t.JudgeResult,
				MinEntitiesForAlert: t.MinEntitiesForAlert,
			})
		}
		out = append(out, c)
	}
	return out
}

// installScanRulePack is the composed pack the install-time scan of a
// connector's skills applies on top of the skill scanner, the gateway's side
// of the rule-pack overlay of `defenseclaw skill scan`. It is nil when the
// connector's scope selects no pack and no guardrail.rules, so a default
// install scans as before. The pack comes from the live generation, which
// composed it with every guardrail.rules layer.
func installScanRulePack(connector string) *guardrail.RulePack {
	g := currentGeneration()
	// Secure Client: Cisco AI Defense decides and local regex detection is off.
	if g == nil || g.Config == nil || ManagedEnterpriseActive() {
		return nil
	}
	selects := func(connector string) bool {
		ref := g.Config.EffectiveRulePackRefForConnector(connector)
		return ref.Name != "" || ref.Dir != "" || len(g.Config.EffectiveRulesForConnector(connector)) > 0
	}
	if connector = canonicalConnectorRulePackKey(connector); connector != "" && selects(connector) {
		if pack := g.RulePacks["conn:"+connector]; pack != nil {
			return pack
		}
	}
	if selects("") {
		return g.RulePacks["global"]
	}
	return nil
}

// applicationProtectionRulePackScope is the global application_protection
// pack override, when one is set. It can apply to a connector discovered
// after publication, so a reload validates it on its own.
func applicationProtectionRulePackScope(cfg *config.Config) (rulePackScope, bool) {
	overlay := cfg.ApplicationProtection.Guardrail
	ref := config.RulePackRef{Name: strings.TrimSpace(overlay.RulePack)}
	if ref.Name == "" {
		ref.Dir = strings.TrimSpace(overlay.RulePackDir)
	}
	if ref.Name == "" && ref.Dir == "" {
		return rulePackScope{}, false
	}
	return rulePackScope{ref: ref, dir: cfg.ResolveRulePackDir(ref), layers: cfg.EffectiveRulesForConnector("")}, true
}
