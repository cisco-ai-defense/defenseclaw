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

package guardrail

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// In-memory rule-pack composition: a loaded base pack plus the
// guardrail.rules customisation of config.yaml (protections, enable, disable,
// severity_overrides, suppressions, sensitive_tools). Nothing is written to
// disk; the gateway composes once per configuration generation and the
// composed pack's Summary().Digest feeds the effective policy digest.

// PackManifestFile is the optional manifest of a rule-pack directory. Its
// "posture" field names the pack's default block/alert levels (default,
// strict or permissive).
const PackManifestFile = "defenseclaw-pack.json"

// ProtectionRuleFile is one rules/<Name> file of a built-in protection
// (use-case) pack.
type ProtectionRuleFile struct {
	Name string
	Data []byte
}

// ProtectionSource returns the rule files of the named protection pack.
type ProtectionSource func(name string) ([]ProtectionRuleFile, error)

// SensitiveToolOverride is a guardrail.rules.sensitive_tools entry. Nil and
// zero fields keep the pack's value for an existing tool.
type SensitiveToolOverride struct {
	Name                string
	ResultInspection    *bool
	JudgeResult         *bool
	MinEntitiesForAlert int
}

// Customization is one guardrail.rules block. Compose applies layers in
// order, so a narrower scope (connector, profile) layers over the global one.
type Customization struct {
	Protections       []string
	Enable            []string
	Disable           []string
	SeverityOverrides map[string]string
	Suppressions      []FindingSuppression
	SensitiveTools    []SensitiveToolOverride
}

// IsZero reports whether the layer changes nothing.
func (c Customization) IsZero() bool {
	return len(c.Protections) == 0 && len(c.Enable) == 0 && len(c.Disable) == 0 &&
		len(c.SeverityOverrides) == 0 && len(c.Suppressions) == 0 && len(c.SensitiveTools) == 0
}

// ComposeError names the guardrail.rules entry that could not be applied.
type ComposeError struct {
	Field  string
	Reason string
}

func (e *ComposeError) Error() string {
	return fmt.Sprintf("guardrail.rules.%s: %s", e.Field, e.Reason)
}

// Compose returns base with every layer applied, validated. base is never
// modified. Within a layer the order is: protections (each pack drops the
// rules whose IDs it ships, then appends its rules to the rule file of the
// same category, or adds the file), enable, disable, severity_overrides,
// suppressions, sensitive_tools. An unknown rule ID, a rule both enabled
// and disabled, or a suppression ID that already exists is an error.
func Compose(base *RulePack, protections ProtectionSource, layers ...Customization) (*RulePack, error) {
	if base == nil {
		return nil, &ComposeError{Field: "rule_pack", Reason: "no base rule pack"}
	}
	active := false
	for _, layer := range layers {
		if !layer.IsZero() {
			active = true
			break
		}
	}
	if !active {
		return base, nil
	}
	rp := cloneRulePackForCompose(base)
	for _, layer := range layers {
		if err := rp.applyCustomization(layer, protections); err != nil {
			return nil, err
		}
	}
	if err := rp.validate(true); err != nil {
		return nil, fmt.Errorf("guardrail.rules: composed rule pack: %w", err)
	}
	return rp, nil
}

func (rp *RulePack) applyCustomization(layer Customization, protections ProtectionSource) error {
	for _, name := range layer.Protections {
		if err := rp.layerProtection(name, protections); err != nil {
			return err
		}
	}
	both := make(map[string]struct{}, len(layer.Enable))
	for _, id := range layer.Enable {
		both[strings.TrimSpace(id)] = struct{}{}
	}
	for _, id := range layer.Disable {
		if _, dup := both[strings.TrimSpace(id)]; dup {
			return &ComposeError{Field: "disable", Reason: fmt.Sprintf("rule %s is also listed under enable", id)}
		}
	}
	for _, id := range layer.Enable {
		rule := rp.findRule(id)
		if rule == nil {
			return &ComposeError{Field: "enable", Reason: fmt.Sprintf("unknown rule %s", id)}
		}
		enabled := true
		rule.Enabled = &enabled
	}
	for _, id := range layer.Disable {
		rule := rp.findRule(id)
		if rule == nil {
			return &ComposeError{Field: "disable", Reason: fmt.Sprintf("unknown rule %s", id)}
		}
		disabled := false
		rule.Enabled = &disabled
	}
	for _, id := range sortedKeys(layer.SeverityOverrides) {
		severity := strings.ToUpper(strings.TrimSpace(layer.SeverityOverrides[id]))
		rule := rp.findRule(id)
		if rule == nil {
			return &ComposeError{Field: "severity_overrides", Reason: fmt.Sprintf("unknown rule %s", id)}
		}
		if !validSeverity(severity) {
			return &ComposeError{Field: "severity_overrides", Reason: fmt.Sprintf("rule %s severity must be LOW, MEDIUM, HIGH or CRITICAL", id)}
		}
		rule.Severity = severity
	}
	if len(layer.Suppressions) > 0 {
		if rp.Suppressions == nil {
			rp.Suppressions = &SuppressionsConfig{Version: 1}
		}
		seen := make(map[string]struct{}, len(rp.Suppressions.PreJudgeStrips)+len(rp.Suppressions.FindingSupps))
		for _, s := range rp.Suppressions.PreJudgeStrips {
			seen[strings.TrimSpace(s.ID)] = struct{}{}
		}
		for _, s := range rp.Suppressions.FindingSupps {
			seen[strings.TrimSpace(s.ID)] = struct{}{}
		}
		for _, s := range layer.Suppressions {
			id := strings.TrimSpace(s.ID)
			if _, dup := seen[id]; dup {
				return &ComposeError{Field: "suppressions", Reason: fmt.Sprintf("suppression %s already exists in the rule pack or config", id)}
			}
			seen[id] = struct{}{}
			if strings.TrimSpace(s.EntityPattern) == "" {
				// guardrail.rules suppressions may leave entity_pattern out:
				// the suppression then holds for every matched value.
				s.EntityPattern = ".*"
			}
			rp.Suppressions.FindingSupps = append(rp.Suppressions.FindingSupps, s)
		}
	}
	for _, override := range layer.SensitiveTools {
		rp.mergeSensitiveTool(override)
	}
	return nil
}

func (rp *RulePack) layerProtection(name string, protections ProtectionSource) error {
	name = strings.TrimSpace(name)
	if protections == nil {
		return &ComposeError{Field: "protections", Reason: fmt.Sprintf("protection pack %s is unavailable", name)}
	}
	files, err := protections(name)
	if err != nil {
		return &ComposeError{Field: "protections", Reason: fmt.Sprintf("protection pack %s: %v", name, err)}
	}
	decoded := make([]*RulesFileYAML, 0, len(files))
	incoming := make(map[string]struct{})
	for _, file := range files {
		var cfg RulesFileYAML
		rel := path.Join("rules", file.Name)
		if err := decodeStrictYAML(file.Data, rel, &cfg); err != nil {
			return &ComposeError{Field: "protections", Reason: fmt.Sprintf("protection pack %s: %v", name, err)}
		}
		cfg.SourcePath = file.Name
		for _, rule := range cfg.Rules {
			incoming[strings.TrimSpace(rule.ID)] = struct{}{}
		}
		decoded = append(decoded, &cfg)
	}
	if len(incoming) == 0 {
		return &ComposeError{Field: "protections", Reason: fmt.Sprintf("protection pack %s has no rules", name)}
	}
	for _, ruleFile := range rp.RuleFiles {
		kept := ruleFile.Rules[:0:0]
		for _, rule := range ruleFile.Rules {
			if _, drop := incoming[strings.TrimSpace(rule.ID)]; !drop {
				kept = append(kept, rule)
			}
		}
		ruleFile.Rules = kept
	}
	for _, pack := range decoded {
		target := rp.ruleFileCategory(pack.Category)
		if target == nil {
			added := *pack
			added.SourcePath = ""
			added.Rules = append([]RuleDefYAML(nil), pack.Rules...)
			rp.RuleFiles = append(rp.RuleFiles, &added)
			continue
		}
		if strings.TrimSpace(pack.Category) != "" {
			target.Category = pack.Category
		}
		target.Rules = append(target.Rules, pack.Rules...)
	}
	// A base file every rule of which a pack replaced would otherwise fail
	// validation as an empty category.
	kept := rp.RuleFiles[:0:0]
	for _, ruleFile := range rp.RuleFiles {
		if len(ruleFile.Rules) > 0 {
			kept = append(kept, ruleFile)
		}
	}
	rp.RuleFiles = kept
	return nil
}

func (rp *RulePack) ruleFileCategory(category string) *RulesFileYAML {
	for _, ruleFile := range rp.RuleFiles {
		if ruleFile.Category == category {
			return ruleFile
		}
	}
	return nil
}

func (rp *RulePack) findRule(id string) *RuleDefYAML {
	id = strings.TrimSpace(id)
	for _, ruleFile := range rp.RuleFiles {
		for index := range ruleFile.Rules {
			if strings.TrimSpace(ruleFile.Rules[index].ID) == id {
				return &ruleFile.Rules[index]
			}
		}
	}
	return nil
}

func (rp *RulePack) mergeSensitiveTool(override SensitiveToolOverride) {
	if rp.SensitiveTools == nil {
		rp.SensitiveTools = &SensitiveToolsConfig{Version: 1}
	}
	name := strings.TrimSpace(override.Name)
	for index := range rp.SensitiveTools.Tools {
		tool := &rp.SensitiveTools.Tools[index]
		if tool.Name != name {
			continue
		}
		if override.ResultInspection != nil {
			tool.ResultInspection = *override.ResultInspection
		}
		if override.JudgeResult != nil {
			tool.JudgeResult = *override.JudgeResult
		}
		if override.MinEntitiesForAlert > 0 {
			tool.MinEntitiesAlert = override.MinEntitiesForAlert
		}
		return
	}
	tool := SensitiveTool{Name: name, MinEntitiesAlert: override.MinEntitiesForAlert}
	if override.ResultInspection != nil {
		tool.ResultInspection = *override.ResultInspection
	}
	if override.JudgeResult != nil {
		tool.JudgeResult = *override.JudgeResult
	}
	rp.SensitiveTools.Tools = append(rp.SensitiveTools.Tools, tool)
}

// cloneRulePackForCompose copies every part Compose edits (rule files and
// their rules, suppressions, sensitive tools). Judge configurations and
// local patterns are read-only and stay shared.
func cloneRulePackForCompose(base *RulePack) *RulePack {
	out := &RulePack{JudgeConfigs: base.JudgeConfigs, LocalPatterns: base.LocalPatterns}
	if base.Suppressions != nil {
		supps := *base.Suppressions
		supps.PreJudgeStrips = append([]PreJudgeStrip(nil), base.Suppressions.PreJudgeStrips...)
		supps.FindingSupps = append([]FindingSuppression(nil), base.Suppressions.FindingSupps...)
		supps.ToolSuppressions = append([]ToolSuppression(nil), base.Suppressions.ToolSuppressions...)
		out.Suppressions = &supps
	}
	if base.SensitiveTools != nil {
		tools := *base.SensitiveTools
		tools.Tools = append([]SensitiveTool(nil), base.SensitiveTools.Tools...)
		out.SensitiveTools = &tools
	}
	out.RuleFiles = make([]*RulesFileYAML, 0, len(base.RuleFiles))
	for _, ruleFile := range base.RuleFiles {
		if ruleFile == nil {
			out.RuleFiles = append(out.RuleFiles, nil)
			continue
		}
		cloned := *ruleFile
		cloned.Rules = make([]RuleDefYAML, len(ruleFile.Rules))
		for index, rule := range ruleFile.Rules {
			if rule.Enabled != nil {
				enabled := *rule.Enabled
				rule.Enabled = &enabled
			}
			rule.Tags = append([]string(nil), rule.Tags...)
			cloned.Rules[index] = rule
		}
		out.RuleFiles = append(out.RuleFiles, &cloned)
	}
	return out
}

// ReadPackPosture returns the "posture" a rule-pack directory's manifest
// declares (default, strict or permissive), or "" when the manifest is
// absent, unreadable or names no known posture.
func ReadPackPosture(dir string) string {
	if strings.TrimSpace(dir) == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(dir, PackManifestFile))
	if err != nil || len(raw) > maxRulePackFileBytes {
		return ""
	}
	var manifest struct {
		Posture string `json:"posture"`
	}
	if json.Unmarshal(raw, &manifest) != nil {
		return ""
	}
	switch posture := strings.ToLower(strings.TrimSpace(manifest.Posture)); posture {
	case "default", "strict", "permissive":
		return posture
	default:
		return ""
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
