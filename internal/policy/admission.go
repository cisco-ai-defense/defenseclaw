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

package policy

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// AdmissionSeverities are the severities CompiledAdmission.Actions is keyed
// by, most severe first.
var AdmissionSeverities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// Admission action sources reported in CompiledAdmission.Source.
const (
	AdmissionSourceBuiltin = "builtin"
	AdmissionSourceDerived = "derived:scanners.skill_scanner"
)

var (
	actionQuarantine = CompiledAction{Install: "block", File: "quarantine", Runtime: "block"}
	actionWarn       = CompiledAction{Install: "none", File: "none", Runtime: "allow"}
	actionAllow      = CompiledAction{Install: "none", File: "none", Runtime: "allow", Verdict: "allowed"}
)

// builtinAdmission is what applies where config.yaml sets nothing: the
// admission defaults that shipped in policies/rego/data.json up to 1.0.
func builtinAdmission(assetType string) CompiledAdmission {
	out := CompiledAdmission{
		ScanOnInstall:       true,
		AllowListBypassScan: true,
		Actions: map[string]CompiledAction{
			"CRITICAL": actionQuarantine, "HIGH": actionQuarantine,
			"MEDIUM": actionWarn, "LOW": actionWarn, "INFO": actionWarn,
		},
		Source: AdmissionSourceBuiltin,
	}
	switch assetType {
	case config.AdmissionTypeSkill:
		out.FirstPartyAllowList = []CompiledFirstParty{{Name: "codeguard", SourcePathContains: []string{
			".openclaw/workspace/skills/codeguard", ".openclaw/skills/codeguard",
			".zeptoclaw/skills/codeguard", ".claude/skills/codeguard",
		}}}
	case config.AdmissionTypeMCP:
		out.Actions["MEDIUM"] = actionQuarantine
		out.Actions["LOW"] = CompiledAction{Install: "none", File: "none", Runtime: "block"}
	case config.AdmissionTypePlugin:
		out.Actions["HIGH"] = actionQuarantine
		out.FirstPartyAllowList = []CompiledFirstParty{{Name: "defenseclaw", SourcePathContains: []string{
			".openclaw/extensions/defenseclaw", ".zeptoclaw/extensions/defenseclaw",
			".claude/extensions/defenseclaw", ".codex/extensions/defenseclaw",
			".config/amp/plugins/defenseclaw.ts",
		}}}
	}
	return out
}

// CompileAdmission compiles config admission: into the input.admission
// object for every asset type (skill, mcp, plugin, tool). Each field and
// each severity resolves, first match wins:
//
//	admission.<type>  >  (skill only) the scanner gate  >  admission.defaults  >  built-in
//
// The scanner gate applies when scanners.skill_scanner.fail_on_severity is
// set: severities at or above it quarantine, [review_queue_min, gate) warn
// and lower ones allow (review_queue_min unset means every lower severity
// warns). A nil first_party_allow_list inherits; an empty one clears the
// list. A severity nothing covers fails closed in Rego and the fallback.
func CompileAdmission(cfg *config.Config) map[string]CompiledAdmission {
	var adm config.AdmissionConfig
	if cfg != nil {
		adm = cfg.Admission
	}
	out := make(map[string]CompiledAdmission, 4)
	for _, assetType := range []string{config.AdmissionTypeSkill, config.AdmissionTypeMCP, config.AdmissionTypePlugin} {
		var own config.AdmissionAssetType
		switch assetType {
		case config.AdmissionTypeSkill:
			own = adm.Skill
		case config.AdmissionTypeMCP:
			own = adm.MCP
		case config.AdmissionTypePlugin:
			own = adm.Plugin
		}
		var derived map[string]CompiledAction
		if assetType == config.AdmissionTypeSkill && cfg != nil {
			derived = derivedScannerGate(cfg.Scanners.SkillScanner.FailOnSeverity, cfg.Scanners.SkillScanner.ReviewQueueMin)
		}
		out[assetType] = compileAssetType(assetType, own, adm.Defaults, derived)
	}
	tool := compileAssetType(config.AdmissionTypeTool, config.AdmissionAssetType{
		Actions:          adm.Tool.Actions,
		ScannerOverrides: adm.Tool.ScannerOverrides,
	}, adm.Defaults, nil)
	out[config.AdmissionTypeTool] = tool
	return out
}

// AdmissionFor returns the compiled admission for one asset type, for use
// as AdmissionInput.Admission. An unknown type gets nil (fail closed).
func AdmissionFor(compiled map[string]CompiledAdmission, assetType string) *CompiledAdmission {
	c, ok := compiled[strings.ToLower(strings.TrimSpace(assetType))]
	if !ok {
		return nil
	}
	return &c
}

func compileAssetType(assetType string, own, defaults config.AdmissionAssetType, derived map[string]CompiledAction) CompiledAdmission {
	out := builtinAdmission(assetType)
	out.ScanOnInstall = firstBool(out.ScanOnInstall, own.ScanOnInstall, defaults.ScanOnInstall)
	out.AllowListBypassScan = firstBool(out.AllowListBypassScan, own.AllowListBypassScan, defaults.AllowListBypassScan)

	ownActions, defaultActions := compileActionMap(own.Actions), compileActionMap(defaults.Actions)
	usedOwn, usedDerived, usedDefaults := false, false, false
	for _, sev := range AdmissionSeverities {
		if a, ok := ownActions[sev]; ok {
			out.Actions[sev], usedOwn = a, true
		} else if a, ok := derived[sev]; ok {
			out.Actions[sev], usedDerived = a, true
		} else if a, ok := defaultActions[sev]; ok {
			out.Actions[sev], usedDefaults = a, true
		}
	}
	switch {
	case usedOwn:
		out.Source = "config:admission." + assetType + ".actions"
	case usedDerived:
		out.Source = AdmissionSourceDerived
	case usedDefaults:
		out.Source = "config:admission.defaults.actions"
	}

	for _, layer := range []map[string]config.AdmissionActionMap{defaults.ScannerOverrides, own.ScannerOverrides} {
		for scanner, actions := range layer {
			compiled := compileActionMap(actions)
			if len(compiled) == 0 {
				continue
			}
			if out.ScannerOverrides == nil {
				out.ScannerOverrides = map[string]map[string]CompiledAction{}
			}
			name := strings.TrimSpace(scanner)
			if out.ScannerOverrides[name] == nil {
				out.ScannerOverrides[name] = map[string]CompiledAction{}
			}
			for sev, a := range compiled {
				out.ScannerOverrides[name][sev] = a
			}
		}
	}

	if list := firstParty(own.FirstPartyAllowList, defaults.FirstPartyAllowList); list != nil {
		out.FirstPartyAllowList = list
	}
	if assetType == config.AdmissionTypeTool {
		// Tool definitions have no install event or on-disk provenance.
		out.FirstPartyAllowList = nil
	}
	return out
}

func firstBool(fallback bool, values ...*bool) bool {
	for _, v := range values {
		if v != nil {
			return *v
		}
	}
	return fallback
}

func firstParty(lists ...[]config.AdmissionFirstParty) []CompiledFirstParty {
	for _, list := range lists {
		if list == nil {
			continue
		}
		out := make([]CompiledFirstParty, 0, len(list))
		for _, entry := range list {
			out = append(out, CompiledFirstParty{Name: entry.Name, SourcePathContains: append([]string(nil), entry.SourcePathContains...)})
		}
		return out
	}
	return nil
}

func compileActionMap(m config.AdmissionActionMap) map[string]CompiledAction {
	out := map[string]CompiledAction{}
	for sev, action := range map[string]*config.AdmissionAction{
		"CRITICAL": m.Critical, "HIGH": m.High, "MEDIUM": m.Medium, "LOW": m.Low, "INFO": m.Info,
	} {
		if action != nil {
			out[sev] = compileAction(*action)
		}
	}
	return out
}

// compileAction expands a shorthand or triple into Rego spelling: install
// block|none|allow, file quarantine|none, runtime block|allow.
func compileAction(a config.AdmissionAction) CompiledAction {
	triple := a.Expand()
	out := CompiledAction{
		Install: coalesceAction(string(triple.Install), "none"),
		File:    coalesceAction(string(triple.File), "none"),
		Runtime: "allow",
	}
	if triple.Runtime == config.RuntimeDisable {
		out.Runtime = "block"
	}
	if a.Shorthand == config.AdmissionActionAllow {
		out.Verdict = "allowed"
	}
	return out
}

// severityRank orders AdmissionSeverities (CRITICAL=5 ... INFO=1); 0 is
// unknown.
func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

// derivedScannerGate maps the scanner gate onto an action map, or nil when
// no gate is configured.
func derivedScannerGate(failOn, reviewMin string) map[string]CompiledAction {
	gate := severityRank(failOn)
	if gate == 0 {
		return nil
	}
	review := severityRank(reviewMin)
	if review == 0 || review > gate {
		review = 1
	}
	out := make(map[string]CompiledAction, len(AdmissionSeverities))
	for _, sev := range AdmissionSeverities {
		switch rank := severityRank(sev); {
		case rank >= gate:
			out[sev] = actionQuarantine
		case rank >= review:
			out[sev] = actionWarn
		default:
			out[sev] = actionAllow
		}
	}
	return out
}

// AssetPolicyLists returns the input.block_list and input.allow_list entries
// for one asset type from asset_policy.<type>.denied/allowed: the only
// operator block/allow source. Rules scoped to another connector are left
// out; a rule without a name (matched on URL, command or path alone) is
// decided by config.EvaluateAssetPolicy instead. A rule pinned with
// source_path_contains yields one entry per path, so admission.rego matches
// the pin as path components.
func AssetPolicyLists(cfg *config.Config, assetType, connector string) (block, allow []ListEntry) {
	if cfg == nil {
		return nil, nil
	}
	var p config.AssetTypePolicy
	switch strings.ToLower(strings.TrimSpace(assetType)) {
	case config.AdmissionTypeSkill:
		p = cfg.AssetPolicy.Skill
	case config.AdmissionTypeMCP:
		p = cfg.AssetPolicy.MCP
	case config.AdmissionTypePlugin:
		p = cfg.AssetPolicy.Plugin
	default:
		return nil, nil
	}
	return listEntries(p.Denied, assetType, connector), listEntries(p.Allowed, assetType, connector)
}

func listEntries(rules []config.AssetPolicyRule, assetType, connector string) []ListEntry {
	var out []ListEntry
	for _, rule := range rules {
		name := strings.TrimSpace(rule.Name)
		if name == "" {
			continue
		}
		if rc := strings.TrimSpace(rule.Connector); rc != "" && !config.SameConnector(rc, connector) {
			continue
		}
		base := ListEntry{TargetType: assetType, TargetName: name, Reason: rule.Reason, Connector: strings.TrimSpace(rule.Connector)}
		if len(rule.SourcePathContains) == 0 {
			out = append(out, base)
			continue
		}
		for _, path := range rule.SourcePathContains {
			entry := base
			entry.SourcePath = path
			out = append(out, entry)
		}
	}
	return out
}
