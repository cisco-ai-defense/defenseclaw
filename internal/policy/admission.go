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
	"encoding/json"
	"os"
	"path/filepath"
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
// object for every asset type (skill, mcp, plugin). Each field and
// each severity resolves, first match wins:
//
//	admission.<type>  >  (skill only) the scanner gate  >  admission.defaults  >  built-in
//
// The scanner gate is scanners.skill_scanner.fail_on_severity and
// review_queue_min with their effective defaults (HIGH and MEDIUM), the
// values setup, the TUI and doctor show: severities at or above the gate
// quarantine, [review_queue_min, gate) warn and lower ones allow. A nil
// first_party_allow_list inherits; an empty one clears the list. A severity
// nothing covers fails closed in Rego and the fallback.
//
// A Secure Client host keeps the 1.0 admission instead: see
// secureClientAdmission.
func CompileAdmission(cfg *config.Config) map[string]CompiledAdmission {
	if cfg != nil && cfg.SecureClientIntegration() {
		return secureClientAdmission(cfg.PolicyDir)
	}
	var adm config.AdmissionConfig
	if cfg != nil {
		adm = cfg.Admission
	}
	out := make(map[string]CompiledAdmission, 3)
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
			skill := cfg.Scanners.SkillScanner
			derived = derivedScannerGate(skill.EffectiveFailOnSeverity(), skill.EffectiveReviewQueueMin())
		}
		out[assetType] = compileAssetType(assetType, own, adm.Defaults, derived)
	}
	return out
}

// secureClientDataJSON is the admission part of the 1.0 policies data.json.
type secureClientDataJSON struct {
	Config struct {
		AllowListBypassScan *bool `json:"allow_list_bypass_scan"`
		ScanOnInstall       *bool `json:"scan_on_install"`
	} `json:"config"`
	Actions             map[string]CompiledAction            `json:"actions"`
	ScannerOverrides    map[string]map[string]CompiledAction `json:"scanner_overrides"`
	FirstPartyAllowList []struct {
		TargetType         string   `json:"target_type"`
		TargetName         string   `json:"target_name"`
		SourcePathContains []string `json:"source_path_contains"`
	} `json:"first_party_allow_list"`
	Guardrail struct {
		BlockThreshold  *int   `json:"block_threshold"`
		AlertThreshold  *int   `json:"alert_threshold"`
		CiscoTrustLevel string `json:"cisco_trust_level"`
	} `json:"guardrail"`
}

// readSecureClientDataJSON reads <policy_dir>/rego/data.json, else
// <policy_dir>/data.json; a missing or unreadable file is empty.
func readSecureClientDataJSON(policyDir string) secureClientDataJSON {
	var data secureClientDataJSON
	if dir := strings.TrimSpace(policyDir); dir != "" {
		for _, path := range []string{filepath.Join(dir, "rego", "data.json"), filepath.Join(dir, "data.json")} {
			raw, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if json.Unmarshal(raw, &data) != nil {
				data = secureClientDataJSON{}
			}
			break
		}
	}
	return data
}

// SecureClientGuardrailThresholds is the Secure Client input.thresholds of
// /v1/guardrail/evaluate, unchanged from 1.0: the data.json guardrail
// block_threshold, alert_threshold and cisco_trust_level (shipped 4, 2 and
// full), not block_at or the rule pack.
func SecureClientGuardrailThresholds(policyDir string) ThresholdsInput {
	g := readSecureClientDataJSON(policyDir).Guardrail
	out := ThresholdsInput{Block: 4, Alert: 2, CiscoTrustLevel: "full"}
	if g.BlockThreshold != nil {
		out.Block = *g.BlockThreshold
	}
	if g.AlertThreshold != nil {
		out.Alert = *g.AlertThreshold
	}
	if level := strings.TrimSpace(g.CiscoTrustLevel); level != "" {
		out.CiscoTrustLevel = level
	}
	return out
}

// secureClientAdmission is the Secure Client admission, unchanged from 1.0
// (spec section 10): a Secure Client config stays config_version 8 with no
// admission block, so the actions, per-type overrides, first-party list and
// scan flags come from <policy_dir>/rego/data.json (or <policy_dir>/data.json)
// when it is there, over the shipped defaults, with no scanner-gate
// derivation. Its actions carry no verdict, so a finding below the block
// level is a warning, as it was.
func secureClientAdmission(policyDir string) map[string]CompiledAdmission {
	data := readSecureClientDataJSON(policyDir)
	out := make(map[string]CompiledAdmission, 3)
	for _, assetType := range []string{config.AdmissionTypeSkill, config.AdmissionTypeMCP, config.AdmissionTypePlugin} {
		c := builtinAdmission(assetType)
		c.ScanOnInstall = firstBool(c.ScanOnInstall, data.Config.ScanOnInstall)
		c.AllowListBypassScan = firstBool(c.AllowListBypassScan, data.Config.AllowListBypassScan)
		if len(data.Actions) > 0 {
			c.Actions = map[string]CompiledAction{}
			for sev, a := range data.Actions {
				c.Actions[strings.ToUpper(sev)] = a
			}
			for sev, a := range data.ScannerOverrides[assetType] {
				c.Actions[strings.ToUpper(sev)] = a
			}
			c.Source = "data.json"
		}
		if data.FirstPartyAllowList != nil {
			c.FirstPartyAllowList = nil
			for _, entry := range data.FirstPartyAllowList {
				if entry.TargetType == assetType {
					c.FirstPartyAllowList = append(c.FirstPartyAllowList, CompiledFirstParty{
						Name: entry.TargetName, SourcePathContains: append([]string(nil), entry.SourcePathContains...),
					})
				}
			}
		}
		out[assetType] = c
	}
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

// AssetPolicyListsFor returns the input.block_list and input.allow_list for
// one asset from asset_policy.<type>.denied/allowed, the only operator
// block/allow source. The lists are decided by config.AssetListDecision, the
// resolver the CLI and the REST API use: a rule scoped to the connector
// decides before an unscoped one (so a connector-scoped allow overrides a
// global deny), denied wins at the same scope, a pinned allow matches only
// its source path, and a rule without a name (an MCP server matched on URL
// or command) counts. The decided rule becomes the single entry, named for
// the asset, so Rego and the fallback reach the same verdict as Python.
func AssetPolicyListsFor(cfg *config.Config, in config.AssetPolicyInput) (block, allow []ListEntry) {
	if cfg == nil {
		return nil, nil
	}
	verdict, rule := cfg.AssetListDecision(in)
	entry := []ListEntry{{
		TargetType: strings.ToLower(strings.TrimSpace(in.TargetType)), TargetName: in.Name,
		Reason: rule.Reason, Connector: strings.TrimSpace(rule.Connector),
	}}
	switch verdict {
	case config.AssetListDeny:
		return entry, nil
	case config.AssetListAllow:
		return nil, entry
	}
	return nil, nil
}
