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
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The Secure Client profile keeps the policy engine of 1.0 (issue #1092).
// That engine needed <policy_dir>/data.json, which no Secure Client layout
// ships, so every load failed and admission used the built-in fallback
// below. These functions keep those answers byte for byte.

// SecureClientPolicyLoadError is the error the 1.0 engine reported when it
// loaded policyDir, or nil when its data.json is readable JSON.
func SecureClientPolicyLoadError(policyDir string) error {
	dir := resolveRegoDir(policyDir)
	raw, err := os.ReadFile(filepath.Join(dir, "rego", "data.json"))
	if err != nil {
		raw, err = os.ReadFile(filepath.Join(dir, "data.json"))
	}
	if err != nil {
		return fmt.Errorf("policy: read data.json: %w", err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return fmt.Errorf("policy: parse data.json: %w", err)
	}
	return nil
}

// LoadSecureClientData is the 1.0 policy show data: exactly
// <regoDir>/data.json with <regoDir>/data-sandbox.json merged over it.
func LoadSecureClientData(regoDir string) (map[string]interface{}, error) {
	data, err := readSecureClientJSONObject(filepath.Join(regoDir, "data.json"), "data.json")
	if err != nil {
		return nil, err
	}
	extra, err := readSecureClientJSONObject(filepath.Join(regoDir, "data-sandbox.json"), "data-sandbox.json")
	if os.IsNotExist(err) {
		return data, nil
	}
	if err != nil {
		return nil, err
	}
	for key, value := range extra {
		data[key] = value
	}
	return data, nil
}

func readSecureClientJSONObject(path, name string) (map[string]interface{}, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) && name != "data.json" {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", name, err)
	}
	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", name, err)
	}
	if data == nil {
		return nil, fmt.Errorf("policy: parse %s: top-level value must be an object", name)
	}
	return data, nil
}

type secureClientFirstPartyEntry struct {
	reason string
	paths  []string
}

// secureClientFallbackProfile is the 1.0 fallback profile: the shipped
// defaults with the data.json of policyDir over them, when there is one.
type secureClientFallbackProfile struct {
	allowListBypassScan bool
	scanOnInstall       bool
	actions             map[string]CompiledAction
	overrides           map[string]map[string]CompiledAction
	firstParty          map[string]secureClientFirstPartyEntry
}

func loadSecureClientFallbackProfile(policyDir string) secureClientFallbackProfile {
	p := secureClientFallbackProfile{
		allowListBypassScan: true,
		scanOnInstall:       true,
		actions: map[string]CompiledAction{
			"CRITICAL": actionQuarantine, "HIGH": actionQuarantine,
			"MEDIUM": actionWarn, "LOW": actionWarn, "INFO": actionWarn,
		},
		overrides: map[string]map[string]CompiledAction{
			"mcp":    {"MEDIUM": actionQuarantine, "LOW": {Install: "none", File: "none", Runtime: "block"}},
			"plugin": {"HIGH": actionQuarantine, "MEDIUM": actionWarn},
		},
		firstParty: map[string]secureClientFirstPartyEntry{
			"plugin\x00defenseclaw": {reason: "first-party DefenseClaw plugin",
				paths: []string{".defenseclaw", "extensions/defenseclaw", ".config/amp/plugins/defenseclaw.ts"}},
			"skill\x00codeguard": {reason: "first-party DefenseClaw skill",
				paths: []string{".defenseclaw", "workspace/skills/codeguard", "skills/codeguard"}},
		},
	}
	if strings.TrimSpace(policyDir) == "" {
		return p
	}
	data := readSecureClientDataJSON(policyDir)
	if data.Config.AllowListBypassScan != nil {
		p.allowListBypassScan = *data.Config.AllowListBypassScan
	}
	if data.Config.ScanOnInstall != nil {
		p.scanOnInstall = *data.Config.ScanOnInstall
	}
	for sev, action := range data.Actions {
		p.actions[strings.ToUpper(sev)] = action
	}
	for targetType, overrides := range data.ScannerOverrides {
		target := map[string]CompiledAction{}
		for sev, action := range overrides {
			target[strings.ToUpper(sev)] = action
		}
		p.overrides[targetType] = target
	}
	for _, entry := range data.FirstPartyAllowList {
		if entry.TargetType == "" || entry.TargetName == "" {
			continue
		}
		p.firstParty[entry.TargetType+"\x00"+entry.TargetName] = secureClientFirstPartyEntry{
			reason: entry.Reason, paths: entry.SourcePathContains,
		}
	}
	return p
}

// EvaluateSecureClientAdmission is the 1.0 admission fallback of a Secure
// Client host, unchanged: list entries and first-party skips answer with
// their reason and no actions, a severity the profile does not name (NONE)
// is a warning, and a scanner failure reason keeps its exit code.
func EvaluateSecureClientAdmission(input AdmissionInput, policyDir string) *AdmissionOutput {
	p := loadSecureClientFallbackProfile(policyDir)
	if ok, reason := secureClientListReason(input.BlockList, input); ok {
		return &AdmissionOutput{Verdict: "blocked", Reason: reason}
	}
	if ok, reason := secureClientListReason(input.AllowList, input); ok {
		return &AdmissionOutput{Verdict: "allowed", Reason: reason}
	}
	if p.allowListBypassScan {
		if entry, ok := p.firstParty[input.TargetType+"\x00"+input.TargetName]; ok && secureClientPathMatches(entry.paths, input.Path) {
			reason := entry.reason
			if reason == "" {
				reason = fmt.Sprintf("%s '%s' is on the allow list — scan skipped", input.TargetType, input.TargetName)
			}
			return &AdmissionOutput{Verdict: "allowed", Reason: reason}
		}
	}

	scan := input.ScanResult
	if scan == nil {
		if !p.scanOnInstall {
			return &AdmissionOutput{Verdict: "allowed", Reason: "scan_on_install disabled — allowed without scan"}
		}
		return &AdmissionOutput{Verdict: "scan", Reason: "scan required"}
	}
	if scan.ExitCode != 0 || strings.TrimSpace(scan.ScanError) != "" {
		reason := "scanner failed"
		if scan.ScanError != "" {
			reason = "scanner failed: " + scan.ScanError
		}
		if scan.ExitCode != 0 {
			reason = fmt.Sprintf("%s (exit_code=%d)", reason, scan.ExitCode)
		}
		return &AdmissionOutput{Verdict: "rejected", Reason: reason, FileAction: "quarantine", InstallAction: "block", RuntimeAction: "block"}
	}

	severity := strings.ToUpper(scan.MaxSeverity)
	if severity == "" {
		severity = "INFO"
	}
	action, ok := p.overrides[input.TargetType][severity]
	if !ok {
		action = p.actions[severity]
	}
	out := &AdmissionOutput{
		FileAction:    coalesceAction(action.File, "none"),
		InstallAction: coalesceAction(action.Install, "none"),
		RuntimeAction: coalesceAction(action.Runtime, "allow"),
	}
	switch {
	case scan.TotalFindings <= 0:
		out.Verdict, out.Reason = "clean", "scan clean"
	case action.Runtime == "block" || action.Install == "block":
		out.Verdict, out.Reason = "rejected", fmt.Sprintf("max severity %s triggers block per policy", severity)
	default:
		out.Verdict, out.Reason = "warning", fmt.Sprintf("findings present (max %s) — allowed with warning", severity)
	}
	return out
}

func secureClientListReason(entries []ListEntry, input AdmissionInput) (bool, string) {
	for _, entry := range entries {
		if entry.TargetType == input.TargetType && entry.TargetName == input.TargetName {
			if entry.Reason != "" {
				return true, entry.Reason
			}
			return true, fmt.Sprintf("%s '%s' is on the allow/block list", input.TargetType, input.TargetName)
		}
	}
	return false, ""
}

// secureClientPathMatches is the 1.0 provenance check: no constraint
// matches, else a case-insensitive substring of the slash path.
func secureClientPathMatches(constraints []string, path string) bool {
	if len(constraints) == 0 {
		return true
	}
	if path == "" {
		return false
	}
	normalised := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))
	for _, c := range constraints {
		if strings.Contains(normalised, strings.ToLower(c)) {
			return true
		}
	}
	return false
}
