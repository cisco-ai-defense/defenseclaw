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
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// EvaluateAdmissionFallback is the Go twin of admission.rego, used only when
// OPA evaluation fails. It reads the same input (input.Admission, the
// asset_policy block/allow lists, the scan result) and returns the same
// verdict, reason and actions, so a Rego outage never changes a decision.
func EvaluateAdmissionFallback(input AdmissionInput) *AdmissionOutput {
	adm := input.Admission
	noScan := &AdmissionOutput{FileAction: "none", InstallAction: "none", RuntimeAction: "allow"}

	if listMatches(input.BlockList, input) {
		noScan.Verdict = "blocked"
		noScan.Reason = fmt.Sprintf("%s '%s' is on the block list", input.TargetType, input.TargetName)
		return noScan
	}
	allowListed := listMatches(input.AllowList, input)
	bypass := allowListed || (adm != nil && adm.AllowListBypassScan && firstPartyMatches(adm.FirstPartyAllowList, input))
	if bypass {
		noScan.Verdict = "allowed"
		noScan.Reason = fmt.Sprintf("%s '%s' is on the allow list — scan skipped", input.TargetType, input.TargetName)
		return noScan
	}

	scan := input.ScanResult
	if scan == nil {
		if adm != nil && !adm.ScanOnInstall {
			noScan.Verdict = "allowed"
			noScan.Reason = "scan_on_install disabled — allowed without scan"
			return noScan
		}
		noScan.Verdict = "scan"
		noScan.Reason = "awaiting scan"
		return noScan
	}

	// hardening (S2.scanners): a scanner failure is fail closed even when
	// the parsed findings list is empty.
	if scan.ExitCode != 0 || scan.ScanError != "" {
		return &AdmissionOutput{
			Verdict:       "rejected",
			Reason:        "scanner failed: " + scan.ScanError,
			FileAction:    "quarantine",
			InstallAction: "block",
			RuntimeAction: "block",
		}
	}
	if scan.TotalFindings == 0 {
		noScan.Verdict = "clean"
		noScan.Reason = "scan clean"
		return noScan
	}
	if scan.TotalFindings < 0 {
		// admission.rego matches neither 0 nor > 0, so it stays "scan".
		noScan.Verdict = "scan"
		noScan.Reason = "awaiting scan"
		return noScan
	}

	action := effectiveAction(adm, scan)
	out := &AdmissionOutput{FileAction: action.File, InstallAction: action.Install, RuntimeAction: action.Runtime}
	switch {
	case action.Runtime == "block" || action.Install == "block" || action.File == "quarantine":
		out.Verdict = "rejected"
		out.Reason = fmt.Sprintf("max severity %s triggers block per policy", scan.MaxSeverity)
	case action.Verdict == "allowed":
		out.Verdict = "allowed"
		out.Reason = fmt.Sprintf("findings present (max %s) — allowed by policy", scan.MaxSeverity)
	default:
		out.Verdict = "warning"
		out.Reason = fmt.Sprintf("findings present (max %s) — allowed with warning", scan.MaxSeverity)
	}
	return out
}

// effectiveAction mirrors admission.rego _effective_action: the scanner
// override, then the severity action, then fail closed.
func effectiveAction(adm *CompiledAdmission, scan *ScanResultInput) CompiledAction {
	sev := strings.ToUpper(scan.MaxSeverity)
	if adm != nil {
		if a, ok := adm.ScannerOverrides[scan.ScannerName][sev]; ok {
			return a
		}
		if a, ok := adm.Actions[sev]; ok {
			return a
		}
	}
	return CompiledAction{Install: "block", File: "none", Runtime: "block"}
}

// BlockListed reports whether the block list names this asset
// (admission.rego _is_blocked).
func (in AdmissionInput) BlockListed() bool { return listMatches(in.BlockList, in) }

// AllowListed reports whether the allow list names this asset at this path
// (admission.rego _is_explicit_allow_listed).
func (in AdmissionInput) AllowListed() bool { return listMatches(in.AllowList, in) }

func listMatches(entries []ListEntry, input AdmissionInput) bool {
	for _, entry := range entries {
		if entry.TargetType != input.TargetType || entry.TargetName != input.TargetName {
			continue
		}
		if entry.SourcePath == "" || config.PathHasComponents(input.Path, entry.SourcePath) {
			return true
		}
	}
	return false
}

func firstPartyMatches(entries []CompiledFirstParty, input AdmissionInput) bool {
	for _, entry := range entries {
		if entry.Name != input.TargetName {
			continue
		}
		for _, marker := range entry.SourcePathContains {
			if config.PathHasComponents(input.Path, marker) {
				return true
			}
		}
	}
	return false
}

func coalesceAction(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
