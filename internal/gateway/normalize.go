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
	"strings"
)

// NormalizedFinding is a stable, scanner-agnostic representation of a
// guardrail finding. Different scanners produce findings in different
// formats; normalization ensures consistent IDs, severities, and
// categories for downstream consumers (audit, telemetry, policy).
type NormalizedFinding struct {
	CanonicalID string `json:"canonical_id"`
	Source      string `json:"source"`
	OriginalID  string `json:"original_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Confidence  float64 `json:"confidence,omitempty"`
}

// Category constants for normalized findings.
const (
	CatPromptInjection = "prompt-injection"
	CatPIIExposure     = "pii-exposure"
	CatCredentialLeak  = "credential-leak"
	CatDangerousExec   = "dangerous-execution"
	CatDataExfil       = "data-exfiltration"
	CatCognitiveTamper = "cognitive-tampering"
	CatSystemFile      = "system-file-access"
	CatSSRF            = "ssrf"
	CatGeneral         = "general"
)

// NormalizeScanVerdict converts a ScanVerdict with raw findings into a
// slice of NormalizedFindings with stable canonical IDs.
func NormalizeScanVerdict(v *ScanVerdict) []NormalizedFinding {
	if v == nil || len(v.Findings) == 0 {
		return nil
	}

	source := v.Scanner
	if source == "" && len(v.ScannerSources) > 0 {
		source = strings.Join(v.ScannerSources, "+")
	}
	if source == "" {
		source = "unknown"
	}

	var out []NormalizedFinding
	for _, raw := range v.Findings {
		nf := normalizeFindingString(raw, source, v.Severity)
		out = append(out, nf)
	}
	return out
}

// NormalizeRuleFindings converts structured RuleFindings to normalized form.
func NormalizeRuleFindings(findings []RuleFinding, source string) []NormalizedFinding {
	if len(findings) == 0 {
		return nil
	}

	out := make([]NormalizedFinding, 0, len(findings))
	for _, f := range findings {
		nf := NormalizedFinding{
			CanonicalID: canonicalIDFromRuleID(f.RuleID),
			Source:      source,
			OriginalID:  f.RuleID,
			Category:    categoryFromTags(f.Tags),
			Severity:    normalizeSeverity(f.Severity),
			Title:       f.Title,
			Confidence:  f.Confidence,
		}
		out = append(out, nf)
	}
	return out
}

// normalizeFindingString maps a raw finding string (from ScanVerdict.Findings)
// to a NormalizedFinding. Raw findings can be:
//   - Rule IDs like "SEC-AWS-KEY:AWS access key"
//   - Judge finding IDs like "JUDGE-INJ-INSTRUCT"
//   - Free-form strings like "pii-data:123-45-6789" or "ignore previous"
func normalizeFindingString(raw, source, verdictSeverity string) NormalizedFinding {
	nf := NormalizedFinding{
		Source:     source,
		OriginalID: raw,
		Severity:   normalizeSeverity(verdictSeverity),
	}

	// Split "RULE-ID:Title" format
	parts := strings.SplitN(raw, ":", 2)
	id := parts[0]
	if len(parts) > 1 {
		nf.Title = parts[1]
	}

	nf.CanonicalID = canonicalIDFromRuleID(id)
	nf.Category = categoryFromFindingID(id)

	return nf
}

// canonicalIDFromRuleID maps a scanner-specific rule ID to a stable
// canonical ID suitable for cross-scanner correlation.
func canonicalIDFromRuleID(ruleID string) string {
	upper := strings.ToUpper(ruleID)

	// Already in canonical form (prefixed with a known category)
	for _, prefix := range []string{"SEC-", "CMD-", "PATH-", "C2-", "COG-", "TRUST-", "JUDGE-"} {
		if strings.HasPrefix(upper, prefix) {
			return upper
		}
	}

	// Cisco AI Defense finding IDs
	if strings.HasPrefix(upper, "CISCO-") || strings.HasPrefix(upper, "AID-") {
		return "CISCO-" + strings.TrimPrefix(strings.TrimPrefix(upper, "CISCO-"), "AID-")
	}

	// Local pattern match strings: map to canonical
	lower := strings.ToLower(ruleID)
	switch {
	case lower == "pii-data" || strings.HasPrefix(lower, "pii-data:"):
		return "LP-PII-DATA"
	case lower == "pii-request" || strings.HasPrefix(lower, "pii-request:"):
		return "LP-PII-REQUEST"
	case strings.Contains(lower, "ignore") && strings.Contains(lower, "instruct"):
		return "LP-INJ-IGNORE"
	case strings.Contains(lower, "jailbreak") || strings.Contains(lower, "dan mode"):
		return "LP-INJ-JAILBREAK"
	case strings.HasPrefix(lower, "sk-") || strings.HasPrefix(lower, "ghp_") || strings.HasPrefix(lower, "bearer"):
		return "LP-SECRET-MATCH"
	case strings.Contains(lower, "/etc/"):
		return "LP-SYSTEM-FILE"
	case strings.Contains(lower, "exfiltrate") || strings.Contains(lower, "base64"):
		return "LP-EXFIL"
	}

	return "UNKNOWN-" + strings.ReplaceAll(upper, " ", "-")
}

// categoryFromTags derives a normalized category from rule tags.
func categoryFromTags(tags []string) string {
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[t] = true
	}

	switch {
	case tagSet["prompt-injection"]:
		return CatPromptInjection
	case tagSet["credential"]:
		return CatCredentialLeak
	case tagSet["reverse-shell"] || tagSet["execution"] || tagSet["destructive"]:
		return CatDangerousExec
	case tagSet["exfiltration"] || tagSet["c2"] || tagSet["dns-tunnel"]:
		return CatDataExfil
	case tagSet["cognitive-tampering"]:
		return CatCognitiveTamper
	case tagSet["system-file"] || tagSet["file-sensitive"]:
		return CatSystemFile
	case tagSet["ssrf"]:
		return CatSSRF
	default:
		return CatGeneral
	}
}

// categoryFromFindingID derives the category from a finding ID prefix.
func categoryFromFindingID(id string) string {
	upper := strings.ToUpper(id)
	switch {
	case strings.HasPrefix(upper, "SEC-"):
		return CatCredentialLeak
	case strings.HasPrefix(upper, "CMD-"):
		return CatDangerousExec
	case strings.HasPrefix(upper, "PATH-"):
		return CatSystemFile
	case strings.HasPrefix(upper, "C2-"):
		return CatDataExfil
	case strings.HasPrefix(upper, "COG-"):
		return CatCognitiveTamper
	case strings.HasPrefix(upper, "TRUST-"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "JUDGE-INJ"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "JUDGE-PII"):
		return CatPIIExposure
	case strings.HasPrefix(upper, "JUDGE-TOOL-INJ"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "LP-PII"):
		return CatPIIExposure
	case strings.HasPrefix(upper, "LP-INJ"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "LP-SECRET"):
		return CatCredentialLeak
	case strings.HasPrefix(upper, "LP-EXFIL"):
		return CatDataExfil
	case strings.HasPrefix(upper, "LP-SYSTEM"):
		return CatSystemFile
	default:
		return CatGeneral
	}
}

// normalizeSeverity ensures severity values are in the canonical set.
func normalizeSeverity(sev string) string {
	upper := strings.ToUpper(strings.TrimSpace(sev))
	switch upper {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return upper
	case "CRIT":
		return "CRITICAL"
	case "MED":
		return "MEDIUM"
	case "INFO", "INFORMATIONAL":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
