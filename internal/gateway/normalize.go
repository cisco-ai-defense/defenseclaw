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
	CanonicalID string  `json:"canonical_id"`
	Source      string  `json:"source"`
	OriginalID  string  `json:"original_id"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Confidence  float64 `json:"confidence,omitempty"`
	// Evidence retains the source-backed local match until the audit logger's
	// persistence boundary can classify and redact it and derive an
	// installation-keyed correlation fingerprint. It must never become part of
	// a normalized identity or be serialized as normalizer metadata.
	Evidence string `json:"-"`
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

	localCredentialFindingTitle = "Local credential pattern match"
	localInjectionFindingTitle  = "Local prompt injection pattern match"
	localPIIFindingTitle        = "Local PII pattern match"
)

// canonicalRuleIDPrefixes lists scanner rule-ID prefixes that already carry
// a stable identity. canonicalStructuredRuleID and canonicalIDFromRuleID must
// use the same set so the structured and fallback paths cannot disagree.
var canonicalRuleIDPrefixes = [...]string{
	"SEC-", "CS-SEC-", "SECRET-", "JSON-SEC-", "CRED-",
	"CMD-", "PATH-", "C2-", "COG-", "TRUST-", "INJ-", "OBFUSC-",
	"PII-", "CS-PII-", "ENT-", "JUDGE-", "LP-",
}

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
		category := categoryFromTags(f.Tags)
		if _, ok := canonicalDottedRuleID(f.RuleID); ok {
			category = categoryFromFindingID(f.RuleID)
		}
		nf := NormalizedFinding{
			CanonicalID: canonicalIDFromRuleID(f.RuleID),
			Source:      source,
			OriginalID:  f.RuleID,
			Category:    category,
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
		Source:   source,
		Severity: normalizeSeverity(verdictSeverity),
	}

	// Split "RULE-ID:Title" format
	parts := strings.SplitN(raw, ":", 2)
	id := strings.TrimSpace(parts[0])
	structuredTitle := ""
	if len(parts) > 1 {
		structuredTitle = strings.TrimSpace(parts[1])
	}
	localPatternSource := sourceIncludesScanner(source, "local-pattern")
	// Local-pattern findings are raw matched substrings, not trusted catalog
	// identities. Classify them before accepting any canonical-looking prefix;
	// otherwise a directive beginning with TRUST-/LP-/PII- could become its own
	// persisted RuleID.
	if localPatternSource {
		if activeLocalPatternRuleIdentity(id, structuredTitle) {
			canonicalID := canonicalIDFromRuleID(id)
			nf.CanonicalID = canonicalID
			nf.OriginalID = id
			nf.Category = categoryFromFindingID(canonicalID)
			nf.Title = structuredTitle
			return nf
		}
		if local, ok := normalizeSensitiveLocalPatternFinding(raw, source, nf.Severity); ok {
			return local
		}
		return normalizeUntrustedLocalPatternFinding(raw, id, source, nf.Severity)
	}
	// Catalog and scanner rule IDs are already inert identities. Keep their
	// precise rule metadata instead of mistaking a static title for a local raw
	// pattern match. OriginalID deliberately excludes the free-form title.
	if canonicalID, ok := canonicalStructuredRuleID(id); ok {
		nf.CanonicalID = canonicalID
		nf.OriginalID = id
		nf.Category = categoryFromFindingID(canonicalID)
		if len(parts) > 1 {
			nf.Title = strings.TrimSpace(parts[1])
		}
		return nf
	}

	nf.OriginalID = raw
	if len(parts) > 1 {
		nf.Title = parts[1]
	}

	nf.CanonicalID = canonicalIDFromRuleID(id)
	nf.Category = categoryFromFindingID(id)

	return nf
}

func activeLocalPatternRuleIdentity(ruleID, title string) bool {
	ruleID = strings.ToUpper(strings.TrimSpace(ruleID))
	title = strings.TrimSpace(title)
	if ruleID == "" || title == "" {
		return false
	}
	ruleCategoriesMu.RLock()
	titles := allRuleGeneration.ruleIdentityTitles[ruleID]
	_, present := titles[title]
	ruleCategoriesMu.RUnlock()
	return present
}

func normalizeUntrustedLocalPatternFinding(raw, apparentID, source, severity string) NormalizedFinding {
	upperID := strings.ToUpper(strings.TrimSpace(apparentID))
	switch {
	case strings.HasPrefix(upperID, "TRUST-"), strings.HasPrefix(upperID, "INJ-"),
		strings.HasPrefix(upperID, "OBFUSC-"), strings.HasPrefix(upperID, "LP-INJ-"):
		return normalizedSensitiveLocalFinding(
			"LP-INJ-MATCH", CatPromptInjection, localInjectionFindingTitle, raw, source, severity,
		)
	case strings.HasPrefix(upperID, "SEC-"), strings.HasPrefix(upperID, "CS-SEC-"),
		strings.HasPrefix(upperID, "SECRET-"), strings.HasPrefix(upperID, "JSON-SEC-"),
		strings.HasPrefix(upperID, "CRED-"), strings.HasPrefix(upperID, "LP-SECRET-"):
		return normalizedSensitiveLocalFinding(
			"LP-SECRET-MATCH", CatCredentialLeak, localCredentialFindingTitle, raw, source, severity,
		)
	case strings.HasPrefix(upperID, "PII-"), strings.HasPrefix(upperID, "CS-PII-"),
		strings.HasPrefix(upperID, "LP-PII-"):
		return normalizedSensitiveLocalFinding(
			"LP-PII-DATA", CatPIIExposure, localPIIFindingTitle, raw, source, severity,
		)
	}

	// Preserve only fixed local classifications whose identities do not include
	// source bytes. Everything else receives a generic stable ID and keeps the
	// raw match solely in the audit-redaction evidence channel.
	canonicalID := canonicalLocalPatternFindingID(raw)
	switch canonicalID {
	case "LP-INJ-IGNORE", "LP-INJ-JAILBREAK":
		return normalizedSensitiveLocalFinding(
			canonicalID, CatPromptInjection, localInjectionFindingTitle, raw, source, severity,
		)
	case "LP-SECRET-MATCH":
		return normalizedSensitiveLocalFinding(
			canonicalID, CatCredentialLeak, localCredentialFindingTitle, raw, source, severity,
		)
	case "LP-SYSTEM-FILE":
		return normalizedSensitiveLocalFinding(
			canonicalID, CatSystemFile, "Local system file pattern match", raw, source, severity,
		)
	case "LP-EXFIL":
		return normalizedSensitiveLocalFinding(
			canonicalID, CatDataExfil, "Local exfiltration pattern match", raw, source, severity,
		)
	default:
		return normalizedSensitiveLocalFinding(
			"LP-MATCH", CatGeneral, "Local pattern match", raw, source, severity,
		)
	}
}

func sourceIncludesScanner(source, scannerName string) bool {
	for _, candidate := range strings.Split(source, "+") {
		if strings.EqualFold(strings.TrimSpace(candidate), scannerName) {
			return true
		}
	}
	return false
}

func canonicalStructuredRuleID(ruleID string) (string, bool) {
	trimmed := strings.TrimSpace(ruleID)
	// These are local scanner framing labels whose suffix is the matched value,
	// not catalog rule IDs. They must flow through sensitive-value handling.
	switch strings.ToLower(trimmed) {
	case "pii-data", "pii-request":
		return "", false
	}
	if canonical, ok := canonicalDottedRuleID(trimmed); ok {
		return canonical, true
	}
	upper := strings.ToUpper(trimmed)
	for _, prefix := range canonicalRuleIDPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return canonicalIDFromRuleID(trimmed), true
		}
	}
	if strings.HasPrefix(upper, "CISCO-") || strings.HasPrefix(upper, "AID-") {
		return canonicalIDFromRuleID(trimmed), true
	}
	return "", false
}

func normalizeSensitiveLocalPatternFinding(raw, source, severity string) (NormalizedFinding, bool) {
	trimmed := strings.TrimSpace(raw)
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, "pii-data:") {
		value := strings.TrimSpace(trimmed[len("pii-data:"):])
		value = strings.TrimSpace(strings.TrimPrefix(value, "[normalized] "))
		if !acceptedLocalPIIMatch(value) {
			return NormalizedFinding{}, false
		}
		return normalizedSensitiveLocalFinding(
			"LP-PII-DATA", CatPIIExposure, localPIIFindingTitle, raw, source, severity,
		), true
	}
	if strings.HasPrefix(lower, "pii-request:") {
		return normalizedSensitiveLocalFinding(
			"LP-PII-REQUEST", CatPIIExposure, localPIIFindingTitle, raw, source, severity,
		), true
	}

	match := strings.TrimSpace(strings.TrimPrefix(trimmed, "[normalized] "))
	normalizedMatch := normalizeForTriage(match)

	// A direct PII regex value is not the usual emitted shape (the scanner adds
	// pii-data:), but accepting it here keeps the persistence boundary safe for
	// callers that adapt the same configured detector output independently.
	localPatternsMu.RLock()
	piiRegexes := piiDataRegexes
	injectionLiterals := injectionPatterns
	injectionREs := injectionRegexes
	secretLiterals := secretPatterns
	localPatternsMu.RUnlock()
	for _, re := range piiRegexes {
		if re != nil {
			match := firstAcceptedRegexMatch(re, normalizedMatch, acceptedLocalPIIMatch)
			if match == nil {
				continue
			}
			return normalizedSensitiveLocalFinding(
				"LP-PII-DATA", CatPIIExposure, localPIIFindingTitle, raw, source, severity,
			), true
		}
	}

	for _, literal := range secretLiterals {
		literal = normalizeForTriage(literal)
		if literal != "" && strings.Contains(normalizedMatch, literal) {
			return normalizedSensitiveLocalFinding(
				"LP-SECRET-MATCH", CatCredentialLeak, localCredentialFindingTitle, raw, source, severity,
			), true
		}
	}
	for _, detector := range secretPatternDetectors {
		if detector.pattern == nil || firstAcceptedRegexMatch(detector.pattern, match, func(candidate string) bool {
			return acceptedLocalSecretMatch(detector.kind, candidate)
		}) == nil {
			continue
		}
		return normalizedSensitiveLocalFinding(
			detector.canonicalID, CatCredentialLeak, localCredentialFindingTitle, raw, source, severity,
		), true
	}

	for _, literal := range injectionLiterals {
		literal = normalizeForTriage(literal)
		if literal != "" && strings.Contains(normalizedMatch, literal) {
			canonicalID := canonicalLocalInjectionFindingID(match)
			if canonicalID == "" {
				canonicalID = "LP-INJ-MATCH"
			}
			return normalizedSensitiveLocalFinding(
				canonicalID, CatPromptInjection, localInjectionFindingTitle, raw, source, severity,
			), true
		}
	}
	for _, re := range injectionREs {
		if re != nil && re.MatchString(normalizedMatch) {
			return normalizedSensitiveLocalFinding(
				"LP-INJ-MATCH", CatPromptInjection, localInjectionFindingTitle, raw, source, severity,
			), true
		}
	}

	return NormalizedFinding{}, false
}

func normalizedSensitiveLocalFinding(
	canonicalID, category, title, evidence, source, severity string,
) NormalizedFinding {
	return NormalizedFinding{
		CanonicalID: canonicalID,
		Source:      source,
		OriginalID:  canonicalID,
		Category:    category,
		Severity:    severity,
		Title:       title,
		Evidence:    evidence,
	}
}

// canonicalIDFromRuleID maps a scanner-specific rule ID to a stable
// canonical ID suitable for cross-scanner correlation.
func canonicalIDFromRuleID(ruleID string) string {
	upper := strings.ToUpper(ruleID)
	lower := strings.ToLower(ruleID)

	// Local-pattern PII findings carry the matched value after a colon. Handle
	// those pseudo IDs before the generic PII- canonical-prefix path so source
	// data can never become part of a persisted rule identity.
	switch {
	case lower == "pii-data" || strings.HasPrefix(lower, "pii-data:"):
		return "LP-PII-DATA"
	case lower == "pii-request" || strings.HasPrefix(lower, "pii-request:"):
		return "LP-PII-REQUEST"
	}

	// Already in canonical form (prefixed with a known category)
	for _, prefix := range canonicalRuleIDPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return upper
		}
	}

	// Cisco AI Defense finding IDs
	if strings.HasPrefix(upper, "CISCO-") || strings.HasPrefix(upper, "AID-") {
		return "CISCO-" + strings.TrimPrefix(strings.TrimPrefix(upper, "CISCO-"), "AID-")
	}
	if canonical, ok := canonicalDottedRuleID(ruleID); ok {
		return canonical
	}

	// Local pattern match strings: map to canonical.
	if canonical := canonicalLocalPatternFindingID(ruleID); canonical != "" {
		return canonical
	}

	return "UNKNOWN-" + strings.ReplaceAll(upper, " ", "-")
}

// canonicalLocalPatternFindingID is the closed set of fixed identities that
// may be derived from an untrusted local-pattern match. It never constructs an
// identifier from the source bytes, so callers cannot accidentally persist an
// UNKNOWN-* value containing matched content.
func canonicalLocalPatternFindingID(value string) string {
	if canonical := canonicalLocalInjectionFindingID(value); canonical != "" {
		return canonical
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "sk-"), strings.HasPrefix(lower, "ghp_"), strings.HasPrefix(lower, "bearer"):
		return "LP-SECRET-MATCH"
	case strings.Contains(lower, "/etc/"):
		return "LP-SYSTEM-FILE"
	case strings.Contains(lower, "exfiltrate"), strings.Contains(lower, "base64"):
		return "LP-EXFIL"
	default:
		return ""
	}
}

// canonicalLocalInjectionFindingID recognizes only fixed classifications. It
// deliberately does not accept canonical-looking prefixes: local-pattern
// input is matched content, so copying an LP-INJ-* shaped value into a rule ID
// would move producer-controlled source bytes into persisted identity fields.
func canonicalLocalInjectionFindingID(value string) string {
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "ignore") && strings.Contains(lower, "instruct"):
		return "LP-INJ-IGNORE"
	case strings.Contains(lower, "jailbreak") || strings.Contains(lower, "dan mode"):
		return "LP-INJ-JAILBREAK"
	default:
		return ""
	}
}

func canonicalDottedRuleID(ruleID string) (string, bool) {
	switch strings.ToLower(ruleID) {
	case "secrets.cloud_credential_read":
		return "secrets.cloud_credential_read", true
	case "secrets.browser_session_store_read":
		return "secrets.browser_session_store_read", true
	case "secrets.cloud_secret_manager_read":
		return "secrets.cloud_secret_manager_read", true
	case "secrets.workload_identity_token_read":
		return "secrets.workload_identity_token_read", true
	case "exfil.secret_read_and_egress_oneliner":
		return "exfil.secret_read_and_egress_oneliner", true
	case "exec.reverse_tunnel":
		return "exec.reverse_tunnel", true
	case "exec.agent_runtime_bypass_flags":
		return "exec.agent_runtime_bypass_flags", true
	case "integrity.git_hooks_bypass":
		return "integrity.git_hooks_bypass", true
	case "recon.network_sweep":
		return "recon.network_sweep", true
	case "privilege.container_host_escape":
		return "privilege.container_host_escape", true
	case "privilege.container_runtime_socket_access":
		return "privilege.container_runtime_socket_access", true
	case "privilege.host_namespace_entry":
		return "privilege.host_namespace_entry", true
	case "lateral.workload_exec":
		return "lateral.workload_exec", true
	case "impact.cryptomining_launch":
		return "impact.cryptomining_launch", true
	case "impact.fork_bomb":
		return "impact.fork_bomb", true
	case "impact.mass_process_termination":
		return "impact.mass_process_termination", true
	case "source.git_remote_tamper":
		return "source.git_remote_tamper", true
	case "source.git_config_exec":
		return "source.git_config_exec", true
	case "tamper.detector_state_write":
		return "tamper.detector_state_write", true
	case "tamper.guardrails_off":
		return "tamper.guardrails_off", true
	case "persistence.shell_profile_write":
		return "persistence.shell_profile_write", true
	case "persistence.git_hook_write":
		return "persistence.git_hook_write", true
	case "persistence.ssh_authorized_keys_command":
		return "persistence.ssh_authorized_keys_command", true
	case "persistence.privileged_account_change":
		return "persistence.privileged_account_change", true
	case "chain.guardrails_off_then_egress":
		return "chain.guardrails_off_then_egress", true
	case "chain.permission_denied_then_runtime_bypass":
		return "chain.permission_denied_then_runtime_bypass", true
	case "chain.privilege_discovery_then_elevation":
		return "chain.privilege_discovery_then_elevation", true
	case "chain.secret_manager_read_then_egress":
		return "chain.secret_manager_read_then_egress", true
	case "chain.secret_read_then_egress":
		return "chain.secret_read_then_egress", true
	case "chain.workload_identity_then_lateral_execution":
		return "chain.workload_identity_then_lateral_execution", true
	default:
		return "", false
	}
}

// categoryFromTags derives a normalized category from rule tags.
func categoryFromTags(tags []string) string {
	tagSet := make(map[string]bool, len(tags))
	for _, t := range tags {
		tagSet[strings.ToLower(strings.TrimSpace(t))] = true
	}

	switch {
	case tagSet["prompt-injection"]:
		return CatPromptInjection
	case tagSet["credential"] || tagSet["credential-leak"] || tagSet["secret"]:
		return CatCredentialLeak
	case tagSet["pii"] || tagSet["pii-exposure"]:
		return CatPIIExposure
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
	case strings.HasPrefix(upper, "SECRETS."):
		return CatCredentialLeak
	case strings.HasPrefix(upper, "EXFIL."):
		return CatDataExfil
	case strings.HasPrefix(upper, "EXEC."):
		return CatDangerousExec
	case strings.HasPrefix(upper, "TAMPER."),
		strings.HasPrefix(upper, "SOURCE."):
		return CatCognitiveTamper
	case strings.HasPrefix(upper, "INTEGRITY."),
		strings.HasPrefix(upper, "RECON."),
		strings.HasPrefix(upper, "PRIVILEGE."),
		strings.HasPrefix(upper, "LATERAL."),
		strings.HasPrefix(upper, "IMPACT."),
		strings.HasPrefix(upper, "PERSISTENCE."),
		strings.HasPrefix(upper, "CHAIN."):
		return CatDangerousExec
	case strings.HasPrefix(upper, "SEC-"), strings.HasPrefix(upper, "CS-SEC-"),
		strings.HasPrefix(upper, "SECRET-"), strings.HasPrefix(upper, "JSON-SEC-"),
		strings.HasPrefix(upper, "CRED-"), strings.HasPrefix(upper, "LP-SECRET-"),
		strings.HasPrefix(upper, "JUDGE-ADJ-SECRET"):
		return CatCredentialLeak
	case strings.HasPrefix(upper, "CMD-"):
		return CatDangerousExec
	case strings.HasPrefix(upper, "PATH-"):
		return CatSystemFile
	case strings.HasPrefix(upper, "C2-"):
		return CatDataExfil
	case strings.HasPrefix(upper, "COG-"):
		return CatCognitiveTamper
	case strings.HasPrefix(upper, "TRUST-"), strings.HasPrefix(upper, "INJ-"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "OBFUSC-"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "JUDGE-INJ"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "JUDGE-ADJ-INJECTION"):
		return CatPromptInjection
	case strings.HasPrefix(upper, "JUDGE-PII"), strings.HasPrefix(upper, "PII-"),
		strings.HasPrefix(upper, "CS-PII-"), strings.HasPrefix(upper, "LP-PII-"),
		strings.HasPrefix(upper, "JUDGE-ADJ-PII"), isEnterprisePIIRuleID(upper):
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
	case strings.HasPrefix(upper, "JUDGE-ADJ-EXFIL"):
		return CatDataExfil
	case strings.HasPrefix(upper, "LP-SYSTEM"):
		return CatSystemFile
	default:
		return CatGeneral
	}
}

func isEnterprisePIIRuleID(ruleID string) bool {
	switch strings.ToUpper(strings.TrimSpace(ruleID)) {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN",
		"ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER",
		"ENT-IBAN", "ENT-US-PHONE", "ENT-EMAIL-BULK", "ENT-PASSPORT-US",
		"ENT-DL-CA", "ENT-MEDICAL-RECORD", "ENT-DOB-PATTERN", "ENT-NHS-NUMBER",
		"ENT-BULK-CSV-PII", "ENT-BULK-JSON-PII":
		return true
	default:
		return false
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
