// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/subtle"
	"strings"
)

// trustedSensitiveFindingRuleIDs is the closed set of built-in identities that
// may cross the sensitive-finding persistence boundary verbatim. Finding
// producers are not a trust boundary: accepting an arbitrary SEC-/PII-/TRUST-
// prefix would let matched source bytes be smuggled into scan_results.raw_json
// and the canonical v8 projection. Unknown and custom IDs are therefore keyed
// and replaced by ensureSensitiveFindingRuleID.
var trustedSensitiveFindingRuleIDs = map[sensitiveFindingKind]map[string]struct{}{
	sensitiveFindingKindSecret: makeSensitiveFindingRuleIDSet(
		"SEC-AWS-KEY", "SEC-AWS-SECRET", "SEC-ANTHROPIC", "SEC-OPENAI", "SEC-OPENAI-V2",
		"SEC-STRIPE", "SEC-GITHUB-TOKEN", "SEC-GITHUB-PAT", "SEC-GITLAB", "SEC-GOOGLE",
		"SEC-SLACK-TOKEN", "SEC-SLACK-WEBHOOK", "SEC-DISCORD-WEBHOOK", "SEC-PRIVKEY",
		"SEC-JWT", "SEC-CONNSTR", "SEC-BEARER", "SEC-SENDGRID", "SEC-TWILIO",
		"SEC-NPM-TOKEN", "SEC-PYPI-TOKEN", "SEC-HEX-SECRET",
		"CS-SEC-AWS-KEY", "CS-SEC-AWS-SECRET", "CS-SEC-AWS-SESSION", "CS-SEC-AWS-ARN",
		"CS-SEC-GCP-KEY", "CS-SEC-GCP-SA", "CS-SEC-GCP-OAUTH",
		"CS-SEC-AZ-STORAGE", "CS-SEC-AZ-CONN", "CS-SEC-AZ-SECRET", "CS-SEC-AZ-SAS",
		"CS-SEC-GH-PAT", "CS-SEC-GH-OAUTH", "CS-SEC-GH-FINE", "CS-SEC-GH-APP", "CS-SEC-GH-REFRESH",
		"CS-SEC-GL-PAT", "CS-SEC-GL-PROJ", "CS-SEC-GL-OAUTH",
		"CS-SEC-SLACK-BOT", "CS-SEC-SLACK-USER", "CS-SEC-SLACK-WH",
		"CS-SEC-STRIPE-LIVE", "CS-SEC-STRIPE-TEST", "CS-SEC-STRIPE-PUB", "CS-SEC-STRIPE-RESTR",
		"CS-SEC-TWILIO-SID", "CS-SEC-TWILIO-AUTH", "CS-SEC-TWILIO-KEY",
		"CS-SEC-SENDGRID", "CS-SEC-MAILGUN", "CS-SEC-NPM", "CS-SEC-PYPI",
		"CS-SEC-KEY-RSA", "CS-SEC-KEY-EC", "CS-SEC-KEY-DSA", "CS-SEC-KEY-GENERIC",
		"CS-SEC-JWT", "CS-SEC-BASIC-AUTH", "CS-SEC-BEARER", "CS-SEC-PASSWORD",
		"CG-CRED-001", "CG-CRED-002", "CG-CRED-003", "CRED-AWS-FILE", "CRED-AWS-KEY",
		"LP-SECRET-MATCH", "LP-SECRET-ASSIGNMENT", "LP-SECRET-BEARER", "JUDGE-ADJ-SECRET",
	),
	sensitiveFindingKindPII: makeSensitiveFindingRuleIDSet(
		"ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN", "ENT-CC-VISA", "ENT-CC-MC",
		"ENT-CC-AMEX", "ENT-CC-DISCOVER", "ENT-IBAN", "ENT-US-PHONE", "ENT-EMAIL-BULK",
		"ENT-PASSPORT-US", "ENT-DL-CA", "ENT-MEDICAL-RECORD", "ENT-DOB-PATTERN",
		"ENT-NHS-NUMBER", "ENT-BULK-CSV-PII", "ENT-BULK-JSON-PII",
		"CS-PII-CC-VISA", "CS-PII-CC-MC", "CS-PII-CC-AMEX", "CS-PII-CC-DISC", "CS-PII-CC-FMT",
		"CS-PII-SSN-DASH", "CS-PII-SSN-SPACE", "CS-PII-EMAIL", "CS-PII-PHONE-1", "CS-PII-PHONE-2",
		"CS-PII-IP", "CS-PII-DOB-MDY", "CS-PII-DOB-ISO", "CS-PII-PASSPORT",
		"CS-PII-DL-1", "CS-PII-DL-2", "CS-PII-BANK", "CS-PII-MED",
		"JUDGE-PII-EMAIL", "JUDGE-PII-EMAIL-EXTERNAL", "JUDGE-PII-IP", "JUDGE-PII-PHONE",
		"JUDGE-PII-DL", "JUDGE-PII-PASSPORT", "JUDGE-PII-SSN", "JUDGE-PII-USER",
		"JUDGE-PII-PASS", "JUDGE-ADJ-PII",
		"LP-PII-DATA", "LP-PII-REQUEST", "PII-PASSPORT", "PII-PASSWORD", "PII-SSN", "PII-SSN-US",
	),
	sensitiveFindingKindTrust: makeSensitiveFindingRuleIDSet(
		"TRUST-AUTHORITY", "TRUST-MAINTENANCE", "TRUST-SAFETY-OVERRIDE", "TRUST-NEW-INSTRUCTIONS",
		"TRUST-IGNORE-PREVIOUS", "TRUST-DISREGARD", "TRUST-JAILBREAK", "TRUST-PRETEND",
		"TRUST-FORGET", "TRUST-NEW-INSTRUCT-PREFIX", "TRUST-OVERRIDE-INSTRUCT", "TRUST-FROM-NOW-ON",
		"TRUST-SWITCH-MODE", "TRUST-PROMPT-EXTRACT", "TRUST-FICTIONAL", "TRUST-NO-ETHICS",
		"TRUST-TOOL-MANIP", "TRUST-PERSONA", "TRUST-DELIMITER", "TRUST-OUTPUT-CONSTRAINT",
		"TRUST-PAYLOAD-SPLIT", "TRUST-AUTHORITY-CLAIM", "TRUST-NEW-INSTRUCTION",
		"OBFUSC-UNICODE-ZWSP",
		"JUDGE-INJ-INSTRUCT", "JUDGE-INJ-CONTEXT", "JUDGE-INJ-OBFUSC", "JUDGE-INJ-SEMANTIC",
		"JUDGE-INJ-TOKEN", "JUDGE-ADJ-INJECTION",
		"JUDGE-TOOL-INJ-INSTRUCT", "JUDGE-TOOL-INJ-CONTEXT", "JUDGE-TOOL-INJ-OBFUSC",
		"JUDGE-TOOL-INJ-EXFIL", "JUDGE-TOOL-INJ-DESTRUCT",
		"LP-INJ-IGNORE", "LP-INJ-JAILBREAK", "LP-INJ-MATCH",
	),
}

func makeSensitiveFindingRuleIDSet(ids ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func trustedSensitiveFindingRuleID(
	value string,
	kind sensitiveFindingKind,
	scannerName string,
	fingerprinter RuntimeV8FindingContentFingerprinter,
) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "redacted."+string(kind)+".unknown" {
		return trimmed, true
	}
	if authenticatedSensitiveOpaqueRuleID(trimmed, kind, scannerName, fingerprinter) {
		return trimmed, true
	}
	canonical := strings.ToUpper(trimmed)
	_, ok := trustedSensitiveFindingRuleIDs[kind][canonical]
	return canonical, ok
}

func wellFormedSensitiveOpaqueRuleID(value string, kind sensitiveFindingKind) bool {
	prefix := "redacted." + string(kind) + "."
	if value == prefix+"unknown" {
		return true
	}
	_, _, ok := parseSensitiveOpaqueRuleID(value, kind)
	return ok
}

func parseSensitiveOpaqueRuleID(value string, kind sensitiveFindingKind) (identity, authenticator string, ok bool) {
	// Syntax is not provenance. Persistence callers must verify the returned
	// authenticator with authenticatedSensitiveOpaqueRuleID before preserving
	// an existing opaque identity.
	prefix := "redacted." + string(kind) + ".id-"
	if !strings.HasPrefix(value, prefix) {
		return "", "", false
	}
	identity, authenticator, found := strings.Cut(strings.TrimPrefix(value, prefix), ".mac-")
	if !found || !canonicalSensitiveRuleIDToken(identity) || !canonicalSensitiveRuleIDToken(authenticator) {
		return "", "", false
	}
	return identity, authenticator, true
}

func canonicalSensitiveRuleIDToken(token string) bool {
	if len(token) != 16 || token != strings.ToLower(token) {
		return false
	}
	for _, char := range token {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func authenticatedSensitiveOpaqueRuleID(
	value string,
	kind sensitiveFindingKind,
	scannerName string,
	fingerprinter RuntimeV8FindingContentFingerprinter,
) bool {
	identity, authenticator, ok := parseSensitiveOpaqueRuleID(value, kind)
	if !ok {
		return false
	}
	expected, ok := sensitiveOpaqueRuleIDAuthenticator(identity, kind, scannerName, fingerprinter)
	return ok && subtle.ConstantTimeCompare([]byte(authenticator), []byte(expected)) == 1
}

func sensitiveOpaqueRuleIDAuthenticator(
	identity string,
	kind sensitiveFindingKind,
	scannerName string,
	fingerprinter RuntimeV8FindingContentFingerprinter,
) (string, bool) {
	if !canonicalSensitiveRuleIDToken(identity) || fingerprinter == nil {
		return "", false
	}
	authInput := strings.Join([]string{
		"defenseclaw-sensitive-finding-rule-id-auth-v1",
		string(kind),
		strings.TrimSpace(scannerName),
		identity,
	}, "\x00")
	left, leftErr := fingerprinter.FingerprintRuntimeV8FindingContent(authInput + "\x00left")
	right, rightErr := fingerprinter.FingerprintRuntimeV8FindingContent(authInput + "\x00right")
	if leftErr != nil || rightErr != nil ||
		!isCanonicalContentFingerprint(left) || !isCanonicalContentFingerprint(right) {
		return "", false
	}
	return left + right, true
}

func canonicalSensitiveFindingCategory(kind sensitiveFindingKind) string {
	switch kind {
	case sensitiveFindingKindSecret:
		return "credential-leak"
	case sensitiveFindingKindPII:
		return "pii-exposure"
	case sensitiveFindingKindTrust:
		return "prompt-injection"
	default:
		return "general"
	}
}

func canonicalSensitiveFindingDataAxes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, 3)
	seen := make(map[string]struct{}, 3)
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		canonical := ""
		switch {
		case strings.EqualFold(trimmed, "ingress_untrusted"):
			canonical = "ingress_untrusted"
		case strings.EqualFold(trimmed, "sensitive_access"):
			canonical = "sensitive_access"
		case strings.EqualFold(trimmed, "egress_external"):
			canonical = "egress_external"
		default:
			continue
		}
		if _, duplicate := seen[canonical]; duplicate {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
		if len(out) == 3 {
			break
		}
	}
	return out
}

func canonicalSensitiveFindingToolCapabilityClass(value string) string {
	trimmed := strings.TrimSpace(value)
	switch {
	case strings.EqualFold(trimmed, "read_fs"):
		return "read_fs"
	case strings.EqualFold(trimmed, "write_fs"):
		return "write_fs"
	case strings.EqualFold(trimmed, "exec_shell"):
		return "exec_shell"
	case strings.EqualFold(trimmed, "network_fetch"):
		return "network_fetch"
	case strings.EqualFold(trimmed, "send_message"):
		return "send_message"
	default:
		return ""
	}
}
