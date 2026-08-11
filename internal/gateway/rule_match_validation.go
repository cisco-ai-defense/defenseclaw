// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ssnListCandidatePattern = regexp.MustCompile(`\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b`)

// firstAcceptedRuleMatch returns the first regex match that also satisfies the
// rule's structural validator. Regexes are intentionally used as a cheap
// candidate generator; formats such as payment cards and credentials need a
// second stage before they are important enough to alert on. Continuing after
// a rejected candidate prevents an obvious placeholder near the start of a
// document from hiding a real value later in the same content.
func firstAcceptedRuleMatch(rule PatternRule, text string) []int {
	return firstAcceptedRegexMatchAt(rule.Pattern, text, func(match string, start, end int) bool {
		return acceptedRuleMatchAt(rule.ID, text, match, start, end)
	})
}

func firstAcceptedRegexMatch(pattern interface {
	FindStringIndex(string) []int
}, text string, accept func(string) bool) []int {
	return firstAcceptedRegexMatchAt(pattern, text, func(match string, _, _ int) bool {
		return accept(match)
	})
}

func firstAcceptedRegexMatchAt(pattern interface {
	FindStringIndex(string) []int
}, text string, accept func(match string, start, end int) bool) []int {
	if pattern == nil || text == "" {
		return nil
	}
	for offset := 0; offset <= len(text); {
		loc := pattern.FindStringIndex(text[offset:])
		if loc == nil {
			return nil
		}
		start, end := offset+loc[0], offset+loc[1]
		if accept(text[start:end], start, end) {
			return []int{start, end}
		}
		if end > start {
			offset = end
			continue
		}
		if end >= len(text) {
			return nil
		}
		_, size := utf8.DecodeRuneInString(text[end:])
		if size <= 0 {
			size = 1
		}
		offset = end + size
	}
	return nil
}

func findAcceptedLocalPIIMatch(original, normalized string, pattern interface {
	FindStringIndex(string) []int
}) (match string, wasNormalized, ok bool) {
	acceptOriginal := func(match string, start, end int) bool {
		return acceptedLocalPIIMatchAt(original, match, start, end)
	}
	if loc := firstAcceptedRegexMatchAt(pattern, original, acceptOriginal); loc != nil {
		return original[loc[0]:loc[1]], false, true
	}
	if normalized != original {
		acceptNormalized := func(match string, start, end int) bool {
			return acceptedLocalPIIMatchAt(normalized, match, start, end)
		}
		if loc := firstAcceptedRegexMatchAt(pattern, normalized, acceptNormalized); loc != nil {
			return normalized[loc[0]:loc[1]], true, true
		}
	}
	return "", false, false
}

func findAcceptedLocalSecretMatch(original, normalized string, pattern interface {
	FindStringIndex(string) []int
}, patternIndex int) (match string, wasNormalized, ok bool) {
	accept := func(match string) bool { return acceptedLocalSecretMatch(patternIndex, match) }
	if loc := firstAcceptedRegexMatch(pattern, original, accept); loc != nil {
		return original[loc[0]:loc[1]], false, true
	}
	if normalized != original {
		if loc := firstAcceptedRegexMatch(pattern, normalized, accept); loc != nil {
			return normalized[loc[0]:loc[1]], true, true
		}
	}
	return "", false, false
}

func findAcceptedRuleLoc(original, normalized, ruleID string, pattern interface {
	FindStringIndex(string) []int
}) (loc []int, source string, wasNormalized, ok bool) {
	acceptOriginal := func(match string, start, end int) bool {
		return acceptedRuleMatchAt(ruleID, original, match, start, end)
	}
	if loc := firstAcceptedRegexMatchAt(pattern, original, acceptOriginal); loc != nil {
		return loc, original, false, true
	}
	if normalized != original {
		acceptNormalized := func(match string, start, end int) bool {
			return acceptedRuleMatchAt(ruleID, normalized, match, start, end)
		}
		if loc := firstAcceptedRegexMatchAt(pattern, normalized, acceptNormalized); loc != nil {
			return loc, normalized, true, true
		}
	}
	return nil, "", false, false
}

func acceptedRuleMatchAt(ruleID, text, match string, start, end int) bool {
	if !acceptedRuleMatch(ruleID, match) {
		return false
	}
	if ruleID == "ENT-BULK-SSN" || ruleID == "ENT-BULK-SSN-NOHYPHEN" {
		return credibleSSNContext(text, start, end)
	}
	return true
}

func acceptedRuleMatch(ruleID, match string) bool {
	switch ruleID {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN":
		return validUSSSN(match)
	case "ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER":
		return validPaymentCardCandidate(match)
	}
	if strings.HasPrefix(ruleID, "SEC-") {
		return acceptedCredentialMatch(ruleID, match)
	}
	return true
}

// acceptedLocalPIIMatch applies the same structural checks to the legacy local
// PII regex lane. Custom patterns that do not produce an SSN- or PAN-shaped
// candidate retain their historical behavior.
func acceptedLocalPIIMatch(match string) bool {
	digits := decimalDigits(match)
	if len(digits) == 9 && strings.Count(match, "-") == 2 {
		return validUSSSN(match)
	}
	if len(digits) >= 13 && len(digits) <= 19 {
		return validPaymentCardCandidate(match)
	}
	return true
}

func acceptedLocalPIIMatchAt(text, match string, start, end int) bool {
	if !acceptedLocalPIIMatch(match) {
		return false
	}
	digits := decimalDigits(match)
	if len(digits) == 9 && strings.Count(match, "-") == 2 {
		return credibleSSNContext(text, start, end)
	}
	return true
}

func credibleSSNContext(text string, start, end int) bool {
	if hasDistinctValidSSNList(text, start, end) {
		return true
	}
	windowStart := start - 80
	if windowStart < 0 {
		windowStart = 0
	}
	prefix := strings.ToLower(text[windowStart:start])
	for _, nonRecordContext := range []string{
		"ssn_hash", "ssn-hash", "ssn hash", "hashed ssn",
		"ssn_digest", "ssn-digest", "ssn digest",
		"example ssn", "ssn example", "ssn_example", "sample ssn", "ssn sample",
		"placeholder ssn", "ssn placeholder", "ssn schema", "ssn format",
		"ssn regex", "ssn pattern",
	} {
		if index := strings.LastIndex(prefix, nonRecordContext); index >= 0 &&
			ssnImmediateLabelTail(prefix[index+len(nonRecordContext):]) {
			return false
		}
	}
	for _, label := range []string{
		"ssn", "social security", "taxpayer id", "taxpayer identification",
	} {
		if strings.Contains(prefix, label) {
			return true
		}
	}
	return false
}

func hasDistinctValidSSNList(text string, start, end int) bool {
	windowStart := start - 256
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 256
	if windowEnd > len(text) {
		windowEnd = len(text)
	}
	distinct := make(map[string]struct{}, 2)
	for _, candidate := range ssnListCandidatePattern.FindAllString(text[windowStart:windowEnd], 16) {
		if !validUSSSN(candidate) {
			continue
		}
		distinct[decimalDigits(candidate)] = struct{}{}
		if len(distinct) >= 2 {
			return true
		}
	}
	return false
}

func ssnImmediateLabelTail(value string) bool {
	words := strings.FieldsFunc(value, func(char rune) bool {
		return !unicode.IsLetter(char) && !unicode.IsDigit(char)
	})
	switch strings.Join(words, " ") {
	case "", "is", "value", "value is", "number", "number is", "field", "field is":
		return true
	default:
		return false
	}
}

func acceptedLocalSecretMatch(patternIndex int, match string) bool {
	candidate := assignmentValue(match)
	if patternIndex == 3 {
		lower := strings.ToLower(match)
		if bearer := strings.Index(lower, "bearer"); bearer >= 0 {
			candidate = strings.TrimSpace(match[bearer+len("bearer"):])
		}
	}
	if candidate == "" {
		return true
	}
	// An explicit password assignment is itself the signal. Weak defaults such
	// as changeme123 and examplepass are often the credentials operators most
	// need surfaced, not documentation placeholders to suppress.
	if patternIndex == 1 {
		return true
	}
	if obviousCredentialPlaceholder(candidate) {
		return false
	}
	return patternIndex != 3 || credentialEntropy(compactCredential(candidate)) >= 2.5
}

func normalizedPIIEvidenceKey(evidence string) string {
	evidence = strings.TrimSpace(strings.TrimPrefix(evidence, "[normalized] "))
	digits := decimalDigits(evidence)
	if len(digits) == 9 || (len(digits) >= 13 && len(digits) <= 19) {
		return digits
	}
	return strings.ToLower(strings.Join(strings.Fields(evidence), " "))
}

func acceptedCredentialMatch(ruleID, match string) bool {
	// A complete private-key block is structural evidence on its own. Other
	// credential formats below expose a compact candidate value that can be
	// checked for public examples and placeholder entropy.
	if ruleID == "SEC-PRIVKEY" {
		return true
	}
	candidate := credentialCandidate(ruleID, match)
	if candidate == "" {
		return true
	}
	// A URI with user-info has already proved a credential-bearing structure.
	// Never hide weak/default passwords based on their spelling.
	if ruleID == "SEC-CONNSTR" {
		return true
	}
	if knownPublicCredentialExample(ruleID, candidate) {
		return false
	}
	if obviousCredentialPlaceholder(candidate) {
		return false
	}
	// The generic bearer shape has no provider-specific checksum or prefix, so
	// require a modest entropy floor before elevating arbitrary header examples.
	return ruleID != "SEC-BEARER" || credentialEntropy(compactCredential(candidate)) >= 2.5
}

func credentialCandidate(ruleID, match string) string {
	trimmed := strings.Trim(strings.TrimSpace(match), `"'`)
	lower := strings.ToLower(trimmed)
	switch ruleID {
	case "SEC-AWS-KEY":
		if len(trimmed) > 4 {
			return trimmed[4:]
		}
	case "SEC-AWS-SECRET", "SEC-HEX-SECRET":
		return assignmentValue(trimmed)
	case "SEC-ANTHROPIC":
		return strings.TrimPrefix(trimmed, "sk-ant-")
	case "SEC-OPENAI":
		return strings.TrimPrefix(trimmed, "sk-proj-")
	case "SEC-OPENAI-V2":
		return strings.TrimPrefix(trimmed, "sk-")
	case "SEC-STRIPE":
		for _, prefix := range []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"} {
			if strings.HasPrefix(lower, prefix) {
				return trimmed[len(prefix):]
			}
		}
	case "SEC-GITHUB-TOKEN":
		if len(trimmed) > 4 {
			return trimmed[4:]
		}
	case "SEC-GITHUB-PAT":
		return strings.TrimPrefix(trimmed, "github_pat_")
	case "SEC-GITLAB":
		return strings.TrimPrefix(trimmed, "glpat-")
	case "SEC-GOOGLE":
		return strings.TrimPrefix(trimmed, "AIza")
	case "SEC-SLACK-TOKEN":
		if dash := strings.IndexByte(trimmed, '-'); dash >= 0 {
			return trimmed[dash+1:]
		}
	case "SEC-SLACK-WEBHOOK", "SEC-DISCORD-WEBHOOK":
		if slash := strings.LastIndexByte(trimmed, '/'); slash >= 0 {
			return trimmed[slash+1:]
		}
	case "SEC-CONNSTR":
		if scheme := strings.Index(trimmed, "://"); scheme >= 0 {
			authority := trimmed[scheme+3:]
			if at := strings.LastIndexByte(authority, '@'); at >= 0 {
				authority = authority[:at]
			}
			if colon := strings.IndexByte(authority, ':'); colon >= 0 {
				return authority[colon+1:]
			}
		}
	case "SEC-BEARER":
		if bearer := strings.LastIndex(lower, "bearer"); bearer >= 0 {
			return strings.TrimSpace(trimmed[bearer+len("bearer"):])
		}
	case "SEC-SENDGRID":
		return strings.TrimPrefix(trimmed, "SG.")
	case "SEC-TWILIO":
		return strings.TrimPrefix(trimmed, "SK")
	case "SEC-NPM-TOKEN":
		return strings.TrimPrefix(trimmed, "npm_")
	case "SEC-PYPI-TOKEN":
		return strings.TrimPrefix(trimmed, "pypi-")
	}
	return ""
}

func assignmentValue(match string) string {
	if index := strings.IndexAny(match, "=:"); index >= 0 {
		return strings.Trim(strings.TrimSpace(match[index+1:]), `"'`)
	}
	return ""
}

func obviousCredentialPlaceholder(candidate string) bool {
	normalized := strings.ToLower(strings.TrimSpace(candidate))
	if normalized == "" {
		return true
	}
	normalized = strings.TrimPrefix(normalized, "api03-")
	canonical := strings.NewReplacer("-", "_", ".", "_", "/", "_").Replace(normalized)
	canonical = strings.Join(strings.FieldsFunc(canonical, func(char rune) bool {
		return char == '_'
	}), "_")
	switch canonical {
	case "example", "example_token", "example_secret", "exampleexample",
		"placeholder", "placeholder_token", "placeholder_secret", "placeholderplaceholder",
		"changeme", "change_me", "changemechangeme", "replace_me", "replaceme",
		"your_access_token", "your_token", "token_here", "secret_here",
		"dummy", "dummy_token", "dummy_secret", "dummydummy",
		"not_a_real_token", "not_a_real_secret", "fake_token", "fake_secret":
		return true
	}

	compact := compactCredential(normalized)
	if len(compact) < 8 {
		return false
	}
	for _, sequence := range []string{
		"abcdefghijklmnopqrstuvwxyz",
		"0123456789abcdefghijklmnopqrstuvwxyz",
		"abcdefghijklmnopqrstuvwxyz0123456789",
		"0123456789abcdef",
		"1234567890abcdef",
	} {
		if strings.Contains(sequence, compact) || strings.Contains(compact, sequence) {
			return true
		}
	}
	return repeatedShortCredentialUnit(compact)
}

func knownPublicCredentialExample(ruleID, candidate string) bool {
	switch ruleID {
	case "SEC-AWS-KEY":
		return strings.EqualFold(candidate, "IOSFODNN7EXAMPLE")
	case "SEC-AWS-SECRET":
		return candidate == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	default:
		return false
	}
}

func compactCredential(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, value)
}

func repeatedShortCredentialUnit(value string) bool {
	for width := 1; width <= 8 && width*3 <= len(value); width++ {
		if len(value)%width != 0 {
			continue
		}
		unit := value[:width]
		if strings.Repeat(unit, len(value)/width) == value {
			return true
		}
	}
	return false
}

func credentialEntropy(value string) float64 {
	if value == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range value {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func validUSSSN(value string) bool {
	digits := decimalDigits(value)
	if len(digits) != 9 {
		return false
	}
	area := decimalNumber(digits[:3])
	group := decimalNumber(digits[3:5])
	serial := decimalNumber(digits[5:])
	return area > 0 && area != 666 && area < 900 && group > 0 && serial > 0
}

func validPaymentCardCandidate(value string) bool {
	digits := decimalDigits(value)
	if len(digits) < 13 || len(digits) > 19 || knownPublicTestPAN(digits) {
		return false
	}
	sum := 0
	parity := len(digits) % 2
	for index, char := range digits {
		digit := int(char - '0')
		if index%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func knownPublicTestPAN(digits string) bool {
	switch digits {
	case "4111111111111111", "4242424242424242", "4000000000000002",
		"5555555555554444", "378282246310005", "6011111111111117":
		return true
	default:
		return false
	}
}

func decimalDigits(value string) string {
	var builder strings.Builder
	for _, char := range value {
		if char >= '0' && char <= '9' {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

func decimalNumber(value string) int {
	n := 0
	for _, char := range value {
		n = n*10 + int(char-'0')
	}
	return n
}
