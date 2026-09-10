// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/csv"
	"io"
	"math"
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

var ssnListCandidatePattern = regexp.MustCompile(`\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b`)

var (
	nodeEvalInvocationPattern    = regexp.MustCompile(`(?i)\bnode(?:js)?\s+(?:-e|--eval)(?:\s+|=)`)
	childProcessExecSinkPattern  = regexp.MustCompile(`(?is)(?:\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process)\s*\.\s*exec(?:Sync)?\s*\(\s*$`)
	childProcessSpawnSinkPattern = regexp.MustCompile(`(?is)(?:\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process)\s*\.\s*spawn(?:Sync)?\s*\(\s*["'](?:/bin/)?(?:ba|da|z|k)?sh["']\s*,\s*\[\s*["']-c["']\s*,\s*$`)
)

var windowsRegistryPersistencePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:hkcu|hkey_current_user|hklm|hkey_local_machine)[\\/]software[\\/]microsoft[\\/]windows[\\/]currentversion[\\/](?:run|runonce)(?:["']|\s)`),
	regexp.MustCompile(`(?i)(?:hkcu|hkey_current_user|hklm|hkey_local_machine)[\\/]software[\\/]microsoft[\\/]windows nt[\\/]currentversion[\\/]winlogon["']?\s+.*(?:/v(?::|\s+)|-(?:name|property)(?::|\s+))(?:shell|userinit)\b`),
	regexp.MustCompile(`(?i)(?:hklm|hkey_local_machine)[\\/]system[\\/]currentcontrolset[\\/]services[\\/][^\\/\s"']+["']?\s+.*(?:/v(?::|\s+)|-(?:name|property)(?::|\s+))(?:imagepath|servicedll)\b`),
}

// ibanLengthsByCountry mirrors the fixed national lengths in the SWIFT ISO
// 13616 IBAN Registry (release 102, June 2026). A MOD97-valid string is not an
// IBAN unless its country participates in the registry and its length matches
// that country's registered format.
var ibanLengthsByCountry = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28,
	"BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28,
	"CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DJ": 27, "DK": 18, "DO": 28,
	"EE": 20, "EG": 29, "ES": 24,
	"FI": 18, "FK": 18, "FO": 18, "FR": 27,
	"GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HN": 28, "HR": 21, "HU": 28,
	"IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
	"JO": 30,
	"KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25,
	"MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30,
	"NI": 28, "NL": 18, "NO": 15,
	"OM": 23,
	"PK": 24, "PL": 28, "PS": 29, "PT": 25,
	"QA": 29,
	"RO": 24, "RS": 22, "RU": 33,
	"SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
	"TL": 23, "TN": 24, "TR": 26,
	"UA": 29,
	"VA": 22, "VG": 24,
	"XK": 20,
	"YE": 30,
}

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

func firstAcceptedRegexMatch(pattern *regexp.Regexp, text string, accept func(string) bool) []int {
	return firstAcceptedRegexMatchAt(pattern, text, func(match string, _, _ int) bool {
		return accept(match)
	})
}

func firstAcceptedRegexMatchAt(pattern *regexp.Regexp, text string, accept func(match string, start, end int) bool) []int {
	if pattern == nil || text == "" {
		return nil
	}
	// Enumerate against the complete input once. Restarting a regex on
	// text[offset:] changes the meaning of ^ and word-boundary assertions after
	// a rejected candidate, allowing a non-match in the original text to become
	// a match solely because the validation cursor moved.
	for _, loc := range pattern.FindAllStringIndex(text, -1) {
		start, end := loc[0], loc[1]
		if accept(text[start:end], start, end) {
			return []int{start, end}
		}
	}
	return nil
}

func findAcceptedLocalPIIMatch(original, normalized string, pattern *regexp.Regexp) (match string, wasNormalized, ok bool) {
	loc, source, wasNormalized, ok := findAcceptedLocalPIILoc(original, normalized, pattern)
	if !ok {
		return "", false, false
	}
	return source[loc[0]:loc[1]], wasNormalized, true
}

func findAcceptedLocalPIILoc(original, normalized string, pattern *regexp.Regexp) (loc []int, source string, wasNormalized, ok bool) {
	acceptOriginal := func(match string, start, end int) bool {
		return acceptedLocalPIIMatchAt(original, match, start, end)
	}
	if loc := firstAcceptedRegexMatchAt(pattern, original, acceptOriginal); loc != nil {
		return loc, original, false, true
	}
	if normalized != original {
		acceptNormalized := func(match string, start, end int) bool {
			return acceptedLocalPIIMatchAt(normalized, match, start, end)
		}
		if loc := firstAcceptedRegexMatchAt(pattern, normalized, acceptNormalized); loc != nil {
			return loc, normalized, true, true
		}
	}
	return nil, "", false, false
}

func findAcceptedLocalSecretMatch(
	original, normalized string,
	detector localSecretDetector,
) (match string, wasNormalized, ok bool) {
	if detector.pattern == nil {
		return "", false, false
	}
	accept := func(match string) bool {
		return acceptedLocalSecretMatch(detector.kind, match)
	}
	if loc := firstAcceptedRegexMatch(detector.pattern, original, accept); loc != nil {
		return original[loc[0]:loc[1]], false, true
	}
	if normalized != original {
		if loc := firstAcceptedRegexMatch(detector.pattern, normalized, accept); loc != nil {
			return normalized[loc[0]:loc[1]], true, true
		}
	}
	return "", false, false
}

func findAcceptedRuleLoc(original, normalized, ruleID string, pattern *regexp.Regexp) (loc []int, source string, wasNormalized, ok bool) {
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
	switch ruleID {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN":
		return credibleSSNContext(text, start, end)
	case "ENT-EMAIL-BULK":
		return credibleEmailContext(text, match, start, end)
	case "ENT-BULK-CSV-PII":
		return credibleBulkCSVContext(text, start, end)
	case "SEC-PRIVKEY":
		return secretshape.ValidPrivateKeyPEMAt(text, start)
	case "CMD-RM-RF":
		return acceptedRecursiveRootDeleteAt(text, start, end)
	case "CMD-WIN-REG-PERSIST":
		for _, pattern := range windowsRegistryPersistencePatterns {
			if pattern.MatchString(text) {
				return true
			}
		}
		return false
	}
	return true
}

// acceptedRecursiveRootDeleteAt rejects destructive command literals that are
// merely data inside a node -e JavaScript program. Outside node's eval payload,
// CMD-RM-RF retains its existing behavior. Inside one, the matched literal must
// be a direct argument to a child_process shell-execution sink and begin in a
// shell command position.
func acceptedRecursiveRootDeleteAt(text string, start, end int) bool {
	script, scriptOffset, ok := nodeEvalPayloadContaining(text, start, end)
	if !ok {
		return true
	}

	relativeStart := start - scriptOffset
	relativeEnd := end - scriptOffset
	stringStart, contentStart, ok := javascriptStringContaining(script, relativeStart, relativeEnd)
	if !ok {
		return false
	}
	prefix := script[:stringStart]
	if !childProcessExecSinkPattern.MatchString(prefix) &&
		!childProcessSpawnSinkPattern.MatchString(prefix) {
		return false
	}
	return destructiveShellCommandPosition(script[contentStart:relativeStart])
}

func nodeEvalPayloadContaining(text string, start, end int) (string, int, bool) {
	for _, invocation := range nodeEvalInvocationPattern.FindAllStringIndex(text, -1) {
		payloadStart, payloadEnd, ok := shellArgumentRange(text, invocation[1])
		if ok && start >= payloadStart && end <= payloadEnd {
			return text[payloadStart:payloadEnd], payloadStart, true
		}
	}
	return "", 0, false
}

// shellArgumentRange returns the source span inside the immediate shell word.
// It deliberately handles only ordinary quoted/unquoted node -e arguments;
// unresolved shell expansions abstain from the JavaScript-specific suppression.
func shellArgumentRange(text string, offset int) (int, int, bool) {
	for offset < len(text) && (text[offset] == ' ' || text[offset] == '\t') {
		offset++
	}
	if offset >= len(text) {
		return 0, 0, false
	}
	quote := text[offset]
	if quote == '\'' || quote == '"' || quote == '`' {
		start := offset + 1
		for index := start; index < len(text); index++ {
			if quote != '\'' && text[index] == '\\' {
				index++
				continue
			}
			if text[index] == quote {
				return start, index, true
			}
		}
		return 0, 0, false
	}

	start := offset
	for offset < len(text) && !strings.ContainsRune(" \t\r\n;|&", rune(text[offset])) {
		offset++
	}
	return start, offset, offset > start
}

// javascriptStringContaining performs just enough lexical analysis to prove
// that the regex match is inside one JavaScript string argument. It does not
// resolve variables, concatenation, interpolation, or other dynamic code.
func javascriptStringContaining(script string, targetStart, targetEnd int) (int, int, bool) {
	for index := 0; index < len(script); index++ {
		quote := script[index]
		if quote != '\'' && quote != '"' && quote != '`' {
			continue
		}
		stringStart := index
		contentStart := index + 1
		for index++; index < len(script); index++ {
			if script[index] == '\\' {
				index++
				continue
			}
			if script[index] != quote {
				continue
			}
			// CMD-RM-RF's regex consumes a closing quote as the critical-path
			// boundary, so permit the target span to include this delimiter.
			if targetStart >= contentStart && targetEnd <= index+1 {
				return stringStart, contentStart, true
			}
			break
		}
	}
	return 0, 0, false
}

func destructiveShellCommandPosition(prefix string) bool {
	for _, separator := range []string{"\n", ";", "&&", "||"} {
		if index := strings.LastIndex(prefix, separator); index >= 0 {
			prefix = prefix[index+len(separator):]
		}
	}
	fields := strings.Fields(prefix)
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		switch {
		case field == "sudo", field == "command", field == "env", field == "nohup":
			continue
		case strings.HasPrefix(field, "-"):
			continue
		case strings.Contains(field, "=") && !strings.HasPrefix(field, "="):
			continue
		case (field == "sh" || field == "bash" || field == "dash" || field == "zsh" || field == "ksh" ||
			strings.HasSuffix(field, "/sh") || strings.HasSuffix(field, "/bash")) &&
			index+1 < len(fields) && fields[index+1] == "-c":
			index++
			continue
		default:
			return false
		}
	}
	return true
}

// credibleEmailContext removes operational addresses and documentation
// examples from the generic email detector. Those strings are common in agent
// instructions but are not evidence that a person record is being exposed.
// The exclusions are intentionally phrased as closed, high-signal contexts;
// ordinary contact, customer, employee, patient, invoice, and structured-data
// records remain eligible even when they use synthetic example domains.
func credibleEmailContext(text, match string, start, end int) bool {
	lower := strings.ToLower(text)
	matchLower := strings.ToLower(match)
	if strings.Contains(lower, "string literal") ||
		strings.Contains(lower, "typical format") ||
		strings.Contains(lower, "common format") {
		return false
	}
	for _, phrase := range []string{
		"format email message", "send email with", "send e-mail to",
		"email an alert", "email it with", "emailing to", "bcc to",
	} {
		if strings.Contains(lower, phrase) {
			return false
		}
	}
	if strings.Contains(lower, "ssh") &&
		!strings.Contains(lower, "email:") &&
		!strings.Contains(lower, "email address") {
		return false
	}
	if strings.HasSuffix(matchLower, ".compute.amazonaws.com") ||
		emailDomainLooksLikeNumericHost(matchLower) {
		return false
	}
	if start >= 0 && end >= start && end <= len(text) {
		tail := strings.TrimLeft(text[end:], " \t\r\n\"'`")
		if strings.HasPrefix(tail, ":") {
			return false
		}
		// Git/SSH host aliases can contain dots and suffixes, so the generic
		// email regex may stop early at an apparent TLD in a locator such as
		// git@github.com-work:cisco/repo.git. Treat a contiguous host suffix
		// followed by ':' as a remote locator rather than a person address.
		if colon := strings.IndexByte(tail, ':'); colon > 0 {
			hostSuffix := tail[:colon]
			if strings.IndexFunc(hostSuffix, func(char rune) bool {
				return !((char >= 'a' && char <= 'z') ||
					(char >= 'A' && char <= 'Z') ||
					(char >= '0' && char <= '9') || char == '.' || char == '-')
			}) == -1 {
				return false
			}
		}
	}
	return true
}

func emailDomainLooksLikeNumericHost(email string) bool {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 3 {
		return false
	}
	numeric := 0
	for _, label := range labels[:len(labels)-1] {
		if label == "" {
			return false
		}
		allDigits := true
		for _, char := range label {
			if char < '0' || char > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			numeric++
		}
	}
	return numeric >= 2
}

func acceptedRuleMatch(ruleID, match string) bool {
	switch ruleID {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN":
		return validUSSSN(match)
	case "ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER":
		return validPaymentCardCandidate(match)
	case "ENT-IBAN":
		return validIBAN(match)
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
	// Wide CSV/TSV exports can place the column header hundreds of bytes
	// before the first value. Preserve that record context by requiring the
	// candidate's exact column to align with a recognized header on the
	// immediately preceding row. This is deliberately narrower than simply
	// widening the free-text window, which would turn distant schema examples
	// back into alerts.
	if hasDelimitedSSNColumnHeader(text, start) {
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

const maxDelimitedSSNContextBytes = 64 * 1024

func hasDelimitedSSNColumnHeader(text string, candidateStart int) bool {
	if candidateStart <= 0 || candidateStart > len(text) {
		return false
	}
	rowSearchStart := candidateStart - maxDelimitedSSNContextBytes
	if rowSearchStart < 0 {
		rowSearchStart = 0
	}
	rowBreak := strings.LastIndexByte(text[rowSearchStart:candidateStart], '\n')
	if rowBreak < 0 {
		return false
	}
	rowStart := rowSearchStart + rowBreak + 1
	headerEnd := rowStart - 1
	if headerEnd > 0 && text[headerEnd-1] == '\r' {
		headerEnd--
	}
	headerSearchStart := headerEnd - maxDelimitedSSNContextBytes
	if headerSearchStart < 0 {
		headerSearchStart = 0
	}
	headerBreak := strings.LastIndexByte(text[headerSearchStart:headerEnd], '\n')
	headerStart := headerSearchStart
	if headerBreak >= 0 {
		headerStart += headerBreak + 1
	} else if headerSearchStart != 0 {
		return false
	}

	rowEnd := len(text)
	if boundedEnd := rowStart + maxDelimitedSSNContextBytes; boundedEnd < rowEnd {
		rowEnd = boundedEnd
	}
	if nextBreak := strings.IndexByte(text[candidateStart:rowEnd], '\n'); nextBreak >= 0 {
		rowEnd = candidateStart + nextBreak
	}
	if rowEnd > rowStart && text[rowEnd-1] == '\r' {
		rowEnd--
	}
	header := text[headerStart:headerEnd]
	row := text[rowStart:rowEnd]

	delimiter := byte(0)
	for _, candidate := range []byte{'\t', ','} {
		if strings.IndexByte(header, candidate) >= 0 && strings.IndexByte(row, candidate) >= 0 {
			delimiter = candidate
			break
		}
	}
	if delimiter == 0 {
		return false
	}
	column, ok := delimitedFieldIndexAt(row, candidateStart-rowStart, delimiter)
	if !ok {
		return false
	}
	headerField, ok := delimitedField(header, column, delimiter)
	if !ok {
		return false
	}
	label := strings.ToLower(strings.Trim(strings.TrimSpace(headerField), `"'`))
	label = strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(label)), " ")
	switch label {
	case "ssn", "social security", "social security number", "taxpayer id", "taxpayer identification":
		return true
	default:
		return false
	}
}

func delimitedFieldIndexAt(row string, offset int, delimiter byte) (int, bool) {
	if offset < 0 || offset > len(row) {
		return 0, false
	}
	column := 0
	quoted := false
	for index := 0; index < offset; index++ {
		switch row[index] {
		case '"':
			if quoted && index+1 < offset && row[index+1] == '"' {
				index++
				continue
			}
			quoted = !quoted
		default:
			if row[index] == delimiter && !quoted {
				column++
			}
		}
	}
	return column, true
}

func delimitedField(row string, wanted int, delimiter byte) (string, bool) {
	if wanted < 0 {
		return "", false
	}
	column := 0
	start := 0
	quoted := false
	for index := 0; index <= len(row); index++ {
		if index == len(row) || (row[index] == delimiter && !quoted) {
			if column == wanted {
				return row[start:index], true
			}
			column++
			start = index + 1
			continue
		}
		if row[index] != '"' {
			continue
		}
		if quoted && index+1 < len(row) && row[index+1] == '"' {
			index++
			continue
		}
		quoted = !quoted
	}
	return "", false
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

func validIBAN(candidate string) bool {
	compact := make([]byte, 0, len(candidate))
	for _, character := range []byte(candidate) {
		if character == ' ' {
			continue
		}
		if !((character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')) {
			return false
		}
		compact = append(compact, character)
	}
	if len(compact) < 15 || len(compact) > 34 ||
		compact[0] < 'A' || compact[0] > 'Z' ||
		compact[1] < 'A' || compact[1] > 'Z' ||
		compact[2] < '0' || compact[2] > '9' ||
		compact[3] < '0' || compact[3] > '9' {
		return false
	}
	expectedLength, registered := ibanLengthsByCountry[string(compact[:2])]
	if !registered || len(compact) != expectedLength {
		return false
	}

	remainder := 0
	for index := 0; index < len(compact); index++ {
		character := compact[(index+4)%len(compact)]
		if character >= '0' && character <= '9' {
			remainder = (remainder*10 + int(character-'0')) % 97
			continue
		}
		remainder = (remainder*100 + int(character-'A') + 10) % 97
	}
	return remainder == 1
}

func credibleBulkCSVContext(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	candidate := strings.TrimPrefix(text[start:end], "\n")
	candidate = strings.TrimPrefix(candidate, "\r")
	headerEnd := strings.IndexByte(candidate, '\n')
	if headerEnd < 0 {
		return false
	}
	headerLine := strings.TrimSuffix(candidate[:headerEnd], "\r")
	firstDataLine := strings.TrimSuffix(candidate[headerEnd+1:], "\r")
	delimiter, header, strongPII, ok := bulkCSVHeader(headerLine)
	if !ok {
		return false
	}
	firstData, ok := parseDelimitedRow(firstDataLine, delimiter)
	if !ok || len(firstData) != len(header) || !hasDelimitedData(firstData) {
		return false
	}
	if strongPII {
		return true
	}

	// A single first/last-name row is a weak bulk-data signal. Require a
	// second well-formed record while preserving one-row recall for stronger
	// SSN, payment-card, and account-number headers.
	nextLine, ok := nextDelimitedDataLine(text[end:])
	if !ok {
		return false
	}
	secondData, ok := parseDelimitedRow(nextLine, delimiter)
	return ok && len(secondData) == len(header) && hasDelimitedData(secondData)
}

func bulkCSVHeader(line string) (rune, []string, bool, bool) {
	for _, delimiter := range []rune{',', '\t'} {
		fields, ok := parseDelimitedRow(line, delimiter)
		if !ok || len(fields) < 2 {
			continue
		}
		piiColumns := 0
		strongPII := false
		for _, field := range fields {
			name := normalizedCSVColumnName(field)
			switch {
			case strings.HasSuffix(name, "firstname"), strings.HasSuffix(name, "lastname"):
				piiColumns++
			case strings.HasSuffix(name, "ssn"),
				strings.HasSuffix(name, "socialsecurity"),
				strings.HasSuffix(name, "creditcard"),
				strings.HasSuffix(name, "cardnumber"),
				strings.HasSuffix(name, "accountnumber"):
				piiColumns++
				strongPII = true
			}
		}
		if piiColumns >= 2 {
			return delimiter, fields, strongPII, true
		}
	}
	return 0, nil, false, false
}

func normalizedCSVColumnName(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, strings.TrimSpace(value))
}

func parseDelimitedRow(line string, delimiter rune) ([]string, bool) {
	reader := csv.NewReader(strings.NewReader(line))
	reader.Comma = delimiter
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	fields, err := reader.Read()
	if err != nil || len(fields) == 0 {
		return nil, false
	}
	if _, err := reader.Read(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

func hasDelimitedData(fields []string) bool {
	for _, field := range fields {
		if strings.TrimSpace(field) != "" {
			return true
		}
	}
	return false
}

func nextDelimitedDataLine(remainder string) (string, bool) {
	if strings.HasPrefix(remainder, "\r\n") {
		remainder = remainder[2:]
	} else if strings.HasPrefix(remainder, "\n") {
		remainder = remainder[1:]
	} else {
		return "", false
	}
	if lineEnd := strings.IndexByte(remainder, '\n'); lineEnd >= 0 {
		remainder = remainder[:lineEnd]
	}
	remainder = strings.TrimSuffix(remainder, "\r")
	return remainder, remainder != ""
}

func acceptedLocalSecretMatch(kind localSecretDetectorKind, match string) bool {
	candidate := assignmentValue(match)
	if kind == localSecretDetectorBearer {
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
	if kind == localSecretDetectorPassword {
		return true
	}
	if obviousCredentialPlaceholder(candidate) {
		return false
	}
	return kind != localSecretDetectorBearer ||
		credentialEntropy(compactCredential(candidate)) >= 2.5
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
	// Private-key candidates are validated against the complete source text in
	// acceptedRuleMatchAt. Other credential formats expose a compact value that
	// can be checked for public examples and placeholder entropy here.
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
	//
	// Deliberately NOT extended to provider-prefixed keys. A padded synthetic
	// token and a leaked credential are indistinguishable by character variety:
	// the security corpus asserts that ghp_abc123ffff… (36 f's) MUST be
	// detected, while an AKIA key with a zero-filler tail looks the same to any
	// entropy or repetition measure. Where the two cannot be separated, the
	// product's choice is to report.
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
