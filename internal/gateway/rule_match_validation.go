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
	"net/netip"
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/paymentcard"
	"github.com/defenseclaw/defenseclaw/internal/secretshape"
)

var ssnListCandidatePattern = lazyregexp.New(`\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b`)

var literalHTTPIPv4Pattern = lazyregexp.New(`(?i)https?://((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?::[0-9]+)?/`)

var nonPublicLiteralIPv4Blocks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
}

var (
	nodeEvalInvocationPattern    = lazyregexp.New(`(?i)\bnode(?:js)?\s+(?:-e|--eval)(?:\s+|=)`)
	childProcessExecSinkPattern  = lazyregexp.New(`(?is)(?:\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process)\s*\.\s*exec(?:Sync)?\s*\(\s*$`)
	childProcessSpawnSinkPattern = lazyregexp.New(`(?is)(?:\brequire\s*\(\s*["'](?:node:)?child_process["']\s*\)|\bchild_process)\s*\.\s*spawn(?:Sync)?\s*\(\s*["'](?:/bin/)?(?:ba|da|z|k)?sh["']\s*,\s*\[\s*["']-c["']\s*,\s*$`)
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
	return firstAcceptedRuleMatchBy(rule, text, textMatches{
		first: func() []int { return rule.Pattern.FindStringIndex(text) },
		all:   func() [][]int { return rule.Pattern.FindAllStringIndex(text, -1) },
	})
}

// textMatches finds the matches of one regex in one text: the first, and all
// of them. A scan of a large text supplies the search in windows
// (rxprefilter.Text); the others the plain regex methods.
type textMatches struct {
	first func() []int
	all   func() [][]int
}

func firstAcceptedRuleMatchBy(rule PatternRule, text string, matches textMatches) []int {
	if ruleMatchValidator(rule.ID) == nil {
		if rule.Pattern == nil || text == "" {
			return nil
		}
		return matches.first()
	}
	return firstAcceptedMatchBy(rule.Pattern, text, matches, func(match string, start, end int) bool {
		return acceptedRuleMatchAt(rule.ID, text, match, start, end)
	})
}

func firstAcceptedRegexMatch(pattern *regexp.Regexp, text string, accept func(string) bool) []int {
	return firstAcceptedRegexMatchAt(pattern, text, func(match string, _, _ int) bool {
		return accept(match)
	})
}

func firstAcceptedRegexMatchAt(pattern *regexp.Regexp, text string, accept func(match string, start, end int) bool) []int {
	return firstAcceptedMatchBy(pattern, text, textMatches{
		first: func() []int { return pattern.FindStringIndex(text) },
		all:   func() [][]int { return pattern.FindAllStringIndex(text, -1) },
	}, accept)
}

func firstAcceptedMatchBy(pattern *regexp.Regexp, text string, matches textMatches, accept func(match string, start, end int) bool) []int {
	if pattern == nil || text == "" {
		return nil
	}
	// The first candidate is usually decisive: accept it without enumerating
	// every later candidate of a large document.
	first := matches.first()
	if first == nil {
		return nil
	}
	if accept(text[first[0]:first[1]], first[0], first[1]) {
		return first
	}
	// Enumerate against the complete input once. Restarting a regex on
	// text[offset:] changes the meaning of ^ and word-boundary assertions after
	// a rejected candidate, allowing a non-match in the original text to become
	// a match solely because the validation cursor moved.
	for _, loc := range matches.all()[1:] {
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
	validator := ruleMatchValidator(ruleID)
	return validator == nil || validator(text, match, start, end)
}

// A nil validator means the regex match itself is decisive. Keep this dispatch
// shared with firstAcceptedRuleMatch so a rule with later valid candidates can
// never take the first-match shortcut.
func ruleMatchValidator(ruleID string) func(text, match string, start, end int) bool {
	switch ruleID {
	case "ENT-BULK-SSN", "ENT-BULK-SSN-NOHYPHEN":
		return func(text, match string, start, end int) bool {
			return validUSSSN(match) && credibleSSNContext(text, start, end)
		}
	case "ENT-CC-VISA", "ENT-CC-MC", "ENT-CC-AMEX", "ENT-CC-DISCOVER":
		return func(text, match string, start, end int) bool {
			return validPaymentCardCandidateAt(text, match, start, end)
		}
	case "PII-CARD-LABELED":
		// Label-bound (privacy-high-assurance): no Luhn or scheme check by
		// design, but the digits must not come from a UUID or other token.
		return func(text, _ string, start, end int) bool {
			return paymentcard.LabeledRunAt(text, start, end)
		}
	case "ENT-IBAN":
		return func(_, match string, _, _ int) bool { return validIBAN(match) }
	case "ENT-EMAIL-BULK", "PII-EMAIL-FIELD":
		// The labeled forms (PII-EMAIL-FIELD, and ENT-EMAIL-BULK in
		// privacy-high-assurance) skip git's own identity key: git config
		// --list prints user.email=..., setup rather than a record field.
		return func(text, match string, start, end int) bool {
			return !gitUserEmailKeyAt(text, start) && credibleEmailContext(text, match, start, end)
		}
	case "PII-EMAIL-LIST":
		// One address is ENT-EMAIL-BULK (LOW): a vendor no-reply address in
		// an agent's own instructions must not block (substrate-1:GAP-0149).
		// Five or more distinct addresses together (a CSV, a list, mailto
		// links) is a bulk disclosure (substrate-1:GAP-0159).
		// Only per-address checks apply: the count already keeps a single
		// vendor address out, and the whole-text phrases of
		// credibleEmailContext ("ssh", "bcc to") must not hide a bulk dump.
		// The bounded window check runs before anything else.
		return func(text, _ string, start, end int) bool {
			return emailListMember(text, start, end) && emailListAt(text, start)
		}
	case "ENT-PHONE-E164":
		return func(text, match string, start, _ int) bool {
			return credibleE164Context(text, match, start)
		}
	case "ENT-BULK-CSV-PII":
		return func(text, _ string, start, end int) bool {
			return credibleBulkCSVContext(text, start, end)
		}
	case "SEC-PRIVKEY":
		return func(text, match string, start, _ int) bool {
			return acceptedCredentialMatch(ruleID, match) && secretshape.ValidPrivateKeyPEMAt(text, start)
		}
	case "CMD-RM-RF":
		return func(text, _ string, start, end int) bool {
			return acceptedRecursiveRootDeleteAt(text, start, end)
		}
	case "CMD-WIN-REG-PERSIST":
		return func(text, _ string, _, _ int) bool {
			for _, pattern := range windowsRegistryPersistencePatterns {
				if pattern.MatchString(text) {
					return true
				}
			}
			return false
		}
	case "exec.remote_ip_download_execute_same_artifact":
		return func(_, match string, _, _ int) bool { return acceptedPublicIPv4Download(match) }
	}
	if ruleID == secretAssignmentRuleID {
		return func(text, match string, start, _ int) bool {
			// The call text is JSON: an escaped newline, return or tab is the two
			// characters backslash and n, r or t, and the word boundary the
			// pattern found sits between them and the key. The letter is the
			// escape, not the first letter of the key.
			if start > 0 && text[start-1] == '\\' && strings.IndexByte("nrt", match[0]) >= 0 {
				match = match[1:]
			}
			return acceptedSecretAssignment(match)
		}
	}
	if strings.HasPrefix(ruleID, "SEC-") {
		return func(_, match string, _, _ int) bool { return acceptedCredentialMatch(ruleID, match) }
	}
	return nil
}

// acceptedPublicIPv4Download keeps the parser-fallback rule aligned with its
// semantic owner. A syntactically complete same-artifact chain is not a remote
// public-IP chain when its URL names loopback, private, link-local, benchmark,
// documentation, multicast, or otherwise reserved address space.
func acceptedPublicIPv4Download(match string) bool {
	parts := literalHTTPIPv4Pattern.FindStringSubmatch(match)
	if len(parts) != 2 {
		return false
	}
	address, err := netip.ParseAddr(parts[1])
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range nonPublicLiteralIPv4Blocks {
		if prefix.Contains(address) {
			return false
		}
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
	if emailIsPathSegment(text, start, end) {
		return false
	}
	if start >= 0 && end >= start && end <= len(text) {
		if gitUserEmailPlaceholder(text[:start], matchLower) {
			return false
		}
		// Only what is glued to the address can make it a locator: a
		// following word and colon on the same or the next line is the next
		// field of a label: value record (GAP-0234).
		tail := strings.TrimLeft(text[end:], "\"'`")
		if strings.HasPrefix(tail, ":") {
			return false
		}
		// Git/SSH host aliases can contain dots and suffixes, so the generic
		// email regex may stop early at an apparent TLD in a locator such as
		// git@github.com-work:cisco/repo.git. Treat a contiguous host suffix
		// followed by ':' as a remote locator rather than a person address.
		if colon := strings.IndexByte(tail, ':'); colon > 0 && (tail[0] == '.' || tail[0] == '-') {
			hostSuffix := tail[:colon]
			if strings.IndexFunc(hostSuffix, func(char rune) bool {
				return (((((char < 'a' || char > 'z') && (char < 'A' || char > 'Z')) && (char < '0' || char > '9')) && char != '.') && char != '-')
			}) == -1 {
				return false
			}
		}
	}
	return true
}

const (
	// emailListMinDistinct distinct addresses make a bulk email list.
	emailListMinDistinct = 5
	// emailListWindow bounds, in bytes from the first address, where the
	// other addresses of one list must be.
	emailListWindow = 4096
	// emailListMaxScan bounds the addresses read per candidate, so a large
	// log that repeats one address costs a bounded scan per match.
	emailListMaxScan = 16
)

var emailAddressPattern = lazyregexp.New(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)

// gitIdentityLinePattern is the text from the start of a line up to the
// first address of a commit identity: git log and show headers, commit
// trailers and git shortlog -e rows. A git log of a busy repository lists
// many authors; that is project history, not a disclosure of addresses.
// Only the first address after the label is the identity, so a label line
// cannot carry a list (no '@' may sit between the label and the address).
var gitIdentityLinePattern = lazyregexp.New(`(?i)^(?:[\s>*-]*(?:author|commit|committer|co-authored-by|signed-off-by|reviewed-by|acked-by|tested-by|reported-by|suggested-by|helped-by)\s*:|\s*\d+\t)[^@\n]*$`)

// emailListAt reports emailListMinDistinct or more distinct list members in
// the window that starts at the address at start.
func emailListAt(text string, start int) bool {
	end := min(len(text), start+emailListWindow)
	seen := make(map[string]struct{}, emailListMinDistinct)
	for _, loc := range emailAddressPattern.Regexp().FindAllStringIndex(text[start:end], emailListMaxScan) {
		s, e := start+loc[0], start+loc[1]
		if !emailListMember(text, s, e) {
			continue
		}
		seen[strings.ToLower(text[s:e])] = struct{}{}
		if len(seen) >= emailListMinDistinct {
			return true
		}
	}
	return false
}

// gitUserEmailKeyAt reports a labeled-field match that is git's user.email
// key (git config --list, .gitconfig).
func gitUserEmailKeyAt(text string, start int) bool {
	return start >= 5 && strings.EqualFold(text[start-5:start], "user.")
}

// emailListMember applies the per-address checks of credibleEmailContext
// that do not read the whole text, plus the commit-identity exclusion.
func emailListMember(text string, start, end int) bool {
	if start < 0 || end > len(text) || start >= end {
		return false
	}
	address := strings.ToLower(text[start:end])
	if strings.HasSuffix(address, ".compute.amazonaws.com") || emailDomainLooksLikeNumericHost(address) ||
		emailIsPathSegment(text, start, end) {
		return false
	}
	if strings.HasPrefix(strings.TrimLeft(text[end:], "\"'`"), ":") {
		return false
	}
	lineStart := strings.LastIndexByte(text[:start], '\n') + 1
	return !gitIdentityLinePattern.MatchString(text[lineStart:start])
}

// gitUserEmailPlaceholder reports a documentation-domain address given as
// git's user.email, as git's own "Author identity unknown" hint prints it
// (git config --global user.email "you@example.com"): setup text, not a
// person's address. The hint usually arrives inside a JSON-encoded tool
// response, where the quote before the address is escaped (\"), so the
// backslash is trimmed along with the quotes.
func gitUserEmailPlaceholder(before, email string) bool {
	key := strings.TrimRight(strings.ToLower(before), " \t\"'=\\")
	if !strings.HasSuffix(key, "user.email") {
		return false
	}
	_, domain, _ := strings.Cut(email, "@")
	switch domain {
	case "example.com", "example.net", "example.org":
		return true
	}
	return strings.HasSuffix(domain, ".example")
}

// emailIsPathSegment reports an address-shaped match that is one folder or
// file name of a local path, such as the home folder of a directory account
// (/home/user@corp.example/project): a path, not someone's address
// (GAP-1286). Only a token that starts like a local path counts; a URL with
// or without a scheme, an scp host:path and a UNC \\host\share path go to
// another host, so the address still alerts (GAP-1934, GAP-1973).
func emailIsPathSegment(text string, start, end int) bool {
	if start <= 0 || start > len(text) || end > len(text) || (text[start-1] != '/' && text[start-1] != '\\') {
		return false
	}
	if end != len(text) && strings.IndexByte("/\\ \t\r\n\"'`:;,)", text[end]) < 0 {
		return false
	}
	return tokenIsLocalPath(text[:start])
}

// tokenIsLocalPath reports a path whose token starts like a local path: "/"
// (not "//"), "~/", "./", "../", a drive "X:\" or "X:/", or "file:///". The
// word (after whitespace or a quote) is read first: a URL to another host
// ("://" with a scheme other than file, or a leading "//") is remote, also
// when a query value in it starts with "/" (GAP-2037). Only then is the
// word cut at "=" and at the shell operators < > ( | & ; , so a path after
// a redirect, an open paren or an option value is read on its own, and a
// glued short option ("-C/home/...") or a leading $NAME/, ${NAME}/ or
// $NAME: (a PATH list) is dropped before the shape test (GAP-2011).
func tokenIsLocalPath(before string) bool {
	word := before[strings.LastIndexAny(before, " \t\r\n\"'`")+1:]
	if strings.HasPrefix(word, "//") || wordHoldsRemoteURL(word) {
		return false
	}
	token := trimShellPathPrefix(word[strings.LastIndexAny(word, "=<>(|&;,")+1:])
	switch {
	case strings.HasPrefix(token, "//"):
		return false
	case strings.HasPrefix(token, "/"), strings.HasPrefix(token, "~/"), strings.HasPrefix(token, "~\\"),
		strings.HasPrefix(token, "./"), strings.HasPrefix(token, "../"),
		strings.HasPrefix(token, ".\\"), strings.HasPrefix(token, "..\\"):
		return true
	case len(token) >= 3 && token[1] == ':' && (token[2] == '\\' || token[2] == '/') &&
		(token[0]|0x20 >= 'a' && token[0]|0x20 <= 'z'):
		return true
	}
	scheme, rest, isURL := strings.Cut(token, "://")
	return isURL && strings.EqualFold(scheme, "file") && strings.HasPrefix(rest, "/")
}

// trimShellPathPrefix drops what the shell puts before a local path in one
// word: a glued short option ("-C/home/x" -> "/home/x"), shell variables
// that expand to a folder or a PATH list ("$HOME/../x", "${HOME}/x",
// "$PATH:/home/x" -> "/../x", "/x", "/home/x"), and the leading ":" of a PATH
// list whose variable the shell-obfuscation view already removed
// (normalizeShell turns "PATH=$PATH:/home/x" into "PATH=:/home/x"). A
// host:/path keeps its host, so it stays remote.
func trimShellPathPrefix(token string) string {
	return strings.TrimLeft(trimShellVariables(token), ":")
}

func trimShellVariables(token string) string {
	if len(token) > 2 && token[0] == '-' && (token[1]|0x20 >= 'a' && token[1]|0x20 <= 'z') &&
		strings.IndexByte("/~.", token[2]) >= 0 {
		token = token[2:]
	}
	for strings.HasPrefix(token, "$") {
		rest := token[1:]
		if strings.HasPrefix(rest, "{") {
			closing := strings.IndexByte(rest, '}')
			if closing < 2 || !shellVariableName(rest[1:closing]) {
				return token
			}
			rest = rest[closing+1:]
		} else {
			n := 0
			for n < len(rest) && shellNameByte(rest[n], n == 0) {
				n++
			}
			if n == 0 {
				return token
			}
			rest = rest[n:]
		}
		switch {
		case strings.HasPrefix(rest, "/"):
			return rest
		case strings.HasPrefix(rest, ":"):
			token = rest[1:]
		default:
			return token
		}
	}
	return token
}

func shellVariableName(name string) bool {
	for i := 0; i < len(name); i++ {
		if !shellNameByte(name[i], i == 0) {
			return false
		}
	}
	return name != ""
}

// shellNameByte reports a byte of a shell variable name (a digit only after
// the first byte).
func shellNameByte(c byte, first bool) bool {
	return c == '_' || c|0x20 >= 'a' && c|0x20 <= 'z' || !first && c >= '0' && c <= '9'
}

// urlSchemeByte reports a byte of a URL scheme (RFC 3986: ALPHA DIGIT + - .).
func urlSchemeByte(c byte) bool {
	return c|0x20 >= 'a' && c|0x20 <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '.' || c == '-'
}

// wordHoldsRemoteURL reports a word that holds a URL with a scheme other than
// file ("https://host/...", "--url=https://host/..."): it goes to another host.
func wordHoldsRemoteURL(word string) bool {
	at := strings.Index(word, "://")
	if at <= 0 {
		return false
	}
	start := at
	for start > 0 {
		if !urlSchemeByte(word[start-1]) {
			break
		}
		start--
	}
	scheme := word[start:at]
	return scheme != "" && !strings.EqualFold(scheme, "file")
}

// isoDatePlus is "+YYYY-MM-DD": a date after a plus sign (a diff's added
// line, a UTC offset), not a country code.
var isoDatePlus = lazyregexp.New(`^\+\d{4}-\d{2}-\d{2}`)

// credibleE164Context rejects the two plus signs that are not a phone
// number's (GAP-1284): a date right after the plus, and the "+" that starts
// an added line of a unified diff ("+1761377703126", "+2026-10-02 07:35").
func credibleE164Context(text, match string, start int) bool {
	plus := strings.IndexByte(match, '+')
	if plus < 0 {
		return true
	}
	if isoDatePlus.MatchString(match[plus:]) {
		return false
	}
	at := start + plus
	lineStart := at == 0 || (at > 0 && at <= len(text) && text[at-1] == '\n')
	return !lineStart || !looksLikeUnifiedDiff(text)
}

// looksLikeUnifiedDiff reports text that holds a unified diff hunk header.
func looksLikeUnifiedDiff(text string) bool {
	return strings.HasPrefix(text, "@@ -") || strings.Contains(text, "\n@@ -")
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

// acceptedLocalPIIMatch applies the same structural checks to the legacy local
// PII regex lane. A match made only of digits and separators whose digits
// carry a card-scheme prefix and length is judged by the shared payment card
// rules (the built-in local card regexes always produce that shape). Any
// other operator pattern (a labeled match, an IMEI, an account number)
// keeps its historical behavior: a 13-19 digit candidate must pass Luhn.
func acceptedLocalPIIMatch(match string) bool {
	digits := decimalDigits(match)
	if len(digits) == 9 && strings.Count(match, "-") == 2 {
		return validUSSSN(match)
	}
	if len(digits) >= 13 && len(digits) <= 19 {
		if localPANShaped(match, digits) {
			return validPaymentCardCandidate(match)
		}
		return paymentcard.Luhn(digits) && !knownPublicTestPAN(digits)
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
	if len(digits) >= 13 && len(digits) <= 19 {
		if localPANShaped(match, digits) {
			return !paymentcard.Embedded(text, start, end)
		}
		// Historical rule for operator patterns: not the fraction of a
		// float (GAP-2062).
		return start < 2 || text[start-1] != '.' || text[start-2] < '0' || text[start-2] > '9'
	}
	return true
}

// localPANShaped reports a local-lane match that is a bare number (digits
// and separators only) whose digits have a payment-card scheme prefix and
// length.
func localPANShaped(match, digits string) bool {
	for i := 0; i < len(match); i++ {
		c := match[i]
		if (c < '0' || c > '9') && c != ' ' && c != '\t' && c != '-' && c != '.' {
			return false
		}
	}
	return paymentcard.Scheme(digits) != ""
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
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') {
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
		// A password that is one reference to a variable (${DB_PASSWORD},
		// $DB_PASS, <password>) is a template slot, not a password: nothing is
		// exposed. A reference in front of literal characters is a password.
		return !secretAssignmentWholeReference.MatchString(strings.TrimSpace(candidate))
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

// secretAlnumCount counts the letters and digits of s; = + / padding carries no secret.
func secretAlnumCount(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			n++
		}
	}
	return n
}

// awsDocumentedSecretKey is the example secret access key of the AWS documentation.
const awsDocumentedSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func knownPublicCredentialExample(ruleID, candidate string) bool {
	switch ruleID {
	case "SEC-AWS-KEY":
		return strings.EqualFold(candidate, "IOSFODNN7EXAMPLE")
	case "SEC-AWS-SECRET":
		// Only the pair AWS documents. The raw text carries it exactly. Shell
		// normalization drops its slashes and may run the escaped newlines
		// after it into the value, so there the slash-free documented value
		// followed by a few characters is the same pair; a longer remainder
		// is another secret.
		if candidate == awsDocumentedSecretKey {
			return true
		}
		rest, ok := strings.CutPrefix(strings.ReplaceAll(candidate, "/", ""), strings.ReplaceAll(awsDocumentedSecretKey, "/", ""))
		// What follows is the debris of the escaped newlines after the value
		// (the letters n, r, t), the rule line under it (= and +) and a word of
		// the next line: too few letters and digits to hold another secret.
		return ok && secretAlnumCount(rest) <= 12
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

// validPaymentCardCandidate reports whether value alone is a payment card
// number under the shared paymentcard rules (Luhn, a real scheme prefix and
// length, a card layout). The six canonical public test PANs that fill
// provider documentation are not treated as cards.
func validPaymentCardCandidate(value string) bool {
	return paymentcard.Valid(value) && !knownPublicTestPAN(paymentcard.Digits(value))
}

// validPaymentCardCandidateAt adds the token-boundary check: a digit run glued
// to a longer token (UUID, hash, trace id, decimal, versioned id) is not a
// card (substrate-1:GAP-0132).
func validPaymentCardCandidateAt(text, match string, start, end int) bool {
	return validPaymentCardCandidate(match) && !paymentcard.Embedded(text, start, end)
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
