// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

var (
	providerTokenRE = regexp.MustCompile(`(?:AKIA|ASIA|AROA|AGPA|AIDA|AIPA|ANPA|ANVA)[A-Z0-9]{16}|(?:ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|glpat-[A-Za-z0-9_-]{20,255}|xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,128}|(?:xoxp-|xoxa-|xoxr-|xoxs-)[A-Za-z0-9-]{24,200}|(?:sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|pk_test_)[A-Za-z0-9]{20,128}|AIza[A-Za-z0-9_-]{35}|sk-proj-[A-Za-z0-9_+=.-]{16,248}|sk-ant-[A-Za-z0-9_+=.-]{17,249}|sk-or-[A-Za-z0-9_+=.-]{18,250}|sk-[A-Za-z0-9_+=.-]{21,253}|eyJ[A-Za-z0-9_-]*={0,2}\.[A-Za-z0-9_-]+={0,2}\.[A-Za-z0-9_-]+={0,2}`)
	authorizationRE = regexp.MustCompile(`(?i)^(authorization|proxy-authorization)[\t ]*[:=][\t ]*(bearer|basic|digest|token|apikey)[\t ]+([^\r\n]+)$`)
	assignmentKeyRE = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|client_secret|api_key|apikey|access_token|refresh_token|private_key|signing_key)`)
	dsnKeyRE        = regexp.MustCompile(`(?i)(password|passwd|pwd|pass|secret|client_secret|api_key|apikey|access_token|refresh_token|token|signature|credential)`)
	entropyRE       = regexp.MustCompile(`[A-Za-z0-9+/_=-]{20,256}`)
	uriRE           = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\x00-\x20<>"']+`)
	cloudLabelRE    = regexp.MustCompile(`(?i)(aws_account_id|azure_tenant_id|azure_subscription_id|gcp_project_number|gcp_project_id)[\t ]*[:=][\t ]*([A-Za-z0-9-]+)`)
	arnRE           = regexp.MustCompile(`arn:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+:[A-Za-z0-9_-]*:([0-9]{12}):[^\x00-\x20:]+`)
	azurePathRE     = regexp.MustCompile(`(?i)/(subscriptions|tenants)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)`)
	gcpPathRE       = regexp.MustCompile(`(?:^|/)projects/([a-z][a-z0-9-]{4,28}[a-z0-9])(?:/|$)`)
	gcpServiceRE    = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([a-z][a-z0-9-]{4,28}[a-z0-9])\.iam\.gserviceaccount\.com`)
	emailRE         = regexp.MustCompile(`[A-Za-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_` + "`" + `{|}~-]+)*@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+`)
	telephoneRE     = regexp.MustCompile(`(?:\+1[ .-])?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[ .-][2-9][0-9]{2}[ .-][0-9]{4}`)
	nationalIDRE    = regexp.MustCompile(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)
)

func recognize(
	id DetectorID,
	input string,
	fieldClass observability.FieldClass,
	prior []acceptedMatch,
) ([]candidate, error) {
	switch id {
	case "credentials.api_token":
		return recognizeProviderTokens(input), nil
	case "credentials.private_key":
		return recognizePrivateKeys(input), nil
	case "credentials.authorization":
		return recognizeAuthorization(input), nil
	case "credentials.cookie":
		return recognizeCookies(input), nil
	case "credentials.connection_string":
		return recognizeConnectionStrings(input)
	case "secrets.assignment":
		return recognizeAssignments(input), nil
	case "secrets.high_entropy":
		return recognizeHighEntropy(input, fieldClass, prior), nil
	case "secrets.url_query":
		return recognizeURLQueries(input)
	case "secrets.cloud_account_identifier":
		return recognizeCloudIdentifiers(input), nil
	case "pii.email":
		return recognizeEmails(input), nil
	case "pii.telephone":
		return recognizeTelephones(input), nil
	case "pii.national_identifier":
		return recognizeNationalIdentifiers(input), nil
	case "pii.payment_card":
		return recognizePaymentCards(input), nil
	case "pii.ip_address":
		return recognizeIPAddresses(input), nil
	default:
		return nil, detectorError(FailureValidator)
	}
}

func recognizeProviderTokens(input string) []candidate {
	indices := providerTokenRE.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		accepted := providerBoundary(input, index[0], index[1])
		value := input[index[0]:index[1]]
		if strings.HasPrefix(value, "eyJ") && strings.Count(value, ".") == 2 {
			accepted = accepted && validJWT(value)
		}
		result = append(result, candidate{start: index[0], end: index[1], accepted: accepted})
	}
	return result
}

func providerBoundary(input string, start, end int) bool {
	return (start == 0 || !isProviderByte(input[start-1])) &&
		(end == len(input) || !isProviderByte(input[end]))
}

func isProviderByte(value byte) bool {
	return isASCIIAlphaNum(value) || strings.ContainsRune("_+=.-", rune(value))
}

func validJWT(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[2] == "" || len(value) > 3074 {
		return false
	}
	for _, part := range parts {
		if len(part) < 2 || len(part) > 1024 {
			return false
		}
	}
	for index, part := range parts {
		decoded, ok := decodeJWTPart(part)
		if !ok || len(decoded) == 0 || len(decoded) > 8192 {
			return false
		}
		if index < 2 && !validBoundedJSONObject(decoded) {
			return false
		}
	}
	return true
}

func decodeJWTPart(part string) ([]byte, bool) {
	trimmed := strings.TrimRight(part, "=")
	padding := len(part) - len(trimmed)
	if padding > 2 || strings.ContainsRune(trimmed, '=') {
		return nil, false
	}
	if padding > 0 {
		if len(part)%4 != 0 {
			return nil, false
		}
		decoded, err := base64.URLEncoding.DecodeString(part)
		return decoded, err == nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(trimmed)
	return decoded, err == nil
}

func validBoundedJSONObject(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	members := 0
	var parseValue func(int) bool
	parseValue = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]struct{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return false
				}
				if _, duplicate := seen[key]; duplicate {
					return false
				}
				seen[key] = struct{}{}
				members++
				if members > 256 || !parseValue(depth+1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for decoder.More() {
				members++
				if members > 256 || !parseValue(depth+1) {
					return false
				}
			}
			end, err := decoder.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !parseValue(1) || len(encoded) == 0 || encoded[0] != '{' {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func recognizePrivateKeys(input string) []candidate {
	const begin = "-----BEGIN "
	result := []candidate{}
	search := 0
	for search < len(input) {
		relative := strings.Index(input[search:], begin)
		if relative < 0 {
			break
		}
		start := search + relative
		search = start + len(begin)
		if start > 0 && input[start-1] != '\n' {
			continue
		}
		lineEnd, ending := nextLine(input, start)
		if lineEnd < 0 {
			result = append(result, candidate{start: start, end: minInt(len(input), start+len(begin)), accepted: false})
			continue
		}
		header := input[start:lineEnd]
		if !strings.HasSuffix(header, "-----") {
			continue
		}
		label := strings.TrimSuffix(strings.TrimPrefix(header, begin), "-----")
		if !allowedPrivateKeyLabel(label) {
			continue
		}
		footer := "-----END " + label + "-----"
		position := lineEnd + len(ending)
		payloadLines := []string{}
		valid := true
		end := position
		for position <= len(input) {
			currentEnd, currentEnding := nextLineAllowEOF(input, position)
			if currentEnd < position {
				valid = false
				break
			}
			line := input[position:currentEnd]
			if line == footer {
				end = currentEnd
				break
			}
			if currentEnding == "" || currentEnding != ending || len(line) < 4 || len(line) > 64 || !validPEMLineLexical(line) {
				valid = false
				end = currentEnd
				break
			}
			payloadLines = append(payloadLines, line)
			position = currentEnd + len(currentEnding)
			end = position
			if end-start > 65536 {
				valid = false
				break
			}
		}
		if end <= start {
			end = minInt(len(input), start+len(header))
		}
		valid = valid && end-start <= 65536 && len(payloadLines) > 0 && input[maxInt(start, end-len(footer)):end] == footer && validPEMPayload(payloadLines)
		result = append(result, candidate{start: start, end: end, accepted: valid})
		search = maxInt(search, end)
	}
	return result
}

func allowedPrivateKeyLabel(label string) bool {
	switch label {
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "OPENSSH PRIVATE KEY":
		return true
	default:
		return false
	}
}

func validPEMPayload(lines []string) bool {
	for i, line := range lines {
		if len(line)%4 != 0 {
			return false
		}
		for j, character := range []byte(line) {
			if character == '=' {
				if i != len(lines)-1 || j < len(line)-2 {
					return false
				}
				continue
			}
			if !isBase64Byte(character) {
				return false
			}
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.Join(lines, ""))
	return err == nil && len(decoded) > 0
}

func validPEMLineLexical(line string) bool {
	if len(line)%4 != 0 {
		return false
	}
	firstPadding := -1
	for index, character := range []byte(line) {
		if character == '=' {
			if firstPadding < 0 {
				firstPadding = index
			}
			continue
		}
		if firstPadding >= 0 || !isBase64Byte(character) {
			return false
		}
	}
	return firstPadding < 0 || firstPadding >= len(line)-2
}

func recognizeAuthorization(input string) []candidate {
	return scanLines(input, func(line string, offset int) []candidate {
		parts := authorizationRE.FindStringSubmatchIndex(line)
		if parts == nil {
			lower := strings.ToLower(line)
			if len(line) > 8192 && (strings.HasPrefix(lower, "authorization") || strings.HasPrefix(lower, "proxy-authorization")) {
				return []candidate{{start: offset, end: offset + len(line), accepted: false}}
			}
			return nil
		}
		if len(line) > 8192 {
			return []candidate{{start: offset, end: offset + len(line), accepted: false}}
		}
		start, end := parts[6], parts[7]
		valid := start >= 0 && end > start && visibleWithoutControls(line[start:end])
		return []candidate{{start: offset + start, end: offset + end, accepted: valid}}
	})
}

func recognizeCookies(input string) []candidate {
	return scanLines(input, func(line string, offset int) []candidate {
		lower := strings.ToLower(line)
		setCookie := strings.HasPrefix(lower, "set-cookie:")
		if !setCookie && !strings.HasPrefix(lower, "cookie:") {
			return nil
		}
		if len(line) > 8192 || !visibleHeaderLine(line) {
			return []candidate{{start: offset, end: offset + len(line), accepted: false}}
		}
		colon := strings.IndexByte(line, ':')
		position := colon + 1
		result := []candidate{}
		member := 0
		for position < len(line) {
			position = skipOWS(line, position)
			nameStart := position
			for position < len(line) && isHTTPTokenByte(line[position]) {
				position++
			}
			if position == nameStart {
				break
			}
			name := strings.ToLower(line[nameStart:position])
			position = skipOWS(line, position)
			if position >= len(line) || line[position] != '=' {
				break
			}
			position++
			position = skipOWS(line, position)
			valueStart, valueEnd, next, valid := parseCookieValue(line, position)
			if sensitiveCookieName(name) && (!setCookie || member == 0) {
				result = append(result, candidate{start: offset + valueStart, end: offset + valueEnd, accepted: valid && valueEnd > valueStart})
			}
			member++
			position = skipOWS(line, next)
			if position == len(line) {
				break
			}
			if line[position] != ';' {
				break
			}
			position++
		}
		return result
	})
}

func parseCookieValue(line string, position int) (start, end, next int, valid bool) {
	if position >= len(line) {
		return position, position, position, false
	}
	if line[position] != '"' {
		start = position
		for position < len(line) && line[position] != ';' {
			character := line[position]
			if character > 0x7e || strings.ContainsRune(",\"\\", rune(character)) || (character < 0x20 && character != '\t') {
				return start, position, position, false
			}
			position++
		}
		next = position
		end = position
		for end > start && (line[end-1] == ' ' || line[end-1] == '\t') {
			end--
		}
		for index := start; index < end; index++ {
			if line[index] < 0x21 {
				return start, end, next, false
			}
		}
		return start, end, next, end > start
	}
	start = position + 1
	position++
	for position < len(line) {
		character := line[position]
		if character == '"' {
			return start, position, position + 1, position > start
		}
		if character == '\\' {
			position++
			if position >= len(line) || line[position] < 0x21 || line[position] > 0x7e {
				return start, position, position, false
			}
		} else if character < 0x21 || character > 0x7e {
			return start, position, position, false
		}
		position++
	}
	return start, position, position, false
}

func recognizeConnectionStrings(input string) ([]candidate, error) {
	result := []candidate{}
	uriRanges := uriRE.FindAllStringIndex(input, -1)
	for _, uri := range uriRanges {
		uriValue := input[uri[0]:uri[1]]
		parsed, ok := parseHierarchicalURI(uriValue)
		if !ok && containsEligibleRawQuery(uriValue) {
			return nil, detectorError(FailureValidator)
		}
		if !ok || !supportedConnectionScheme(parsed.scheme) {
			continue
		}
		if parsed.passwordStart >= 0 && parsed.passwordEnd > parsed.passwordStart {
			result = append(result, candidate{start: uri[0] + parsed.passwordStart, end: uri[0] + parsed.passwordEnd, accepted: true})
		}
		result = append(result, queryCandidates(input[uri[0]:uri[1]], uri[0], parsed, true)...)
	}
	for _, item := range scanKeyValues(input, dsnKeyRE, true) {
		if !overlapsAnyRange(item.start, item.end, uriRanges) {
			result = append(result, item)
		}
	}
	return result, nil
}

func overlapsAnyRange(start, end int, ranges [][]int) bool {
	// regexp.FindAllStringIndex returns non-overlapping ranges in source
	// order. Binary search for the first range whose end is after start so a
	// field with many URI and DSN candidates remains O(n log n), never O(n²).
	low, high := 0, len(ranges)
	for low < high {
		middle := low + (high-low)/2
		if len(ranges[middle]) != 2 || ranges[middle][1] <= start {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low < len(ranges) {
		interval := ranges[low]
		return len(interval) == 2 && interval[0] < end
	}
	return false
}

func recognizeAssignments(input string) []candidate {
	return scanKeyValues(input, assignmentKeyRE, false)
}

func scanKeyValues(input string, keyPattern *regexp.Regexp, dsn bool) []candidate {
	indices := keyPattern.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		lexicalStart := index[0]
		if !dsn && lexicalStart > 0 && input[lexicalStart-1] == '"' {
			lexicalStart--
		}
		if index[0] > 0 && (isASCIIAlphaNum(input[index[0]-1]) || input[index[0]-1] == '_') {
			continue
		}
		if index[1] < len(input) && (isASCIIAlphaNum(input[index[1]]) || input[index[1]] == '_') {
			continue
		}
		position := index[1]
		if !dsn && index[0] > 0 && input[index[0]-1] == '"' && position < len(input) && input[position] == '"' {
			position++
		}
		position = skipOWS(input, position)
		if position >= len(input) || (input[position] != '=' && (dsn || input[position] != ':')) {
			continue
		}
		position = skipOWS(input, position+1)
		if !dsn && strings.HasPrefix(input[position:], "${") {
			if close := strings.IndexByte(input[position+2:], '}'); close >= 0 {
				close += position + 2
				result = append(result, candidate{start: position, end: close + 1, accepted: false})
				continue
			}
		}
		start, end, valid := parseAssignmentValue(input, position, dsn)
		if end <= start {
			end = minInt(len(input), start+1)
		}
		decoded := input[start:end]
		if valid && position < len(input) && input[position] == '"' {
			var value string
			if err := json.Unmarshal([]byte(input[position:end+1]), &value); err != nil {
				valid = false
			} else {
				decoded = value
			}
		}
		valid = valid && end-lexicalStart <= 8192 && !excludedAssignmentValue(decoded)
		result = append(result, candidate{start: start, end: end, accepted: valid})
	}
	return result
}

func parseAssignmentValue(input string, position int, dsn bool) (start, end int, valid bool) {
	if position >= len(input) {
		return position, position, false
	}
	if input[position] == '"' {
		start = position + 1
		for current := start; current < len(input); current++ {
			if input[current] == '\\' {
				current++
				continue
			}
			if input[current] == '"' {
				return start, current, true
			}
		}
		return start, len(input), false
	}
	start = position
	for position < len(input) {
		character := input[position]
		if dsn {
			if character == ';' || character == ' ' || character == '\t' || character == '\r' || character == '\n' {
				break
			}
		} else if character == ' ' || character == '\t' || character == '\r' || character == '\n' || strings.ContainsRune(",;}]", rune(character)) {
			break
		}
		position++
	}
	return start, position, position > start
}

func excludedAssignmentValue(value string) bool {
	if value == "" {
		return true
	}
	lower := strings.ToLower(value)
	switch lower {
	case "true", "false", "null", "example", "sample", "dummy", "changeme", "redacted":
		return true
	}
	if strings.Trim(value, "*") == "" || (strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")) {
		return true
	}
	return false
}

func recognizeHighEntropy(input string, fieldClass observability.FieldClass, prior []acceptedMatch) []candidate {
	indices := entropyRE.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		value := input[index[0]:index[1]]
		accepted := entropyBoundary(input, index[0], index[1]) && validHighEntropy(value, fieldClass)
		if overlapsCredentialClaim(index[0], index[1], prior) {
			accepted = false
		}
		result = append(result, candidate{start: index[0], end: index[1], accepted: accepted})
	}
	return result
}

func validHighEntropy(value string, fieldClass observability.FieldClass) bool {
	if len(value) < 20 || len(value) > 256 || repeatedUnit(value, 8) {
		return false
	}
	if !allHex(value) && !validBase64Alphabet(value) {
		return false
	}
	lower := strings.ToLower(value)
	for _, placeholder := range []string{"example", "sample", "dummy", "changeme", "redacted"} {
		if strings.ReplaceAll(lower, placeholder, "") == "" {
			return false
		}
	}
	if looksUUID(value) || (len(value) == 32 && allHex(value)) || (len(value) == 64 && allHex(value) && fieldClass == observability.FieldClassIdentifier) {
		return false
	}
	classes := 0
	for _, predicate := range []func(byte) bool{isASCIIUpper, isASCIILower, isASCIIDigit, func(value byte) bool { return strings.ContainsRune("+/_-=", rune(value)) }} {
		if byteAny(value, predicate) {
			classes++
		}
	}
	if !allHex(value) && classes < 3 {
		return false
	}
	counts := [256]int{}
	for i := range len(value) {
		counts[value[i]]++
	}
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / float64(len(value))
		entropy -= probability * math.Log2(probability)
	}
	return entropy >= 3.5
}

func validBase64Alphabet(value string) bool {
	trimmed := strings.TrimRight(value, "=")
	if len(value)-len(trimmed) > 2 || strings.ContainsRune(trimmed, '=') || trimmed == "" {
		return false
	}
	standard, urlSafe := true, true
	for _, character := range []byte(trimmed) {
		if !isASCIIAlphaNum(character) && character != '+' && character != '/' {
			standard = false
		}
		if !isASCIIAlphaNum(character) && character != '-' && character != '_' {
			urlSafe = false
		}
	}
	return standard || urlSafe
}

func recognizeURLQueries(input string) ([]candidate, error) {
	result := []candidate{}
	for _, uri := range uriRE.FindAllStringIndex(input, -1) {
		uriValue := input[uri[0]:uri[1]]
		parsed, ok := parseHierarchicalURI(uriValue)
		if !ok && containsEligibleRawQuery(uriValue) {
			return nil, detectorError(FailureValidator)
		}
		if !ok {
			continue
		}
		result = append(result, queryCandidates(uriValue, uri[0], parsed, false)...)
	}
	return result, nil
}

func containsEligibleRawQuery(value string) bool {
	question := strings.IndexByte(value, '?')
	if question < 0 {
		return false
	}
	query := value[question+1:]
	if hash := strings.IndexByte(query, '#'); hash >= 0 {
		query = query[:hash]
	}
	for _, item := range strings.FieldsFunc(query, func(r rune) bool { return r == '&' || r == ';' }) {
		if equals := strings.IndexByte(item, '='); equals >= 0 && eligibleQueryKey(item[:equals]) {
			return true
		}
	}
	return false
}

func queryCandidates(uri string, offset int, parsed parsedURI, connectionOnly bool) []candidate {
	if parsed.queryStart < 0 {
		return nil
	}
	end := parsed.queryEnd
	position := parsed.queryStart
	result := []candidate{}
	for position <= end {
		itemEnd := position
		for itemEnd < end && uri[itemEnd] != '&' && uri[itemEnd] != ';' {
			itemEnd++
		}
		equals := strings.IndexByte(uri[position:itemEnd], '=')
		if equals >= 0 {
			equals += position
			key := uri[position:equals]
			valueStart := equals + 1
			valueEnd := itemEnd
			eligible := eligibleQueryKey(key)
			decoded, valid := percentDecodeUTF8(uri[valueStart:valueEnd])
			accepted := eligible && valid && decoded != ""
			if connectionOnly {
				accepted = accepted && eligibleConnectionQueryKey(key)
			}
			if eligible {
				result = append(result, candidate{start: offset + valueStart, end: offset + valueEnd, accepted: accepted})
			}
		}
		if itemEnd == end {
			break
		}
		position = itemEnd + 1
	}
	return result
}

func recognizeCloudIdentifiers(input string) []candidate {
	result := []candidate{}
	for _, parts := range cloudLabelRE.FindAllStringSubmatchIndex(input, -1) {
		label := strings.ToLower(input[parts[2]:parts[3]])
		value := input[parts[4]:parts[5]]
		accepted := asciiIdentifierBoundary(input, parts[2], parts[3]) && validCloudLabelValue(label, value)
		result = append(result, candidate{start: parts[4], end: parts[5], accepted: accepted})
	}
	for _, parts := range arnRE.FindAllStringSubmatchIndex(input, -1) {
		result = append(result, candidate{start: parts[2], end: parts[3], accepted: parts[0] == 0 || !isASCIIIdentifierByte(input[parts[0]-1])})
	}
	for _, parts := range azurePathRE.FindAllStringSubmatchIndex(input, -1) {
		result = append(result, candidate{start: parts[4], end: parts[5], accepted: validUUID(input[parts[4]:parts[5]])})
	}
	for _, pattern := range []*regexp.Regexp{gcpPathRE, gcpServiceRE} {
		for _, parts := range pattern.FindAllStringSubmatchIndex(input, -1) {
			result = append(result, candidate{start: parts[2], end: parts[3], accepted: validGCPProjectID(input[parts[2]:parts[3]])})
		}
	}
	return result
}

func asciiIdentifierBoundary(input string, start, end int) bool {
	return (start == 0 || !isASCIIIdentifierByte(input[start-1])) &&
		(end == len(input) || !isASCIIIdentifierByte(input[end]))
}

func isASCIIIdentifierByte(value byte) bool {
	return isASCIIAlphaNum(value) || value == '_'
}

func recognizeEmails(input string) []candidate {
	indices := emailRE.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		accepted := emailBoundary(input, index[0], index[1]) && validEmail(input[index[0]:index[1]])
		result = append(result, candidate{start: index[0], end: index[1], accepted: accepted})
	}
	return result
}

func recognizeTelephones(input string) []candidate {
	indices := telephoneRE.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		value := input[index[0]:index[1]]
		accepted := digitBoundary(input, index[0], index[1]) &&
			!hasInternationalPrefix(input, index[0]) &&
			!hasNumericTelephonePrefix(input, index[0]) &&
			validTelephone(value) &&
			!hasTelephoneExtension(input[index[1]:])
		result = append(result, candidate{start: index[0], end: index[1], accepted: accepted})
	}
	return result
}

func hasNumericTelephonePrefix(input string, start int) bool {
	return start >= 2 && strings.ContainsRune(" .-", rune(input[start-1])) && isASCIIDigit(input[start-2])
}

func hasInternationalPrefix(input string, start int) bool {
	if start == 0 || !strings.ContainsRune(" .-", rune(input[start-1])) {
		return false
	}
	position := start - 2
	digits := 0
	for position >= 0 && digits < 3 && isASCIIDigit(input[position]) {
		digits++
		position--
	}
	return digits > 0 && position >= 0 && input[position] == '+'
}

func hasTelephoneExtension(remainder string) bool {
	remainder = strings.TrimLeft(remainder, " \t")
	lower := strings.ToLower(remainder)
	for _, prefix := range []string{"x", "ext", "extension"} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		position := len(prefix)
		if position < len(lower) && (lower[position] == '.' || lower[position] == ':') {
			position++
		}
		position = skipOWS(lower, position)
		return position < len(lower) && isASCIIDigit(lower[position])
	}
	return false
}

func recognizeNationalIdentifiers(input string) []candidate {
	indices := nationalIDRE.FindAllStringIndex(input, -1)
	result := make([]candidate, 0, len(indices))
	for _, index := range indices {
		accepted := digitBoundary(input, index[0], index[1]) && validNationalID(input[index[0]:index[1]])
		result = append(result, candidate{start: index[0], end: index[1], accepted: accepted})
	}
	return result
}

func recognizePaymentCards(input string) []candidate {
	// Go's RE2 has no lookahead, so scan maximal digit/separator runs and let
	// the semantic validator enforce digit count and consistent separators.
	result := []candidate{}
	for start := 0; start < len(input); {
		if !isASCIIDigit(input[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(input) && (isASCIIDigit(input[end]) || input[end] == ' ' || input[end] == '-') {
			end++
		}
		value := strings.TrimRight(input[start:end], " -")
		candidateEnd := start + len(value)
		if digitsIn(value) >= 13 {
			result = append(result, candidate{start: start, end: candidateEnd, accepted: digitBoundary(input, start, candidateEnd) && validPaymentCard(value)})
		}
		start = maxInt(end, start+1)
	}
	return result
}

func recognizeIPAddresses(input string) []candidate {
	result := []candidate{}
	for start := 0; start < len(input); {
		if !isIPLexicalByte(input[start]) {
			start++
			continue
		}
		end := start + 1
		for end < len(input) && isIPLexicalByte(input[end]) {
			end++
		}
		value := input[start:end]
		if strings.ContainsAny(value, ".:") {
			_, err := netip.ParseAddr(value)
			accepted := err == nil && ipBoundary(input, start, end)
			result = append(result, candidate{start: start, end: end, accepted: accepted})
		}
		start = end
	}
	return result
}

type parsedURI struct {
	scheme                     string
	passwordStart, passwordEnd int
	queryStart, queryEnd       int
}

func parseHierarchicalURI(value string) (parsedURI, bool) {
	result := parsedURI{passwordStart: -1, passwordEnd: -1, queryStart: -1, queryEnd: -1}
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || colon+2 >= len(value) || value[colon+1:colon+3] != "//" || !allASCII(value) {
		return result, false
	}
	result.scheme = strings.ToLower(value[:colon])
	authorityStart := colon + 3
	authorityEnd := len(value)
	for _, delimiter := range []byte{'/', '?', '#'} {
		if relative := strings.IndexByte(value[authorityStart:], delimiter); relative >= 0 && authorityStart+relative < authorityEnd {
			authorityEnd = authorityStart + relative
		}
	}
	if authorityEnd == authorityStart {
		return result, false
	}
	authority := value[authorityStart:authorityEnd]
	hostpart := authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo := authority[:at]
		hostpart = authority[at+1:]
		if userColon := strings.IndexByte(userinfo, ':'); userColon >= 0 {
			result.passwordStart = authorityStart + userColon + 1
			result.passwordEnd = authorityStart + at
		}
	}
	if !validURIHostPart(hostpart) {
		return parsedURI{}, false
	}
	fragment := len(value)
	if hash := strings.IndexByte(value[authorityEnd:], '#'); hash >= 0 {
		fragment = authorityEnd + hash
	}
	if question := strings.IndexByte(value[authorityEnd:fragment], '?'); question >= 0 {
		result.queryStart = authorityEnd + question + 1
		result.queryEnd = fragment
	}
	if !validPercentEscapes(value) {
		return parsedURI{}, false
	}
	return result, true
}

func validURIHostPart(hostpart string) bool {
	if hostpart == "" {
		return false
	}
	host := hostpart
	if strings.HasPrefix(host, "[") {
		close := strings.IndexByte(host, ']')
		if close < 0 {
			return false
		}
		if _, err := netip.ParseAddr(host[1:close]); err != nil {
			return false
		}
		rest := host[close+1:]
		return rest == "" || (strings.HasPrefix(rest, ":") && validPort(rest[1:]))
	}
	if colon := strings.LastIndexByte(host, ':'); colon >= 0 {
		if !validPort(host[colon+1:]) {
			return false
		}
		host = host[:colon]
	}
	if host == "" {
		return false
	}
	for _, character := range []byte(host) {
		if !isASCIIAlphaNum(character) && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validPort(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if !isASCIIDigit(character) {
			return false
		}
	}
	return true
}

func supportedConnectionScheme(scheme string) bool {
	switch scheme {
	case "postgres", "postgresql", "mysql", "mariadb", "mongodb", "mongodb+srv", "redis", "rediss", "amqp", "amqps", "kafka", "sqlserver", "snowflake":
		return true
	default:
		return false
	}
}

func eligibleQueryKey(key string) bool {
	switch strings.ToLower(key) {
	case "token", "access_token", "refresh_token", "api_key", "apikey", "key", "secret", "client_secret", "password", "passwd", "pwd", "signature", "sig", "x-amz-signature", "x-goog-signature", "code", "credential":
		return true
	default:
		return false
	}
}

func eligibleConnectionQueryKey(key string) bool { return eligibleQueryKey(key) }

func percentDecodeUTF8(value string) (string, bool) {
	decoded := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			decoded = append(decoded, value[i])
			continue
		}
		if i+2 >= len(value) || !isASCIIHex(value[i+1]) || !isASCIIHex(value[i+2]) {
			return "", false
		}
		decoded = append(decoded, detectorFromHex(value[i+1])<<4|detectorFromHex(value[i+2]))
		i += 2
	}
	return string(decoded), utf8.Valid(decoded)
}

func validPercentEscapes(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '%' {
			continue
		}
		if i+2 >= len(value) || !isASCIIHex(value[i+1]) || !isASCIIHex(value[i+2]) {
			return false
		}
		i += 2
	}
	return true
}

func validCloudLabelValue(label, value string) bool {
	switch label {
	case "aws_account_id":
		return len(value) == 12 && allDigits(value)
	case "azure_tenant_id", "azure_subscription_id":
		return validUUID(value)
	case "gcp_project_number":
		return len(value) >= 6 && len(value) <= 19 && allDigits(value)
	case "gcp_project_id":
		return validGCPProjectID(value)
	default:
		return false
	}
}

func validGCPProjectID(value string) bool {
	if len(value) < 6 || len(value) > 30 || !isASCIILower(value[0]) || !isASCIIAlphaNum(value[len(value)-1]) {
		return false
	}
	for _, character := range []byte(value) {
		if !isASCIILower(character) && !isASCIIDigit(character) && character != '-' {
			return false
		}
	}
	return true
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range []byte(value) {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
		} else if !isASCIIHex(character) {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	if len(value) > 254 {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at > 64 {
		return false
	}
	local, host := value[:at], value[at+1:]
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range []byte(label) {
			if !isASCIIAlphaNum(character) && character != '-' {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	if len(last) < 2 || len(last) > 63 {
		return false
	}
	for _, character := range []byte(last) {
		if !isASCIIUpper(character) && !isASCIILower(character) {
			return false
		}
	}
	return true
}

func validTelephone(value string) bool {
	base := value
	prefixSeparator := byte(0)
	if strings.HasPrefix(base, "+1") {
		if len(base) < 4 || !strings.ContainsRune(" .-", rune(base[2])) {
			return false
		}
		prefixSeparator = base[2]
		base = base[3:]
	}
	separator := byte(0)
	for _, character := range []byte(base) {
		if character == ' ' || character == '.' || character == '-' {
			if separator == 0 {
				separator = character
			} else if separator != character {
				return false
			}
		}
	}
	digits := onlyDigits(base)
	return len(digits) == 10 && digits[0] >= '2' && digits[0] <= '9' && digits[3] >= '2' && digits[3] <= '9' && separator != 0 && (prefixSeparator == 0 || prefixSeparator == separator)
}

func validNationalID(value string) bool {
	denied := map[string]struct{}{
		"078-05-1120": {}, "111-11-1111": {}, "123-45-6789": {},
		"219-09-9999": {}, "987-65-4321": {},
	}
	if _, found := denied[value]; found {
		return false
	}
	area, _ := strconv.Atoi(value[:3])
	group, _ := strconv.Atoi(value[4:6])
	serial, _ := strconv.Atoi(value[7:])
	digits := onlyDigits(value)
	return area != 0 && area != 666 && area < 900 && group != 0 && serial != 0 && !allSame(digits)
}

func validPaymentCard(value string) bool {
	digits := onlyDigits(value)
	if len(digits) < 13 || len(digits) > 19 || allSame(digits) {
		return false
	}
	separator := byte(0)
	for _, character := range []byte(value) {
		if character != ' ' && character != '-' {
			continue
		}
		if separator == 0 {
			separator = character
		} else if separator != character {
			return false
		}
	}
	sum := 0
	parity := len(digits) % 2
	for index, character := range []byte(digits) {
		digit := int(character - '0')
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

func scanLines(input string, scan func(string, int) []candidate) []candidate {
	result := []candidate{}
	position := 0
	for position <= len(input) {
		end := strings.IndexByte(input[position:], '\n')
		if end < 0 {
			end = len(input)
		} else {
			end += position
		}
		lineEnd := end
		if lineEnd > position && input[lineEnd-1] == '\r' {
			lineEnd--
		}
		result = append(result, scan(input[position:lineEnd], position)...)
		if end == len(input) {
			break
		}
		position = end + 1
	}
	return result
}

func nextLine(input string, start int) (int, string) {
	if start >= len(input) {
		return -1, ""
	}
	index := strings.IndexByte(input[start:], '\n')
	if index < 0 {
		return -1, ""
	}
	end := start + index
	if end > start && input[end-1] == '\r' {
		return end - 1, "\r\n"
	}
	return end, "\n"
}

func nextLineAllowEOF(input string, start int) (int, string) {
	end, ending := nextLine(input, start)
	if end >= 0 {
		return end, ending
	}
	return len(input), ""
}

func entropyBoundary(input string, start, end int) bool {
	return (start == 0 || !isEntropyByte(input[start-1])) && (end == len(input) || !isEntropyByte(input[end]))
}

func isEntropyByte(value byte) bool {
	return isASCIIAlphaNum(value) || strings.ContainsRune("+/_-=", rune(value))
}

func emailBoundary(input string, start, end int) bool {
	return (start == 0 || input[start-1] < utf8.RuneSelf && !isEmailByte(input[start-1])) &&
		(end == len(input) || input[end] < utf8.RuneSelf && !isEmailByte(input[end]))
}

func isEmailByte(value byte) bool {
	return isASCIIAlphaNum(value) || strings.ContainsRune("!#$%&'*+/=?^_`{|}~@.-", rune(value))
}

func digitBoundary(input string, start, end int) bool {
	return (start == 0 || !isASCIIDigit(input[start-1])) && (end == len(input) || !isASCIIDigit(input[end]))
}

func ipBoundary(input string, start, end int) bool {
	return (start == 0 || input[start-1] != '[' && !isIPTokenByte(input[start-1])) &&
		(end == len(input) || input[end] != ']' && !isIPTokenByte(input[end]))
}

func isIPTokenByte(value byte) bool {
	return isASCIIAlphaNum(value) || strings.ContainsRune("_:./%", rune(value))
}
func isIPLexicalByte(value byte) bool {
	return isASCIIHex(value) || strings.ContainsRune(".:/%", rune(value))
}

func visibleWithoutControls(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func visibleHeaderLine(value string) bool {
	for _, character := range []byte(value) {
		if (character < 0x20 && character != '\t') || character == 0x7f {
			return false
		}
	}
	return true
}

func sensitiveCookieName(name string) bool {
	switch name {
	case "session", "sessionid", "sid", "auth", "authorization", "token", "access_token", "refresh_token", "jwt", "csrf":
		return true
	default:
		return false
	}
}

func isHTTPTokenByte(value byte) bool {
	return isASCIIAlphaNum(value) || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(value))
}

func skipOWS(value string, position int) int {
	for position < len(value) && (value[position] == ' ' || value[position] == '\t') {
		position++
	}
	return position
}

func repeatedUnit(value string, maximum int) bool {
	for size := 1; size <= maximum && size < len(value); size++ {
		if len(value)%size == 0 && strings.Repeat(value[:size], len(value)/size) == value {
			return true
		}
	}
	return false
}

func looksUUID(value string) bool { return validUUID(value) }
func allHex(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if !isASCIIHex(character) {
			return false
		}
	}
	return true
}
func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if !isASCIIDigit(character) {
			return false
		}
	}
	return true
}
func allASCII(value string) bool {
	for _, character := range []byte(value) {
		if character >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
func allSame(value string) bool {
	if value == "" {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] != value[0] {
			return false
		}
	}
	return true
}
func onlyDigits(value string) string {
	var builder strings.Builder
	for _, character := range []byte(value) {
		if isASCIIDigit(character) {
			builder.WriteByte(character)
		}
	}
	return builder.String()
}
func digitsIn(value string) int { return len(onlyDigits(value)) }
func byteAny(value string, predicate func(byte) bool) bool {
	for _, character := range []byte(value) {
		if predicate(character) {
			return true
		}
	}
	return false
}
func isASCIIAlphaNum(value byte) bool {
	return isASCIIUpper(value) || isASCIILower(value) || isASCIIDigit(value)
}
func isASCIIUpper(value byte) bool { return value >= 'A' && value <= 'Z' }
func isASCIILower(value byte) bool { return value >= 'a' && value <= 'z' }
func isASCIIDigit(value byte) bool { return value >= '0' && value <= '9' }
func isASCIIHex(value byte) bool {
	return isASCIIDigit(value) || value >= 'A' && value <= 'F' || value >= 'a' && value <= 'f'
}
func isBase64Byte(value byte) bool { return isASCIIAlphaNum(value) || value == '+' || value == '/' }
func detectorFromHex(value byte) byte {
	if value >= '0' && value <= '9' {
		return value - '0'
	}
	if value >= 'A' && value <= 'F' {
		return value - 'A' + 10
	}
	return value - 'a' + 10
}
func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}
