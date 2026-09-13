// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var (
	httpFieldNamePattern           = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	httpSQLPrefixPattern           = regexp.MustCompile(`(?i)^[a-z0-9_.-]*'?$`)
	httpSQLIdentifierPrefixPattern = regexp.MustCompile(`(?i)^[a-z0-9_.-]*$`)
	httpSQLExpressionPattern       = regexp.MustCompile(
		`(?i)^(?:[a-z_][a-z0-9_]*|[0-9]{1,10}|null|'[a-z0-9_.@ -]{1,64}'|[a-z_][a-z0-9_]*\(\))$`,
	)
	httpSQLIdentifierPattern = regexp.MustCompile(`(?i)^[a-z_][a-z0-9_]*$`)
	httpSQLWherePattern      = regexp.MustCompile(
		`(?i)^([a-z_][a-z0-9_]*)\s*=\s*'([a-z0-9_.@ -]{1,64})'$`,
	)
	httpSQLStringTautologyTailPattern = regexp.MustCompile(
		`^([^'[:space:]]{1,32})'[[:space:]]*=[[:space:]]*'([^'[:space:]]{1,32})'?[[:space:]]*(?:--[[:space:]]*-?)?[[:space:]]*$`,
	)
	httpSQLNumericTautologyPattern = regexp.MustCompile(
		`(?i)^([a-z0-9_.-]*)'\s+or\s+([0-9]{1,10})\s*=\s*([0-9]{1,10})\s*$`,
	)
	httpSQLXPCmdShellPattern = regexp.MustCompile(
		`(?i)^(?:exec|execute)\s+xp_cmdshell\s*\(\s*'([^'\r\n]{1,512})'\s*\)\s*--(?:\s+-)?\s*$`,
	)
	httpSQLIntoOutfilePattern = regexp.MustCompile(
		`(?i)^[0-9]{1,10}\s+union\s+select\s+0x([0-9a-f]+)\s+into\s+outfile\s+'([^'\r\n]{1,512})'\s*$`,
	)
)

type exactHTTPRequest struct {
	values []string
}

// ExactHTTPSQLInjections returns validated value-free technique facts. URL,
// body, header, parameter, SQL, and destination values never cross this API.
func ExactHTTPSQLInjections(facts Facts) []HTTPSQLInjectionFact {
	if facts.Parse.Status != StatusComplete || len(facts.HTTPSQLInjections) == 0 {
		return nil
	}
	result := make([]HTTPSQLInjectionFact, 0, len(facts.HTTPSQLInjections))
	seen := make(map[HTTPSQLInjectionTechnique]struct{}, len(facts.HTTPSQLInjections))
	for _, fact := range facts.HTTPSQLInjections {
		if !validHTTPSQLInjectionTechnique(fact.Technique) {
			return nil
		}
		if _, exists := seen[fact.Technique]; exists {
			continue
		}
		seen[fact.Technique] = struct{}{}
		result = append(result, fact)
	}
	return result
}

func projectHTTPSQLInjections(input Input) []HTTPSQLInjectionFact {
	if input.Tool != "http_request" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	request, ok := exactHTTPRequestInput(input.Args)
	if !ok {
		return nil
	}
	result := make([]HTTPSQLInjectionFact, 0, 2)
	seen := make(map[HTTPSQLInjectionTechnique]struct{}, 4)
	for _, value := range request.values {
		for _, technique := range exactHTTPSQLInjectionTechniques(value) {
			if _, exists := seen[technique]; exists {
				continue
			}
			seen[technique] = struct{}{}
			result = append(result, HTTPSQLInjectionFact{Technique: technique})
		}
	}
	return result
}

func exactHTTPRequestInput(raw json.RawMessage) (exactHTTPRequest, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return exactHTTPRequest{}, false
	}
	if _, hasURL := object["url"]; hasURL {
		return exactHTTPURLRequestInput(object)
	}
	return exactHTTPPathRequestInput(object)
}

func selectsHTTPPathRequestSchema(raw json.RawMessage) bool {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return false
	}
	_, selected := object["query"]
	return selected
}

func exactHTTPURLRequestInput(object map[string]any) (exactHTTPRequest, bool) {
	if len(object) < 2 || len(object) > 4 {
		return exactHTTPRequest{}, false
	}
	for key := range object {
		if key != "method" && key != "url" && key != "headers" && key != "body" {
			return exactHTTPRequest{}, false
		}
	}
	method, methodOK := object["method"].(string)
	rawURL, urlOK := object["url"].(string)
	if !methodOK || !urlOK || (method != "GET" && method != "POST") {
		return exactHTTPRequest{}, false
	}
	values, ok := exactHTTPURLValues(rawURL)
	if !ok {
		return exactHTTPRequest{}, false
	}
	contentType, ok := exactHTTPHeaders(object["headers"])
	if !ok {
		return exactHTTPRequest{}, false
	}
	bodyValue, hasBody := object["body"]
	if method == "GET" {
		if hasBody || contentType != "" {
			return exactHTTPRequest{}, false
		}
		return exactHTTPRequest{values: values}, true
	}
	body, bodyOK := bodyValue.(string)
	if !hasBody || !bodyOK || body == "" || len(body) > maxCommandBytes || !utf8.ValidString(body) {
		return exactHTTPRequest{}, false
	}
	var bodyValues []string
	switch contentType {
	case "application/json":
		bodyValues, ok = exactHTTPJSONBodyValues(body)
	case "", "application/x-www-form-urlencoded":
		bodyValues, ok = exactHTTPFormValues(body)
	default:
		return exactHTTPRequest{}, false
	}
	if !ok {
		return exactHTTPRequest{}, false
	}
	values = append(values, bodyValues...)
	return exactHTTPRequest{values: values}, true
}

// exactHTTPPathRequestInput accepts the normalized fuzz-agent request shape.
// It is intentionally a separate closed schema from the URL/header/body shape
// above: mixing fields, adding transport controls, or nesting values fails
// closed. Only scalar query/body strings are returned to reviewed recognizers.
func exactHTTPPathRequestInput(object map[string]any) (exactHTTPRequest, bool) {
	if len(object) < 3 || len(object) > 4 {
		return exactHTTPRequest{}, false
	}
	for key := range object {
		if key != "method" && key != "path" && key != "query" && key != "body" {
			return exactHTTPRequest{}, false
		}
	}
	method, methodOK := object["method"].(string)
	rawPath, pathOK := object["path"].(string)
	if !methodOK || !pathOK || !exactStructuredHTTPMethod(method) ||
		!exactStructuredHTTPPath(rawPath) {
		return exactHTTPRequest{}, false
	}
	queryValues, ok := exactHTTPScalarObjectValues(object["query"], true)
	if !ok {
		return exactHTTPRequest{}, false
	}
	bodyValue, hasBody := object["body"]
	bodyValues := []string(nil)
	if hasBody {
		bodyValues, ok = exactHTTPScalarObjectValues(bodyValue, true)
		if !ok {
			return exactHTTPRequest{}, false
		}
	}
	if (method == "GET" || method == "DELETE") && len(bodyValues) != 0 {
		return exactHTTPRequest{}, false
	}
	return exactHTTPRequest{values: append(queryValues, bodyValues...)}, true
}

func exactStructuredHTTPMethod(method string) bool {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func exactStructuredHTTPPath(rawPath string) bool {
	if rawPath == "" || len(rawPath) > maxScalarBytes || !utf8.ValidString(rawPath) ||
		strings.TrimSpace(rawPath) != rawPath || !strings.HasPrefix(rawPath, "/") ||
		strings.HasPrefix(rawPath, "//") || strings.ContainsAny(rawPath, "\\?#%") ||
		unresolvedHTTPValue(rawPath) {
		return false
	}
	for _, segment := range strings.Split(rawPath, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func exactHTTPScalarObjectValues(value any, allowEmpty bool) ([]string, bool) {
	object, ok := value.(map[string]any)
	if !ok || len(object) > 64 || (!allowEmpty && len(object) == 0) {
		return nil, false
	}
	values := make([]string, 0, len(object))
	for key, rawValue := range object {
		if !httpFieldNamePattern.MatchString(key) {
			return nil, false
		}
		switch scalar := rawValue.(type) {
		case string:
			if len(scalar) > maxScalarBytes || !utf8.ValidString(scalar) ||
				strings.Contains(scalar, "%") || unresolvedHTTPValue(scalar) {
				return nil, false
			}
			values = append(values, scalar)
		case json.Number, bool, nil:
			// Exact JSON scalars are accepted as part of the closed request but
			// cannot contain shell syntax and therefore need no projection.
		default:
			return nil, false
		}
	}
	return values, true
}

func exactHTTPHeaders(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	headers, ok := value.(map[string]any)
	if !ok || len(headers) == 0 || len(headers) > 3 {
		return "", false
	}
	contentType := ""
	for key, rawValue := range headers {
		text, textOK := rawValue.(string)
		if !textOK || text == "" || len(text) > maxScalarBytes || unresolvedHTTPValue(text) {
			return "", false
		}
		switch key {
		case "Content-Type":
			if text != "application/json" && text != "application/x-www-form-urlencoded" {
				return "", false
			}
			contentType = text
		case "Authorization", "User-Agent":
		default:
			return "", false
		}
	}
	return contentType, true
}

func exactHTTPURLValues(raw string) ([]string, bool) {
	if raw == "" || len(raw) > maxCommandBytes || !utf8.ValidString(raw) ||
		strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\\\r\n\t") ||
		strings.Contains(raw, "%") || unresolvedHTTPValue(raw) {
		return nil, false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Fragment != "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Hostname() == "" || parsed.Path == "" || !strings.HasPrefix(parsed.Path, "/") {
		return nil, false
	}
	if port := parsed.Port(); port != "" {
		value, parseErr := strconv.ParseUint(port, 10, 16)
		if parseErr != nil || value == 0 {
			return nil, false
		}
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == ".." {
			return nil, false
		}
	}
	if parsed.RawQuery == "" {
		return nil, true
	}
	return exactHTTPFormValues(parsed.RawQuery)
}

func exactHTTPJSONBodyValues(body string) ([]string, bool) {
	object, problem := exactJSONObject(json.RawMessage(body))
	if problem.status != "" || len(object) == 0 || len(object) > 64 {
		return nil, false
	}
	values := make([]string, 0, len(object))
	for key, rawValue := range object {
		value, ok := rawValue.(string)
		if !httpFieldNamePattern.MatchString(key) || !ok || value == "" ||
			len(value) > maxCommandBytes || unresolvedHTTPValue(value) {
			return nil, false
		}
		values = append(values, value)
	}
	return values, true
}

func exactHTTPFormValues(body string) ([]string, bool) {
	if body == "" || strings.ContainsAny(body, "%+\r\n\t") || unresolvedHTTPValue(body) {
		return nil, false
	}
	parts := strings.Split(body, "&")
	if len(parts) == 0 || len(parts) > 64 {
		return nil, false
	}
	values := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		key, value, found := strings.Cut(part, "=")
		if !found || key == "" || value == "" || !httpFieldNamePattern.MatchString(key) ||
			len(value) > maxCommandBytes {
			return nil, false
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, false
		}
		seen[key] = struct{}{}
		values = append(values, value)
	}
	return values, true
}

func unresolvedHTTPValue(value string) bool {
	if strings.ContainsAny(value, "$`\x00") || strings.Contains(value, "{{") ||
		strings.Contains(value, "}}") || strings.Contains(value, "<%") || strings.Contains(value, "%>") {
		return true
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func exactHTTPSQLInjectionTechniques(value string) []HTTPSQLInjectionTechnique {
	if value == "" || len(value) > maxCommandBytes || unresolvedHTTPValue(value) {
		return nil
	}
	techniques := make([]HTTPSQLInjectionTechnique, 0, 2)
	if exactHTTPQuotedBooleanTautology(value) {
		techniques = append(techniques, HTTPSQLInjectionQuotedBooleanTautology)
	}
	if exactHTTPUnionSelect(value) {
		techniques = append(techniques, HTTPSQLInjectionUnionSelect)
	}
	if exactHTTPXPCmdShell(value) {
		techniques = append(techniques, HTTPSQLInjectionXPCmdShell)
	}
	if exactHTTPIntoOutfile(value) {
		techniques = append(techniques, HTTPSQLInjectionIntoOutfile)
	}
	return techniques
}

func exactHTTPQuotedBooleanTautology(value string) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	const quotedMarker = "' or '"
	if index := strings.Index(lower, quotedMarker); index >= 0 &&
		httpSQLIdentifierPrefixPattern.MatchString(value[:index]) {
		matches := httpSQLStringTautologyTailPattern.FindStringSubmatch(
			value[index+len(quotedMarker):],
		)
		if len(matches) != 0 {
			return matches[1] == matches[2]
		}
	}
	matches := httpSQLNumericTautologyPattern.FindStringSubmatch(value)
	return len(matches) != 0 && matches[2] == matches[3]
}

func exactHTTPUnionSelect(value string) bool {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	marker := " union select "
	index := strings.Index(lower, marker)
	if index < 0 || strings.Contains(value, ";") || !httpSQLPrefixPattern.MatchString(strings.TrimSpace(value[:index])) {
		return false
	}
	statement := strings.TrimSpace(value[index+len(marker):])
	comment := strings.LastIndex(statement, "--")
	if comment < 0 || strings.Trim(statement[comment+2:], " -") != "" {
		return false
	}
	statement = strings.TrimSpace(statement[:comment])
	selectPart := statement
	fromPart := ""
	if fromIndex := strings.Index(strings.ToLower(statement), " from "); fromIndex >= 0 {
		selectPart = strings.TrimSpace(statement[:fromIndex])
		fromPart = strings.TrimSpace(statement[fromIndex+len(" from "):])
	}
	if !exactHTTPSelectList(selectPart) {
		return false
	}
	if fromPart == "" {
		return true
	}
	table := fromPart
	where := ""
	if whereIndex := strings.Index(strings.ToLower(fromPart), " where "); whereIndex >= 0 {
		table = strings.TrimSpace(fromPart[:whereIndex])
		where = strings.TrimSpace(fromPart[whereIndex+len(" where "):])
	}
	if !exactHTTPQualifiedIdentifier(table) {
		return false
	}
	return where == "" || httpSQLWherePattern.MatchString(where)
}

func exactHTTPSelectList(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 16 {
		return false
	}
	for _, part := range parts {
		if !httpSQLExpressionPattern.MatchString(strings.TrimSpace(part)) {
			return false
		}
	}
	return true
}

func exactHTTPQualifiedIdentifier(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return false
	}
	for _, part := range parts {
		if !httpSQLIdentifierPattern.MatchString(part) {
			return false
		}
	}
	return true
}

func exactHTTPXPCmdShell(value string) bool {
	prefix, statement, found := strings.Cut(strings.TrimSpace(value), ";")
	if !found || !exactHTTPQuotedBooleanTautology(prefix) {
		return false
	}
	matches := httpSQLXPCmdShellPattern.FindStringSubmatch(strings.TrimSpace(statement))
	return len(matches) != 0 && !unresolvedHTTPValue(matches[1])
}

func exactHTTPIntoOutfile(value string) bool {
	matches := httpSQLIntoOutfilePattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(matches) == 0 {
		return false
	}
	if len(matches[1]) < 16 || len(matches[1]) > 16384 {
		return false
	}
	path := matches[2]
	if unresolvedHTTPValue(path) || strings.Contains(path, "..") {
		return false
	}
	return strings.HasPrefix(path, "/") ||
		(len(path) >= 3 && ((path[0] >= 'A' && path[0] <= 'Z') ||
			(path[0] >= 'a' && path[0] <= 'z')) && path[1] == ':' && path[2] == '\\')
}

func validHTTPSQLInjectionTechnique(technique HTTPSQLInjectionTechnique) bool {
	switch technique {
	case HTTPSQLInjectionQuotedBooleanTautology, HTTPSQLInjectionUnionSelect,
		HTTPSQLInjectionXPCmdShell, HTTPSQLInjectionIntoOutfile:
		return true
	default:
		return false
	}
}
