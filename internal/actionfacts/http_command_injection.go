// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var httpCommandInjectionPattern = regexp.MustCompile(
	`^[^;&|<>\\]+(?:;|&&|\|\||\|) *(?:id|whoami) *$`,
)

// ExactHTTPCommandInjection reports one exact, value-free proof. Request
// values and even the reviewed proof-command class remain private.
func ExactHTTPCommandInjection(facts Facts) bool {
	return facts.Parse.Status == StatusComplete &&
		len(facts.HTTPCommandInjections) == 1
}

func projectHTTPCommandInjections(input Input) []HTTPCommandInjectionFact {
	if input.Tool != "http_request" || input.Command != "" || len(input.Argv) != 0 ||
		containsJSONUnicodeEscape(input.Args) {
		return nil
	}
	request, ok := exactHTTPRequestInput(input.Args)
	if !ok {
		return nil
	}
	for _, value := range request.values {
		if exactHTTPCommandInjectionValue(value) {
			return []HTTPCommandInjectionFact{{}}
		}
	}
	return nil
}

func exactHTTPCommandInjectionValue(value string) bool {
	if value == "" || len(value) > maxScalarBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.Contains(value, "%") ||
		strings.ContainsAny(value, "$`\\\"'") ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 || unresolvedHTTPValue(value) {
		return false
	}
	return httpCommandInjectionPattern.MatchString(value)
}

func containsJSONUnicodeEscape(raw []byte) bool {
	return bytes.Contains(raw, []byte(`\u`))
}
