// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

// RedactURLQueryCredentialsForCompatibility applies the canonical
// secrets.url_query recognizer to a compatibility telemetry copy. It reuses
// the observability detector's key allowlist so signed-URL handling cannot
// drift. Recognition failures fail closed by redacting the whole content.
func RedactURLQueryCredentialsForCompatibility(input string) string {
	recognized, boundaries := normalizeJSONEscapedURLSyntax(input)
	candidates, err := recognize("secrets.url_query", recognized, observability.FieldClassContent, nil)
	if err != nil {
		return legacyredaction.ForSinkMessageContent(input)
	}
	accepted := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		if item.accepted && item.start >= 0 && item.end > item.start && item.end < len(boundaries) {
			start, end := boundaries[item.start], boundaries[item.end]
			if start >= 0 && end > start && end <= len(input) {
				accepted = append(accepted, candidate{start: start, end: end, accepted: true})
			}
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })
	if len(accepted) == 0 {
		return input
	}
	var output strings.Builder
	output.Grow(len(input))
	previousEnd := 0
	for _, item := range accepted {
		if item.start < previousEnd {
			continue
		}
		output.WriteString(input[previousEnd:item.start])
		output.WriteString(legacyredaction.ForSinkEntity(input[item.start:item.end]))
		previousEnd = item.end
	}
	output.WriteString(input[previousEnd:])
	return output.String()
}

// normalizeJSONEscapedURLSyntax exposes slash, ampersand, and semicolon
// URL syntax encoded inside JSON string values to the canonical recognizer.
// boundaries maps every normalized byte boundary back to its original input
// boundary so only credential values are replaced in the source text.
func normalizeJSONEscapedURLSyntax(input string) (string, []int) {
	var normalized strings.Builder
	normalized.Grow(len(input))
	boundaries := make([]int, 1, len(input)+1)
	for index := 0; index < len(input); {
		if index+2 <= len(input) && input[index] == '\\' && input[index+1] == '\\' {
			normalized.WriteString(input[index : index+2])
			index += 2
			boundaries = append(boundaries, index-1, index)
			continue
		}
		if index+2 <= len(input) && input[index] == '\\' && input[index+1] == '/' {
			normalized.WriteByte('/')
			index += 2
			boundaries = append(boundaries, index)
			continue
		}
		if index+6 <= len(input) && input[index] == '\\' && input[index+1] == 'u' {
			escape := strings.ToLower(input[index+2 : index+6])
			if escape == "0026" || escape == "003b" {
				separator := byte('&')
				if escape == "003b" {
					separator = ';'
				}
				normalized.WriteByte(separator)
				index += 6
				boundaries = append(boundaries, index)
				continue
			}
		}
		normalized.WriteByte(input[index])
		index++
		boundaries = append(boundaries, index)
	}
	return normalized.String(), boundaries
}
