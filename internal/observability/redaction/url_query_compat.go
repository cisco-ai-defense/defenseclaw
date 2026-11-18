// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

// RedactURLQueryCredentialsForCompatibility applies the canonical
// secrets.url_query recognizer to a compatibility telemetry copy. It reuses
// the observability detector's key allowlist so signed-URL handling cannot
// drift. Recognition failures fail closed by redacting the whole content.
func RedactURLQueryCredentialsForCompatibility(input string) string {
	candidates, err := recognize("secrets.url_query", input, observability.FieldClassContent, nil)
	if err != nil {
		return legacyredaction.ForSinkMessageContent(input)
	}
	accepted := make([]candidate, 0, len(candidates))
	for _, item := range candidates {
		if item.accepted && item.start >= 0 && item.end > item.start && item.end <= len(input) {
			accepted = append(accepted, item)
		}
	}
	sort.Slice(accepted, func(i, j int) bool { return accepted[i].start < accepted[j].start })
	output := input
	for index := len(accepted) - 1; index >= 0; index-- {
		item := accepted[index]
		output = output[:item.start] + legacyredaction.ForSinkEntity(input[item.start:item.end]) + output[item.end:]
	}
	return output
}
