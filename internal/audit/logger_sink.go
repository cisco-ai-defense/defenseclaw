// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// safeSinkHealthDimension converts a caller-provided subsystem name into the
// bounded stable token required by canonical v8 platform-health families. It
// intentionally retains no endpoint or credential-shaped source value.
func safeSinkHealthDimension(value string) string {
	value = strings.TrimSpace(value)
	if observability.IsStableToken(value) {
		return value
	}
	if value != "" && len(value) <= observability.MaxStableTokenBytes &&
		!strings.Contains(strings.ToLower(value), "://") {
		var normalized strings.Builder
		previousSeparator := false
		for _, character := range strings.ToLower(value) {
			allowed := character >= 'a' && character <= 'z' ||
				character >= '0' && character <= '9' || character == '.' ||
				character == '_' || character == '-'
			if allowed {
				normalized.WriteRune(character)
				previousSeparator = false
				continue
			}
			if normalized.Len() > 0 && !previousSeparator {
				normalized.WriteByte('-')
				previousSeparator = true
			}
		}
		candidate := strings.Trim(normalized.String(), "-._")
		if observability.IsStableToken(candidate) {
			return candidate
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "sink-" + hex.EncodeToString(digest[:8])
}
