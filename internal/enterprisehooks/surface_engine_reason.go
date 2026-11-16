// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"unicode"
)

// engineUnverifiedReasonMax bounds connector.AgentSurface.EngineUnverified.
const engineUnverifiedReasonMax = 1024

// ValidEngineUnverifiedReason checks the reason a per-user discovery worker
// gives for an engine build it did not identify: the worker runs as the
// user, so the parent keeps only bounded, printable text.
func ValidEngineUnverifiedReason(reason string) bool {
	if reason == "" || len(reason) > engineUnverifiedReasonMax {
		return false
	}
	for _, r := range reason {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// boundEngineUnverifiedReason cuts reason (it may name a long path) to
// engineUnverifiedReasonMax bytes, on a character boundary.
func boundEngineUnverifiedReason(reason string) string {
	if len(reason) <= engineUnverifiedReasonMax {
		return reason
	}
	return strings.ToValidUTF8(reason[:engineUnverifiedReasonMax-3], "") + "..."
}
