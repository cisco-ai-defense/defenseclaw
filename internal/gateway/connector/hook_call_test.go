// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "strings"

// hookCallBlocked reports whether a shell hook run denied the call, in any
// connector's native answer: an error status, or a deny/block document.
func hookCallBlocked(err error, out string) bool {
	if err != nil {
		return true
	}
	for _, marker := range []string{`"decision":"deny"`, `"decision":"block"`, `"action":"block"`,
		`"permission":"deny"`, `"permissionDecision":"deny"`, `"behavior":"deny"`, `"continue":false`} {
		if strings.Contains(out, marker) {
			return true
		}
	}
	return false
}
