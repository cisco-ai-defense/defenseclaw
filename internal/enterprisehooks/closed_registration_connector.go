// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "strings"

// WindowsClosedRegistrationProofConnector reports whether
// WindowsProtectedTargetHasClosedMachineRegistration can prove, for the
// connector, that a registered machine hook fails closed for a signed-out
// account: Claude Code and Codex. For every other connector no such proof
// exists, and an account's wait for its next sign-in rests on the earlier
// release's lock alone (GAP-0980).
func WindowsClosedRegistrationProofConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "claudecode", "codex":
		return true
	}
	return false
}
