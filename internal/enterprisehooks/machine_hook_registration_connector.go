// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "strings"

// WindowsMachineHookRegistrationConnector reports whether the standalone
// guardian itself publishes the machine policy that registers the
// connector's hook for every account: Copilot (the policy.d drop-in), OpenCode
// (its managed config, while that machine policy is in force) and Cursor (its
// machine hooks file). For these the registration is machine-side state a
// signed-out account cannot change, so an upgrade's drift in the account's
// own folder can wait for its next sign-in once
// WindowsProtectedTargetHasMachineHookRegistration proves the policy is in
// force (GAP-0980). Claude Code and Codex have a stricter proof
// (WindowsProtectedTargetHasClosedMachineRegistration), and the connectors
// that register their hooks in the account's own agent configuration (Hermes,
// Amp, Devin and the rest) have none.
func WindowsMachineHookRegistrationConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "copilot", "opencode", "cursor":
		return true
	}
	return false
}
