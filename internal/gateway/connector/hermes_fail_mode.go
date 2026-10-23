// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

// hookBlocksItsOwnFailures reports a connector whose rendered hook keeps the
// resolved "closed" fail mode although the agent itself has no fail-closed
// hook contract (HookCapability.SupportsFailClosed is false).
//
// That is the per-user Copilot CLI, Antigravity and Hermes hook on every OS.
// Each of these agents lets a call run when its hook times out or cannot
// start, which is why SupportsFailClosed stays false, but each honours a
// native deny the hook prints: Copilot's permissionDecision / behavior deny,
// Antigravity's PreToolUse decision deny and Hermes' block directive. The
// Linux and macOS hook scripts and the Windows native hook (hookexec) print
// that deny for every failure DefenseClaw itself sees when their fail mode
// is closed: the gateway is down or does not answer, its answer cannot be
// used, the token is missing, or the input is too large. Downgrading the
// render to "open" let such a tool call run during a gateway outage with a
// closed or unset hook_fail_mode, against the rule that hooks fail open only
// under Secure Client. A saved per-user "open" also resolves closed.
//
// Managed renders keep their own rules: a standalone render is closed for
// every connector (managedStandaloneRender), and Secure Client keeps these
// connectors open.
func hookBlocksItsOwnFailures(opts SetupOpts, conn Connector) bool {
	if conn == nil || opts.ManagedEnterprise {
		return false
	}
	switch conn.Name() {
	case "antigravity", "copilot", "hermes":
		return true
	}
	return false
}
