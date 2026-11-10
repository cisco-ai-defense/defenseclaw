// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "strings"

// WindowsManagedRuntimePendingForSID reports, only on positive proof, that the
// standalone hook of connectorName refuses the account sid as
// enterprise_managed_enrollment_pending (GAP-1034): the connector's primary
// machine policy registers the SID and no managed runtime generation is
// selected for it. That is the check the hook makes (the registered check,
// then the machine runtime selector), made from the service's token, so the
// user's own status can say the agent is blocked until the account signs in
// without any read of the guardian's ledger. Both inputs are machine files the
// hook already reads as the user. Any unreadable input, an inactive policy, a
// SID the policy does not register, a selected runtime (whatever its state) and
// every connector but Claude Code, Codex and Cursor give false: the status
// then claims nothing new.
func WindowsManagedRuntimePendingForSID(connectorName, sid string) bool {
	if !windowsEnterpriseStandaloneProcess() {
		return false
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	switch name {
	case "claudecode", "codex", "cursor":
	default:
		return false
	}
	sid = strings.ToUpper(strings.TrimSpace(sid))
	if sid == "" {
		return false
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return false
	}
	registered, err := windowsMachinePolicyRegisteredSIDs(name, hookExecutable)
	if err != nil || !registered[sid] {
		return false
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(name, true)
	if err != nil {
		return false
	}
	if !exists {
		return true
	}
	_, selected := windowsManagedRuntimeSelectorTargetForSID(selector, sid)
	return !selected
}
