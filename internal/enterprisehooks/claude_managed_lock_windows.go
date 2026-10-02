// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The standalone Claude Code managed drop-in carries allowManagedHooksOnly:
// true while the claudecode machine policy is managed_hooks_only: enforce,
// the default, as the Unix drop-in rendered by enterprisepolicy does. Without
// it a user or project hook that returns updatedInput changes the command
// after DefenseClaw inspected the original. Every standalone path
// that renders or verifies the machine-wide Claude policy applies the lock
// through withWindowsClaudeManagedHooksOnly, so install, the guardian's
// verify and repair, and deferred staging agree on one body. Secure Client
// processes never render it: their drop-in bytes are fixed by the Secure
// Client golden.

var windowsClaudeManagedHooksOnlyPolicy struct {
	sync.Mutex
	enforce func() bool
}

// SetWindowsClaudeManagedHooksOnlyPolicy installs the check that reports
// whether the administrator's claudecode machine policy enforces the
// managed-hooks-only lock. The CLI installs one that reads the loaded
// config; unset, the secure default (enforce) applies.
func SetWindowsClaudeManagedHooksOnlyPolicy(enforce func() bool) {
	windowsClaudeManagedHooksOnlyPolicy.Lock()
	defer windowsClaudeManagedHooksOnlyPolicy.Unlock()
	windowsClaudeManagedHooksOnlyPolicy.enforce = enforce
}

func windowsClaudeManagedHooksOnlyEnforced() bool {
	windowsClaudeManagedHooksOnlyPolicy.Lock()
	enforce := windowsClaudeManagedHooksOnlyPolicy.enforce
	windowsClaudeManagedHooksOnlyPolicy.Unlock()
	if enforce == nil {
		return true
	}
	return enforce()
}

// withWindowsClaudeManagedHooksOnly returns setup with the lock this process
// renders and verifies in the machine-wide Claude policy: on in a standalone
// process whose policy enforces it, off otherwise (always off for Secure
// Client).
func withWindowsClaudeManagedHooksOnly(setup connector.SetupOpts) connector.SetupOpts {
	setup.ClaudeAllowManagedHooksOnly = windowsEnterpriseStandaloneProcess() && windowsClaudeManagedHooksOnlyEnforced()
	return setup
}

// windowsClaudeManagedPolicyHasLock reports whether a persisted drop-in sets
// allowManagedHooksOnly: true; an unreadable document has no lock.
func windowsClaudeManagedPolicyHasLock(data []byte) bool {
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false
	}
	return settings["allowManagedHooksOnly"] == true
}
