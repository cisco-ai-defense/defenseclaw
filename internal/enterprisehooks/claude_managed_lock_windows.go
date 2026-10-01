// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"fmt"
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
	if windowsEnterpriseStandaloneProcess() {
		setup.ClaudeAllowManagedHooksOnly = windowsClaudeManagedHooksOnlyEnforced()
		setup.ClaudeCodeAllowUnmanagedHooks = true
	}
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

// currentWindowsClaudeManagedPolicyAllowsUnmanagedHooks returns the lock state
// of the active machine-wide Claude Code policy. Deferred staging only adds a
// SID to that shared policy and has no administrator configuration of its own,
// so it keeps the published lock state instead of resetting an opt-out. A
// missing policy reports the secure default (locked).
func currentWindowsClaudeManagedPolicyAllowsUnmanagedHooks() (bool, error) {
	allow := false
	err := windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		if err := windowsManagedPolicyFileTrustCheckIfExists(path); err != nil {
			return err
		}
		policy, err := snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedPolicyLimit)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		locked, err := connector.ClaudeCodeManagedHookPolicyEnforcesManagedOnly(policy.data)
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect Claude Code managed hooks-only lock: %w", err)
		}
		allow = !locked
		return nil
	})
	return allow, err
}

func windowsManagedPolicyFileTrustCheckIfExists(path string) error {
	if !windowsPathExists(path) {
		return nil
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return fmt.Errorf("enterprise hooks: untrusted Claude Code managed policy %s: %w", path, err)
	}
	return nil
}
