// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// The helpers below serve the rollback of a failed first standalone install
// (FUB-WIN-F76). The guardian may already have registered DefenseClaw in the
// accounts' agent configurations and published per-user and machine policy
// before the install failed; the rollback removes all of it.

// RestoreWindowsStandaloneUserAgentConfigs puts back, as the account, every
// agent file a connector setup recorded in the account's DefenseClaw folder:
// the bytes setup found, or no file when setup created it
// (connector.RestoreManagedFileBackups). It runs before the rollback removes
// the folder that holds the records, and writes nothing into it. An account
// without a session returns an error IsWindowsTargetSessionUnavailable
// recognizes.
func RestoreWindowsStandaloneUserAgentConfigs(userHome, ownerSID, dataDir string) (restored, kept []string, err error) {
	home, sid, err := validateWindowsEnterpriseHome(userHome, ownerSID)
	if err != nil {
		return nil, nil, err
	}
	resolved, err := resolveWindowsEnterpriseDataDir(home, dataDir)
	if err != nil {
		return nil, nil, err
	}
	targets, err := connector.ManagedFileBackupTargets(resolved)
	if err != nil || len(targets) == 0 {
		return nil, nil, err
	}
	// The guardian hardened the folders of the agent files it patched, which
	// takes the owner's WRITE_DAC. As a connector teardown does, give them
	// the owner-private shape a connector setup keeps (as LocalSystem, before
	// the impersonation), so the account can write its files back. Nothing
	// inside the DefenseClaw folder changes: the rollback cleanup that
	// follows requires its exact DACLs.
	var relaxErrs []error
	relaxTarget := windowsGenericManagedTarget{home: home, dataDir: resolved, sid: sid}
	for _, target := range targets {
		directory := filepath.Dir(filepath.Clean(target))
		if !windowsPathWithin(home, directory) ||
			sameWindowsEnterprisePath(directory, resolved) || windowsPathWithin(resolved, directory) {
			continue
		}
		if _, err := relaxWindowsStandalonePerUserDirectory(relaxTarget, directory); err != nil {
			relaxErrs = append(relaxErrs, err)
		}
	}
	err = windowsEnterpriseTargetImpersonation(sid, home, func() error {
		var restoreErr error
		restored, kept, restoreErr = connector.RestoreManagedFileBackups(resolved, home)
		return restoreErr
	})
	return restored, kept, errors.Join(append(relaxErrs, err)...)
}

// RemoveWindowsStandalonePerUserRuntimeSelectors removes the runtime selector
// of every standalone per-user connector. A connector without its machine
// directory has none, and none is created.
func RemoveWindowsStandalonePerUserRuntimeSelectors() error {
	var errs []error
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		present, err := windowsPerUserManagedRuntimeDirPresent(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !present {
			continue
		}
		current, err := CaptureWindowsManagedRuntimeSelector(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: read the %s runtime selector: %w", name, err))
			continue
		}
		if !current.Existed {
			continue
		}
		if err := RestoreWindowsManagedRuntimeSelectorCAS(WindowsManagedRuntimeSelectorFullRestoreOptions{
			Snapshot:        WindowsManagedRuntimeSelectorSnapshot{SchemaVersion: 1, Connector: name},
			ExpectedCurrent: current.CAS,
		}); err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove the %s runtime selector: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// RemoveWindowsStandaloneManagedPolicyLocks removes the Claude Code and Codex
// managed-policy transaction lock files in those vendors' machine-policy
// folders. A lock that is not a plain administrator-owned file stays and is
// reported.
func RemoveWindowsStandaloneManagedPolicyLocks(codexRequirementsPath string) error {
	if !windowsEnterpriseStandaloneProcess() {
		return nil
	}
	policyPath, err := windowsClaudeManagedPolicyPath()
	if err != nil {
		return err
	}
	locks := []string{filepath.Join(filepath.Dir(policyPath), windowsClaudeManagedLockFile)}
	if path := strings.TrimSpace(codexRequirementsPath); path != "" {
		locks = append(locks, filepath.Join(filepath.Dir(filepath.Clean(path)), windowsClaudeManagedLockFile))
	}
	var errs []error
	for _, lock := range locks {
		info, err := os.Lstat(lock)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && !info.Mode().IsRegular() {
			err = fmt.Errorf("%s is not a regular file", lock)
		}
		if err == nil {
			err = rejectWindowsReparseChain(lock)
		}
		if err == nil {
			err = windowsManagedPolicyFileTrustCheck(lock)
		}
		if err == nil {
			if err = os.Remove(lock); errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove the managed policy lock %s: %w", lock, err))
		}
	}
	return errors.Join(errs...)
}
