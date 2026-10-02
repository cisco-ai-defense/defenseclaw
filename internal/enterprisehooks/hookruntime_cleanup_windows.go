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

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// windowsStandaloneHookRuntimeRoot is the standalone hook runtime directory
// (C:\ProgramData\Cisco\DefenseClaw-HookRuntime) that holds one directory per
// per-user connector.
var windowsStandaloneHookRuntimeRoot = func() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	return layout.HookRuntimeDir, nil
}

// windowsHookRuntimeLockFiles are the only files DefenseClaw leaves in a
// per-user connector directory once its enrollment and selector are gone.
var windowsHookRuntimeLockFiles = map[string]struct{}{
	strings.ToLower(windowsPerUserManagedEnrollmentLockFile): {},
	strings.ToLower(windowsManagedRuntimeSelectorLockFile):   {},
}

// RemoveWindowsStandaloneHookRuntimeDirectories is the last step of a
// standalone managed-hook teardown. Each per-user connector directory that
// holds only DefenseClaw's lock files loses them and is removed, then the
// hook runtime root is removed once it is empty. A directory that still holds
// an enrollment, a selector or any other entry is left in place: teardown
// verification owns those, and nothing unexpected is deleted. It returns the
// directories that could not be removed.
func RemoveWindowsStandaloneHookRuntimeDirectories() ([]string, error) {
	if !windowsEnterpriseStandaloneProcess() {
		return nil, nil
	}
	root, err := windowsStandaloneHookRuntimeRoot()
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: resolve the standalone hook runtime directory: %w", err)
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, fmt.Errorf("enterprise hooks: refusing noncanonical hook runtime directory %s", root)
	}
	if exists, err := windowsHookRuntimePlainDirectory(root); err != nil || !exists {
		return nil, err
	}
	var kept []string
	var errs []error
	for _, name := range WindowsStandalonePerUserConnectorNames() {
		directory, err := windowsPerUserManagedRuntimeDir(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !sameWindowsEnterprisePath(filepath.Dir(directory), root) {
			errs = append(errs, fmt.Errorf("enterprise hooks: %s runtime directory %s is outside %s", name, directory, root))
			continue
		}
		removed, err := removeWindowsHookRuntimeConnectorDirectory(directory)
		if err != nil {
			errs = append(errs, err)
		}
		if !removed {
			kept = append(kept, directory)
		}
	}
	if err := os.Remove(root); err != nil && !errors.Is(err, os.ErrNotExist) {
		if !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove hook runtime directory %s: %w", root, err))
		}
		kept = append(kept, root)
	}
	return kept, errors.Join(errs...)
}

// windowsMachinePolicySelectorConnectors are the connectors whose runtime
// selector sits in a vendor machine-policy directory instead of the hook
// runtime root.
var windowsMachinePolicySelectorConnectors = []string{"claudecode", "codex", "cursor"}

// windowsSelectorTargetAccountRemoved reports a runtime selector entry whose
// local account was deleted together with its profile folder: no one can
// sign in as it, and its runtime bundle went with the profile. A domain or
// Entra account's lookup also fails while its directory is unreachable, so
// only a local account qualifies. Tests replace it.
var windowsSelectorTargetAccountRemoved = func(entry windowsManagedRuntimeSelectorTarget) bool {
	if _, err := os.Lstat(entry.DataDir); !errors.Is(err, os.ErrNotExist) {
		return false
	}
	sid, err := windows.StringToSid(entry.SID)
	if err != nil || !WindowsLocalAccountSID(sid.String()) {
		return false
	}
	_, _, _, err = sid.LookupAccount("")
	return errors.Is(err, windows.ERROR_NONE_MAPPED)
}

// RemoveWindowsStandaloneDeletedAccountSelectorTargets drops, at the end of a
// standalone uninstall, the runtime selector entries of local accounts that
// were deleted together with their profile folder. Such an account has left
// the enrollment manifest and the teardown revokes only the manifest's
// targets, so its entry would otherwise keep the selector, and the lock
// beside it, in the vendor's machine-policy folder after the uninstall. The
// entry was already unusable. Every other entry is left to the teardown.
func RemoveWindowsStandaloneDeletedAccountSelectorTargets() error {
	if !windowsEnterpriseStandaloneProcess() {
		return nil
	}
	connectors := append(
		append([]string(nil), windowsMachinePolicySelectorConnectors...),
		WindowsStandalonePerUserConnectorNames()...,
	)
	var errs []error
	for _, name := range connectors {
		path, err := windowsManagedRuntimeSelectorPath(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: inspect %s: %w", path, err))
			continue
		}
		if err := windowsManagedRuntimeSelectorMutationAuthorize(); err != nil {
			return err
		}
		err = withWindowsManagedRuntimeSelectorTransaction(name, func() error {
			selector, _, exists, err := readWindowsManagedRuntimeSelector(name, true)
			if err != nil || !exists {
				return err
			}
			kept := make([]windowsManagedRuntimeSelectorTarget, 0, len(selector.Targets))
			for _, entry := range selector.Targets {
				if !windowsSelectorTargetAccountRemoved(entry) {
					kept = append(kept, entry)
				}
			}
			if len(kept) == len(selector.Targets) {
				return nil
			}
			selector.Targets = kept
			return publishOrRemoveWindowsManagedRuntimeSelector(selector)
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: drop deleted accounts from the %s runtime selector: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// RemoveWindowsStandaloneMachinePolicySelectorLocks drops the runtime selector
// lock that selector transactions leave in each machine-policy connector's
// vendor directory (Claude Code's managed-settings.d, and the Codex and Cursor
// machine folders), so a standalone uninstall leaves no DefenseClaw file
// there. It runs after the teardown's last selector transaction. A lock whose
// selector still exists is kept, since teardown verification owns that
// selector, and the shared vendor directories are left as found.
func RemoveWindowsStandaloneMachinePolicySelectorLocks() error {
	if !windowsEnterpriseStandaloneProcess() {
		return nil
	}
	var errs []error
	for _, name := range windowsMachinePolicySelectorConnectors {
		selector, err := windowsManagedRuntimeSelectorPath(name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := os.Lstat(selector); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("enterprise hooks: inspect %s: %w", selector, err))
			continue
		}
		lock := filepath.Join(filepath.Dir(selector), windowsManagedRuntimeSelectorLockFile)
		info, err := os.Lstat(lock)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && !info.Mode().IsRegular() {
			err = fmt.Errorf("enterprise hooks: %s is not a regular file", lock)
		}
		if err == nil {
			err = rejectWindowsReparseChain(lock)
		}
		if err == nil {
			if err = os.Remove(lock); errors.Is(err, os.ErrNotExist) {
				err = nil
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("enterprise hooks: remove the %s runtime selector lock: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// windowsHookRuntimePlainDirectory reports whether path is an existing plain
// directory; a reparse point or a file in its place is an error.
func windowsHookRuntimePlainDirectory(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: inspect %s: %w", path, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("enterprise hooks: %s is not a plain directory", path)
	}
	if err := rejectWindowsReparseChain(path); err != nil {
		return false, err
	}
	return true, nil
}

// removeWindowsHookRuntimeConnectorDirectory removes one connector directory
// when it holds nothing but DefenseClaw lock files. It reports whether the
// directory is gone.
func removeWindowsHookRuntimeConnectorDirectory(directory string) (bool, error) {
	exists, err := windowsHookRuntimePlainDirectory(directory)
	if err != nil || !exists {
		return !exists && err == nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: list %s: %w", directory, err)
	}
	for _, entry := range entries {
		if _, lock := windowsHookRuntimeLockFiles[strings.ToLower(entry.Name())]; !lock || !entry.Type().IsRegular() {
			return false, nil
		}
	}
	for _, entry := range entries {
		if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("enterprise hooks: remove %s: %w", filepath.Join(directory, entry.Name()), err)
		}
	}
	if err := os.Remove(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: remove %s: %w", directory, err)
	}
	return true, nil
}
