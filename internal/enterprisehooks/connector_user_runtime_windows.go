// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/windows"
)

// windowsMachineScopeUserRuntimeConnectors are the connectors the standalone
// profile enrolls by machine policy (Claude Code, Codex, Cursor): the roster
// change that removes one revokes its machine enrollment at once, and what the
// connector wrote into each enrolled account's own DefenseClaw folder stays
// until RemoveWindowsConnectorUserRuntime takes it out.
var windowsMachineScopeUserRuntimeConnectors = []string{"claudecode", "codex", "cursor"}

// WindowsMachineScopeUserRuntimeConnector reports whether name is one of them.
func WindowsMachineScopeUserRuntimeConnector(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, candidate := range windowsMachineScopeUserRuntimeConnectors {
		if candidate == name {
			return true
		}
	}
	return false
}

// WindowsMachineScopeUserRuntimeConnectorNames lists them.
func WindowsMachineScopeUserRuntimeConnectorNames() []string {
	return append([]string(nil), windowsMachineScopeUserRuntimeConnectors...)
}

// windowsConnectorUserRuntimeLeaves returns, relative to the account's
// DefenseClaw folder, every file the managed install of one machine-scope
// connector wrote for the account and no other connector shares: the entries
// of its bounded cleanup contract in hooks (the scoped hook token, the hook
// config, a connector's own hook script) minus the shell scripts that every
// script-rendering connector shares, and the runtime generation records
// (.managed-runtime-<connector>-<id>.json), which the caller lists.
func windowsConnectorUserRuntimeLeaves(name string) ([]string, error) {
	files, ok := windowsManagedRuntimeCleanupConnectors[name]
	if !ok || !WindowsMachineScopeUserRuntimeConnector(name) {
		return nil, fmt.Errorf("enterprise hooks: %q has no machine-scope user runtime to remove", name)
	}
	shared := make(map[string]struct{}, len(windowsManagedRuntimeSharedHookScripts))
	for _, leaf := range windowsManagedRuntimeSharedHookScripts {
		shared[leaf] = struct{}{}
	}
	var leaves []string
	for _, leaf := range files.hooks {
		if _, isShared := shared[leaf]; !isShared {
			leaves = append(leaves, filepath.Join("hooks", leaf))
		}
	}
	return leaves, nil
}

// WindowsConnectorUserRuntimeLeftover reports whether the account's DefenseClaw
// folder still holds, for one machine-scope connector, a file its managed
// install wrote: the scoped hook token, the hook config, the connector's own
// hook script or a runtime generation record. It only looks, so the guardian
// can ask it for every profile on every pass and queue
// RemoveWindowsConnectorUserRuntime only where there is something to remove
// (GAP-0964). The removal itself pins the folder and leaves a link as found, so
// a link planted for this answer changes nothing but the question. An
// unreadable folder says false.
func WindowsConnectorUserRuntimeLeftover(rawHome, rawDataDir, connectorName string) bool {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	leaves, err := windowsConnectorUserRuntimeLeaves(name)
	if err != nil {
		return false
	}
	home := filepath.Clean(strings.TrimSpace(rawHome))
	if !filepath.IsAbs(home) {
		return false
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, rawDataDir)
	if err != nil {
		return false
	}
	for _, leaf := range leaves {
		if _, err := os.Lstat(filepath.Join(dataDir, leaf)); err == nil {
			return true
		}
	}
	entries, err := os.ReadDir(filepath.Join(dataDir, "hooks"))
	if err != nil {
		return false
	}
	prefix := ".managed-runtime-" + name + "-"
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), ".json") {
			return true
		}
	}
	return false
}

// windowsConnectorUserRuntimeBeforeLockClear runs, while the folder is pinned,
// right before the privileged lock-entry write; a seam for tests.
var windowsConnectorUserRuntimeBeforeLockClear = func() {}

// ErrWindowsConnectorUserRuntimeKept is returned when the account's DefenseClaw
// folder holds a per-user DefenseClaw install: its files are left as found, so
// the cleanup is not done and the guardian reports and retries it.
var ErrWindowsConnectorUserRuntimeKept = errors.New("the account's DefenseClaw folder holds a per-user DefenseClaw install, so the removed connector's files in it were left as found")

// RemoveWindowsConnectorUserRuntime removes, for one account and one
// machine-scope connector (Claude Code, Codex or Cursor) a roster change took
// off the roster, what that connector's managed install wrote into the
// account's %USERPROFILE%\.defenseclaw: its scoped hook token, its hook
// config, its own hook script, its runtime generation records and its entry of
// the hook contract lock. Nothing the account or another connector owns is
// touched: the shared hook scripts, the other connectors' files, the account's
// own agent configuration and the folder itself stay. It runs as LocalSystem,
// whether or not the account is signed in, and never through a link: a link or
// junction at the folder, at hooks or at an entry is left as found. A missing
// folder or file is not an error. The machine enrollment is not touched; the
// guardian revoked it first, so the account's hook already fails closed.
//
// It holds the account's runtime transaction lock (the one an install and a
// managed-policy removal hold), so a connector admitted again between the
// plan and the run cannot lose a file the install has just written. A folder
// that holds a per-user DefenseClaw install (windowsPerUserInstallLeftover) is
// left as found, as RemoveWindowsManagedUserRuntime leaves it: its files may
// be that install's. That is reported as ErrWindowsConnectorUserRuntimeKept,
// not as done, while the files are still there. The lock entry is cleared while the folder is still
// pinned, so the folder cannot be swapped for a junction between the link
// check and the privileged write.
func RemoveWindowsConnectorUserRuntime(rawHome, rawSID, rawDataDir, connectorName string) error {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	leaves, err := windowsConnectorUserRuntimeLeaves(name)
	if err != nil {
		return err
	}
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, rawDataDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(home, dataDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return fmt.Errorf("enterprise hooks: refusing to clean %s, which is not below the profile %s", dataDir, home)
	}
	unlock, err := lockWindowsUserRuntimeTransaction(sid.String())
	if err != nil {
		return err
	}
	defer unlock()
	linked := fmt.Errorf("enterprise hooks: %s is reached through a link or junction; left as found", dataDir)
	if err := inventoryDACLRejectLinkBelow(home, rel); errors.Is(err, errInventoryDACLLink) {
		return linked
	} else if err != nil {
		return err
	}
	info, err := os.Lstat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("enterprise hooks: refusing to clean %s, which is not a plain folder", dataDir)
	}
	if leftover := windowsPerUserInstallLeftover(dataDir); leftover != "" {
		return fmt.Errorf("%w (%s)", ErrWindowsConnectorUserRuntimeKept, leftover)
	}
	pin, err := openWindowsUserStatePin(home, rel)
	if errors.Is(err, errInventoryDACLLink) {
		return linked
	}
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		pin.Close()
		return err
	}
	removeErr := func() error {
		pinned, err := pin.Stat()
		if err != nil {
			return err
		}
		opened, err := root.Stat(".")
		if err != nil {
			return err
		}
		if !pinned.IsDir() || pinned.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !os.SameFile(pinned, opened) {
			return fmt.Errorf("enterprise hooks: refusing to clean %s, which changed while it was opened", dataDir)
		}
		if err := removeWindowsConnectorUserRuntimeEntries(root, windows.Handle(pin.Fd()), name, leaves); err != nil {
			return err
		}
		// The connector's entry of the hook contract lock goes last, through
		// the lock's own owner-bound writer (it claims the entry and removes
		// exactly that one, and removes nothing when the entry names another
		// gateway). The folder is still pinned, without delete sharing, so it
		// cannot be replaced; the link check is repeated right before the
		// privileged write all the same. A missing lock is not an error.
		// Writing the account's protected file as LocalSystem needs the
		// restore privilege that helper provides.
		windowsConnectorUserRuntimeBeforeLockClear()
		if err := inventoryDACLRejectLinkBelow(home, rel); err != nil {
			return errors.Join(err, linked)
		}
		lock, err := root.Lstat("hook_contract_lock.json")
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !lock.Mode().IsRegular() {
			return fmt.Errorf("enterprise hooks: refusing to change %s, which is not a regular file", filepath.Join(dataDir, "hook_contract_lock.json"))
		}
		return RunWithWindowsAdministratorOwnerRestorePrivilege(func() error {
			if err := connector.ClearManagedHookContractLockEntryForOwner(
				dataDir, name, sid.String(), managed.StandaloneWindowsGatewaySvc,
			); err != nil {
				return fmt.Errorf("enterprise hooks: clear connector %s hook contract lock: %w", name, err)
			}
			return nil
		})
	}()
	root.Close()
	pin.Close()
	if err := inventoryDACLRejectLinkBelow(home, rel); err != nil {
		return errors.Join(removeErr, linked)
	}
	return removeErr
}

// removeWindowsConnectorUserRuntimeEntries removes the named leaves and the
// connector's runtime generation records below root, each through
// removeWindowsManagedUserRuntimeEntry (a link is named and left as found; an
// entry whose access list refuses LocalSystem goes with backup intent).
func removeWindowsConnectorUserRuntimeEntries(root *os.Root, pin windows.Handle, name string, leaves []string) error {
	if info, err := root.Lstat("hooks"); err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return errors.New("enterprise hooks: the hooks folder is a link or junction; left as found")
	}
	var failures []error
	var links []string
	for _, leaf := range leaves {
		failures = append(failures, removeWindowsManagedUserRuntimeEntry(root, pin, leaf, 0, &links))
	}
	if info, err := root.Lstat("hooks"); err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		names, err := windowsManagedUserRuntimeDirNames(root, "hooks")
		if err != nil {
			failures = append(failures, fmt.Errorf("enterprise hooks: list hooks: %w", err))
		}
		prefix := ".managed-runtime-" + name + "-"
		for _, entry := range names {
			if strings.HasPrefix(entry, prefix) && strings.HasSuffix(entry, ".json") {
				failures = append(failures, removeWindowsManagedUserRuntimeEntry(root, pin, filepath.Join("hooks", entry), 0, &links))
			}
		}
	}
	return errors.Join(failures...)
}
