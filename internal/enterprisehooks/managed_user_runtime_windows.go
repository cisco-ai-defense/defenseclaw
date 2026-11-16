// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// windowsManagedUserRuntimeEntries are the entries the standalone managed
// runtime and its hooks write into an enrolled account's
// %USERPROFILE%\.defenseclaw, as LocalSystem or for the account: hooks (the
// hook scripts, .hookcfg files, hook tokens and runtime generations), logs
// (the hook's hook-failures.jsonl), the hook contract lock and its lock file,
// the gateway's inventory database, the foreign-hook policy's
// foreign-hook-env.json and foreign-hook-sessions, and every root leaf the
// per-user connectors' managed cleanup contract names
// (windowsManagedRuntimeCleanupConnectors: agent_selection.json and its lock,
// lifecycle and token-publish locks, kiro-created-dirs.json). They carry the
// managed DACL (LocalSystem and Administrators full control, a read-only
// OWNER RIGHTS entry), which a per-user install does not accept: its first
// run refused hook_contract_lock.json as "not protected" (cowork-1-0-8
// GAP-0045). foreign-hooks-backup (the account's own hooks the policy moved
// aside), connector_backups records, acp and anything else stay.
var windowsManagedUserRuntimeEntries = func() []string {
	set := map[string]struct{}{
		"hooks":                        {},
		"logs":                         {},
		"hook_contract_lock.json":      {},
		"hook_contract_lock.json.lock": {},
		"inventory.db":                 {},
		"inventory.db-journal":         {},
		"inventory.db-shm":             {},
		"inventory.db-wal":             {},
		"foreign-hook-env.json":        {},
		"foreign-hook-sessions":        {},
	}
	for _, files := range windowsManagedRuntimeCleanupConnectors {
		for _, leaf := range files.root {
			set[leaf] = struct{}{}
		}
	}
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}()

// windowsManagedUserRuntimeMaxDepth bounds the walk below one entry.
const windowsManagedUserRuntimeMaxDepth = 16

// RemoveWindowsManagedUserRuntime removes, for a standalone uninstall without
// purge, what DefenseClaw's managed runtime wrote into one enrolled account's
// %USERPROFILE%\.defenseclaw (windowsManagedUserRuntimeEntries), once the
// uninstall removed that account's agent registrations. A plain uninstall
// kept the whole folder with its managed DACL, and a later per-user install
// of the same account failed its first run (GAP-0045). It runs as
// LocalSystem, whether or not the account is signed in, and never through a
// link: a link or junction at the folder, at an entry or below one is left as
// found. A folder that holds a per-user install (config.yaml, audit.db, .venv
// or installer) is not changed. The folder goes when nothing else stays in
// it; what stays gets the owner-private DACL the per-user CLI keeps
// (relaxWindowsKeptUserState), so a later per-user install can manage it.
// It returns "" when no folder is left, otherwise why it stays.
func RemoveWindowsManagedUserRuntime(rawHome, rawSID, rawDataDir string) (string, error) {
	if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
		return "", err
	}
	home, sid, err := validateWindowsEnterpriseHome(rawHome, rawSID)
	if err != nil {
		return "", err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, rawDataDir)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(home, dataDir)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return "", fmt.Errorf("enterprise hooks: refusing to clean %s, which is not below the profile %s", dataDir, home)
	}
	linked := fmt.Errorf("enterprise hooks: %s is reached through a link or junction; left as found", dataDir)
	if err := inventoryDACLRejectLinkBelow(home, rel); errors.Is(err, errInventoryDACLLink) {
		return "", linked
	} else if err != nil {
		return "", err
	}
	info, err := os.Lstat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return "", fmt.Errorf("enterprise hooks: refusing to clean %s, which is not a plain folder", dataDir)
	}
	if leftover := windowsPerUserInstallLeftover(dataDir); leftover != "" {
		return "kept: it holds " + leftover + ", which a per-user DefenseClaw install leaves; that install's data was not changed", nil
	}
	pin, err := openWindowsUserStatePin(home, rel)
	if errors.Is(err, errInventoryDACLLink) {
		return "", linked
	}
	if err != nil {
		return "", err
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		pin.Close()
		return "", err
	}
	var links []string
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
		var failures []error
		for _, name := range windowsManagedUserRuntimeEntries {
			failures = append(failures, removeWindowsManagedUserRuntimeEntry(root, windows.Handle(pin.Fd()), name, 0, &links))
		}
		// A teardown removes the backup records it restored; their emptied
		// per-connector folders and connector_backups go too. A record that
		// stays keeps its folder.
		removeWindowsManagedUserRuntimeEmptyDirs(root, "connector_backups")
		return errors.Join(failures...)
	}()
	root.Close()
	pin.Close()
	if err := inventoryDACLRejectLinkBelow(home, rel); err != nil {
		return "", errors.Join(removeErr, linked)
	}
	// Remove takes only an empty folder, and a link put in its place only as
	// the link itself.
	if err := os.Remove(dataDir); err == nil || errors.Is(err, os.ErrNotExist) {
		return "", removeErr
	}
	if err := relaxWindowsKeptUserState(home, sid, dataDir); err != nil {
		removeErr = errors.Join(removeErr, err)
	}
	return windowsManagedUserRuntimeKeptReason(dataDir, links), removeErr
}

// removeWindowsManagedUserRuntimeEntry removes rel below root, a file or a
// folder with what is in it, without following a link: a link, junction or
// other reparse point is named in links and left as found, and so is
// anything below windowsManagedUserRuntimeMaxDepth. An entry whose access
// list refuses LocalSystem goes with backup intent
// (removeWindowsUserStateDenied). A missing entry is not an error.
func removeWindowsManagedUserRuntimeEntry(root *os.Root, pin windows.Handle, rel string, depth int, links *[]string) error {
	info, err := root.Lstat(rel)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s: %w", rel, err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		*links = append(*links, rel)
		return nil
	}
	if info.IsDir() {
		if depth >= windowsManagedUserRuntimeMaxDepth {
			*links = append(*links, rel)
			return nil
		}
		names, err := windowsManagedUserRuntimeDirNames(root, rel)
		if errors.Is(err, fs.ErrPermission) {
			return removeWindowsManagedUserRuntimeDenied(pin, rel, err)
		}
		if err != nil {
			return fmt.Errorf("enterprise hooks: list %s: %w", rel, err)
		}
		var failures []error
		for _, name := range names {
			failures = append(failures, removeWindowsManagedUserRuntimeEntry(root, pin, filepath.Join(rel, name), depth+1, links))
		}
		if err := errors.Join(failures...); err != nil {
			return err
		}
		if left, err := windowsManagedUserRuntimeDirNames(root, rel); err == nil && len(left) != 0 {
			// Only links stay below it.
			return nil
		}
	}
	if err := root.Remove(rel); err != nil && !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, fs.ErrPermission) {
			return removeWindowsManagedUserRuntimeDenied(pin, rel, err)
		}
		return fmt.Errorf("enterprise hooks: remove %s: %w", rel, err)
	}
	return nil
}

func removeWindowsManagedUserRuntimeDenied(pin windows.Handle, rel string, cause error) error {
	if err := removeWindowsUserStateDenied(pin, rel); err != nil {
		return errors.Join(fmt.Errorf("enterprise hooks: remove %s: %w", rel, cause), err)
	}
	return nil
}

func windowsManagedUserRuntimeDirNames(root *os.Root, rel string) ([]string, error) {
	dir, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	sort.Strings(names)
	return names, err
}

// removeWindowsManagedUserRuntimeEmptyDirs removes rel's empty plain
// subfolders, then rel when it is empty. Nothing else is removed.
func removeWindowsManagedUserRuntimeEmptyDirs(root *os.Root, rel string) {
	info, err := root.Lstat(rel)
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return
	}
	names, err := windowsManagedUserRuntimeDirNames(root, rel)
	if err != nil {
		return
	}
	for _, name := range names {
		child := filepath.Join(rel, name)
		if info, err := root.Lstat(child); err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
			_ = root.Remove(child)
		}
	}
	_ = root.Remove(rel)
}

// windowsManagedUserRuntimeKeptReason names what stays in dataDir after the
// cleanup (at most 16 names), and the links it left as found.
func windowsManagedUserRuntimeKeptReason(dataDir string, links []string) string {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return "kept: " + err.Error()
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	more := ""
	if len(names) > 16 {
		more = fmt.Sprintf(" and %d more", len(names)-16)
		names = names[:16]
	}
	reason := "kept: it still holds " + strings.Join(names, ", ") + more + ", which DefenseClaw's managed runtime did not write"
	if len(links) != 0 {
		reason += "; links or junctions left as found: " + strings.Join(links, ", ")
	}
	return reason
}
