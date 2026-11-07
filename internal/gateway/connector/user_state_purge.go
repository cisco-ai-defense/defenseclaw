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

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// BackedUpConnectors lists the connectors that still keep DefenseClaw's
// backups of files they changed (<dataDir>/connector_backups/<name>): each
// one's teardown can still put those files back.
func BackedUpConnectors(dataDir string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(dataDir, "connector_backups"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	return names, nil
}

// UserStatePurgeResult records the per-user entries removed and retained.
type UserStatePurgeResult struct {
	Removed bool
	Kept    []string
}

// PurgeUserState removes DefenseClaw-owned entries from an account's data
// directory (normally ~/.defenseclaw) for an enterprise uninstall --purge.
// Run it as the account, after every
// connector's teardown has removed the hook registrations: the backups a
// teardown restores from are part of this state. An agent still running
// with a hook it loaded before the teardown gets a missing script, which
// it treats as a failed, non-blocking hook until it restarts.
//
// The folders below the home that DefenseClaw created for the agents (the
// list in watcher-created-dirs.json: ~/.claude/commands, ~/.copilot/hooks,
// ~/.config/opencode/plugins and the like) go first, those still empty,
// because the list goes with the data directory. The account's unrelated
// files stay, including files inside a managed directory.
func PurgeUserState(dataDir string) error {
	_, err := PurgeUserStateWithResult(dataDir)
	return err
}

// PurgeUserStateWithResult performs the purge and lists retained paths.
func PurgeUserStateWithResult(dataDir string) (UserStatePurgeResult, error) {
	return purgeUserStateWithManagedFiles(dataDir, nil)
}

// purgeUserStateWithManagedFiles also accepts exact hook paths declared by
// a connector whose teardown created a previously missing data directory.
func purgeUserStateWithManagedFiles(dataDir string, managedFiles []string) (UserStatePurgeResult, error) {
	var result UserStatePurgeResult
	info, err := os.Lstat(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if !info.IsDir() || info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return result, fmt.Errorf("per-user state is not a plain directory: %s", dataDir)
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return result, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		_ = root.Close()
		return result, fmt.Errorf("per-user state changed while opening: %s", dataDir)
	}
	if home := strings.TrimSpace(userHomeDir()); home != "" && filepath.IsAbs(home) {
		removeCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), filepath.Clean(home))
	}
	err = purgeManagedUserStateDir(root, "", managedFiles, &result)
	_ = root.Close()
	if current, statErr := os.Lstat(dataDir); statErr == nil && os.SameFile(info, current) {
		if removeErr := os.Remove(dataDir); removeErr == nil {
			result.Removed = true
		} else if !errors.Is(removeErr, os.ErrNotExist) && !errors.Is(removeErr, fs.ErrExist) {
			err = errors.Join(err, removeErr)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		err = errors.Join(err, fmt.Errorf("per-user state changed before removal: %s", dataDir))
	}
	result.Kept = RemainingUserStateEntries(dataDir)
	return result, err
}

// purgeManagedUserStateDir visits only known managed directories pinned by a
// root handle. It removes known regular files and empty directories; links
// and unknown entries stay.
func purgeManagedUserStateDir(root *os.Root, rel string, managedFiles []string, result *UserStatePurgeResult) error {
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		child := filepath.Join(rel, entry.Name())
		info, err := root.Lstat(entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		switch {
		case info.IsDir() && ManagedUserStateDir(child):
			childRoot, err := root.OpenRoot(entry.Name())
			if err != nil {
				errs = append(errs, err)
				continue
			}
			opened, openErr := childRoot.Stat(".")
			if openErr != nil || !os.SameFile(info, opened) {
				_ = childRoot.Close()
				errs = append(errs, fmt.Errorf("per-user state directory changed while opening: %s", child))
				continue
			}
			if err := purgeManagedUserStateDir(childRoot, child, managedFiles, result); err != nil {
				errs = append(errs, err)
			}
			_ = childRoot.Close()
			if current, statErr := root.Lstat(entry.Name()); statErr != nil || !os.SameFile(info, current) {
				errs = append(errs, fmt.Errorf("per-user state directory changed before removal: %s", child))
				continue
			}
			if err := root.Remove(entry.Name()); err == nil {
				result.Removed = true
			} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, fs.ErrExist) {
				// A directory that still holds account files stays. fs.ErrExist is
				// the portable not-empty test: it matches ENOTEMPTY on Linux and
				// macOS and ERROR_DIR_NOT_EMPTY on Windows.
				errs = append(errs, err)
			}
		case info.Mode().IsRegular() && (ManagedUserStateFile(child) || slices.Contains(managedFiles, filepath.ToSlash(child))):
			if err := root.Remove(entry.Name()); err == nil {
				result.Removed = true
			} else if !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// RemainingUserStateEntries lists retained leaves, bounded for an uninstall
// result. WalkDir does not follow links. A directory that cannot be read is
// named as a kept entry.
func RemainingUserStateEntries(dataDir string) []string {
	const limit = 32
	var kept []string
	_ = filepath.WalkDir(dataDir, func(path string, entry fs.DirEntry, err error) error {
		if path == dataDir {
			return err
		}
		rel, relErr := filepath.Rel(dataDir, path)
		if relErr != nil {
			return relErr
		}
		emptyDir := false
		if err == nil && entry.IsDir() {
			children, readErr := os.ReadDir(path)
			emptyDir = readErr != nil || len(children) == 0
		}
		if err != nil || !entry.IsDir() || emptyDir {
			kept = append(kept, userStateEntryLabel(rel))
		}
		if len(kept) >= limit {
			kept = append(kept, "...")
			return fs.SkipAll
		}
		if err != nil {
			return fs.SkipDir
		}
		return nil
	})
	return kept
}

// userStateEntryLabel keeps account-controlled path names printable and
// bounded in both JSON and text uninstall results.
func userStateEntryLabel(rel string) string {
	const maxBytes = 256
	var out strings.Builder
	for _, ch := range filepath.ToSlash(rel) {
		part := string(ch)
		if !unicode.IsPrint(ch) {
			part = fmt.Sprintf("\\u%04x", ch)
		}
		if out.Len()+len(part) > maxBytes {
			out.WriteString("...")
			break
		}
		out.WriteString(part)
	}
	return out.String()
}
