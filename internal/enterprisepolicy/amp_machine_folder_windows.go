//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Amp reads %ProgramData%\ampcode (managed-settings.json and AGENTS.md) for
// every account on Windows, ahead of each user's own settings. DefenseClaw
// publishes no Amp policy there (Amp's route is per user), but in the
// standalone profile it holds the folder like its other vendor folders:
// administrator-owned and read-only for standard users, so no account can
// place settings or guidance there for every other account.
func windowsAmpMachineDir(opts Options) string {
	return strings.TrimRight(opts.WindowsProgramData, `\`) + `\ampcode`
}

const windowsAmpMachineFolderOwnerFile = ".defenseclaw-folder-owner"
const windowsAmpMachineFolderOwnerContents = "defenseclaw-created-amp-folder-v1\n"

// reserveWindowsAmpMachineDir creates the Amp machine folder when it is
// missing, takes back one an unprivileged user created and moves aside
// what such a user put in it. The guardian runs it on every pass.
func reserveWindowsAmpMachineDir(opts Options) (State, error) {
	dir := windowsAmpMachineDir(opts)
	state := State{Connector: connectorAmp, Route: RoutePerUser, Paths: []string{dir}}
	if opts.WindowsProgramData == "" || opts.SkipTrustChecks {
		return state, nil
	}
	created, err := takeBackPolicyPath(opts, filepath.Join(dir, "managed-settings.json"), &state)
	if err != nil {
		return state, err
	}
	made, err := ensurePolicyDir(opts, dir)
	if err != nil {
		return state, err
	}
	// Record ownership only when this writer created the vendor folder.
	// An empty folder that predates Setup may belong to Amp or an administrator.
	for _, path := range append(created, made...) {
		if path == dir {
			if err := atomicWriteSDDL(filepath.Join(dir, windowsAmpMachineFolderOwnerFile),
				[]byte(windowsAmpMachineFolderOwnerContents), privateFileSDDL); err != nil {
				return state, fmt.Errorf("record ownership of Amp machine folder: %w", err)
			}
			break
		}
	}
	displaceUntrustedEntries(opts, dir, &state)
	state.Changed = len(created) > 0 || len(made) > 0 || len(state.Details) > 0
	return state, nil
}

// RemoveWindowsAmpMachineFolderIfCreated removes the folder this writer made
// only when its protected ownership marker is the sole entry. A vendor or
// administrator folder, or one containing any other entry, stays intact.
func RemoveWindowsAmpMachineFolderIfCreated(opts Options) error {
	if opts.goos() != "windows" || opts.WindowsProgramData == "" {
		return nil
	}
	dir := windowsAmpMachineDir(opts)
	marker := filepath.Join(dir, windowsAmpMachineFolderOwnerFile)
	info, err := os.Lstat(marker)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Amp folder ownership marker: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != int64(len(windowsAmpMachineFolderOwnerContents)) {
		return fmt.Errorf("Amp folder ownership marker is not the Setup marker: %s", marker)
	}
	if err := validateTrustedLeafDir(dir); err != nil {
		return fmt.Errorf("Amp folder is not protected: %w", err)
	}
	if err := validateTrustedPolicyFile(opts, marker); err != nil {
		return fmt.Errorf("Amp folder ownership marker is not protected: %w", err)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != windowsAmpMachineFolderOwnerContents {
		return fmt.Errorf("Amp folder ownership marker is not the Setup marker: %s", marker)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("inspect Amp machine folder: %w", err)
	}
	removeFolder := len(entries) == 1 && entries[0].Name() == windowsAmpMachineFolderOwnerFile
	if err := os.Remove(marker); err != nil {
		return fmt.Errorf("remove Amp folder ownership marker: %w", err)
	}
	if !removeFolder {
		return nil
	}
	if err := os.Remove(dir); err != nil {
		// Preserve the proof for a later purge if another writer added an entry.
		_ = atomicWriteSDDL(marker, []byte(windowsAmpMachineFolderOwnerContents), privateFileSDDL)
		return fmt.Errorf("remove empty Setup-created Amp machine folder: %w", err)
	}
	return nil
}

// InspectWindowsAmpMachineFolder reports, read-only, why the Amp machine
// folder is not held for the administrator: missing (any account could
// create it), changeable by a standard account, or holding an entry one
// could change. It returns nothing when the folder is held.
func InspectWindowsAmpMachineFolder(opts Options) []string {
	if opts.WindowsProgramData == "" {
		return nil
	}
	dir := windowsAmpMachineDir(opts)
	const fix = "repair (or the guardian's next pass) takes it back"
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return []string{fmt.Sprintf("%s is not reserved: any account could create it and put Amp settings or guidance there for every account; %s", dir, fix)}
	} else if err != nil {
		return []string{fmt.Sprintf("inspect %s: %v", dir, err)}
	}
	if err := validateTrustedLeafDir(dir); err != nil {
		return []string{fmt.Sprintf("%s can be changed by a standard account (%v); Amp reads it for every account; %s", dir, err, fix)}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{fmt.Sprintf("inspect %s: %v", dir, err)}
	}
	var problems []string
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			continue
		}
		trusted := validateTrustedPolicyFile(opts, path)
		if plainDirectory(info) {
			trusted = validateTrustedDir(path)
		} else if !info.Mode().IsRegular() {
			trusted = fmt.Errorf("not a regular file")
		}
		if trusted != nil {
			problems = append(problems, fmt.Sprintf("%s is not held by an administrator (%v); Amp reads it for every account; %s", path, trusted, fix))
		}
	}
	return problems
}
