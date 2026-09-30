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
	"os"
	"path/filepath"
	"sort"
)

// foreignHooksBackupDir holds an account's own hooks that the enterprise
// foreign-hook policy moved aside; only the account may put them back.
const foreignHooksBackupDir = "foreign-hooks-backup"

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

// PurgeUserState removes an account's DefenseClaw state in dataDir, for an
// enterprise uninstall --purge. Two things stay: the account's own hooks the
// foreign-hook policy moved aside (foreign-hooks-backup), and DefenseClaw's
// hook scripts, each replaced by the disabled stub that exits 0, because an
// agent that is still running may call the hook path it loaded. Everything
// else goes, including the per-user hook credentials. Run it as the account,
// after every connector's teardown: the backups a teardown restores from are
// part of this state.
func PurgeUserState(dataDir string) error {
	entries, err := os.ReadDir(dataDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dataDir, entry.Name())
		switch {
		case entry.Name() == foreignHooksBackupDir:
			continue
		case entry.Name() == "hooks" && entry.IsDir():
			if err := purgeHookScripts(dataDir); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
		}
	}
	// Gone only when nothing stayed.
	_ = os.Remove(dataDir)
	return errors.Join(errs...)
}

// purgeHookScripts turns every DefenseClaw hook script in <dataDir>/hooks
// into the disabled stub and removes everything else there (credentials,
// hook config, temporary files).
func purgeHookScripts(dataDir string) error {
	dir := filepath.Join(dataDir, "hooks")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.Type().IsRegular() && scriptHasMarker(path) {
			if err := writeDisabledHookTombstone(SetupOpts{DataDir: dataDir}, entry.Name(), "DefenseClaw"); err != nil {
				errs = append(errs, err)
			}
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(dir)
	return errors.Join(errs...)
}
