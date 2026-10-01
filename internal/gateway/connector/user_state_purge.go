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

// PurgeUserState removes an account's whole DefenseClaw data directory
// (dataDir, normally ~/.defenseclaw), for an enterprise uninstall --purge:
// everything goes, including DefenseClaw's hook scripts, the per-user hook
// credentials, and the account's own hooks the foreign-hook policy moved
// aside (foreign-hooks-backup). Run it as the account, after every
// connector's teardown has removed the hook registrations: the backups a
// teardown restores from are part of this state. An agent still running
// with a hook it loaded before the teardown gets a missing script, which
// it treats as a failed, non-blocking hook until it restarts.
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
		if err := os.RemoveAll(filepath.Join(dataDir, entry.Name())); err != nil {
			errs = append(errs, err)
		}
	}
	if err := os.Remove(dataDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
