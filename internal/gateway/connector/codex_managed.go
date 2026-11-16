// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
)

// migrateCodexManagedHooks removes the matrix an earlier per-user Windows
// release registered in managed_config.toml. It does nothing when neither that
// file nor its setup backup exists, so a fresh install never creates either.
func (c *CodexConnector) migrateCodexManagedHooks(opts SetupOpts) error {
	_, configErr := os.Lstat(codexManagedConfigPath())
	_, backupErr := os.Lstat(managedFileBackupPath(opts.DataDir, c.Name(), codexManagedConfigLogicalName))
	if os.IsNotExist(configErr) && os.IsNotExist(backupErr) {
		return nil
	}
	return c.restoreCodexManagedHooks(opts)
}

func (c *CodexConnector) restoreCodexManagedHooks(opts SetupOpts) error {
	path := codexManagedConfigPath()
	if err := ensureCodexConfigDir(filepath.Dir(path)); err != nil {
		return fmt.Errorf("prepare Codex managed config directory for restore: %w", err)
	}
	backup, err := loadManagedFileBackupForTransform(
		opts.DataDir,
		c.Name(),
		codexManagedConfigLogicalName,
		path,
	)
	if err != nil {
		return fmt.Errorf("load Codex managed hook backup: %w", err)
	}

	if err := withFileLock(path, func() error {
		return atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, func(raw []byte, exists bool) (atomicTransformResult, error) {
			if exact, ok := managedFileBackupTransform(backup, raw, exists); ok {
				if exact.Remove {
					return exact, nil
				}
				cleaned, changed, err := removeOwnedCodexHooksFromTOML(
					exact.Data,
					path,
					filepath.Join(opts.DataDir, "hooks"),
				)
				if err != nil {
					return atomicTransformResult{}, fmt.Errorf("clean exact-restored Codex managed hooks: %w", err)
				}
				if changed {
					exact.Data = cleaned
					exact.Remove = len(cleaned) == 0
				}
				return exact, nil
			}
			if !exists {
				return atomicTransformResult{Remove: true}, nil
			}
			cleaned, changed, err := removeOwnedCodexHooksFromTOML(raw, path, filepath.Join(opts.DataDir, "hooks"))
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("restore Codex managed hooks: %w", err)
			}
			if !changed {
				return atomicTransformResult{Data: append([]byte(nil), raw...)}, nil
			}
			if len(cleaned) == 0 {
				return atomicTransformResult{Remove: true}, nil
			}
			return atomicTransformResult{Data: cleaned}, nil
		})
	}); err != nil {
		return fmt.Errorf("write restored Codex managed config: %w", err)
	}
	discardManagedFileBackup(opts.DataDir, c.Name(), codexManagedConfigLogicalName)
	return nil
}
