// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
)

func transformClaudeCodeRollback(path string, opts SetupOpts, transform func([]byte, bool) (atomicTransformResult, error)) error {
	return atomicTransformFileWithStateDir(path, opts.DataDir, 0o600, transform)
}

func writeClaudeCodeRollbackBackup(dataDir string, data []byte) error {
	dir := filepath.Join(dataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, claudeCodeRollbackBackupName), data, 0o600)
}
