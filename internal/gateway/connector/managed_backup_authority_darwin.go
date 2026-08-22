// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"fmt"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func ensureManagedBackupAuthorityDirs(connectorDir string) error {
	backupRoot := filepath.Dir(connectorDir)
	if filepath.Base(backupRoot) != "connector_backups" {
		return fmt.Errorf("managed backup directory is outside the connector_backups tree: %s", connectorDir)
	}
	if err := safefile.ProtectDirectory(backupRoot); err != nil {
		return fmt.Errorf("create managed backup root %s: %w", backupRoot, err)
	}
	return ensureManagedBackupDirRestricted(connectorDir)
}

func writeManagedBackupAuthority(path string, data []byte) error {
	return safefile.WritePrivate(path, data)
}
