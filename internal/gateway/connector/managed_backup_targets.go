// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ManagedFileBackupTargetsForConnector returns only the targets recorded by
// one connector. The worker calls this as the account whose receipts it reads.
func ManagedFileBackupTargetsForConnector(dataDir, connectorName string) ([]string, error) {
	if connectorName == "" || connectorName != filepath.Base(connectorName) {
		return nil, fmt.Errorf("invalid connector name %q", connectorName)
	}
	root := filepath.Join(dataDir, "connector_backups", connectorName)
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
			continue
		}
		recordPath := filepath.Join(root, entry.Name())
		backup, err := loadManagedFileBackupPath(recordPath)
		if err != nil {
			return nil, fmt.Errorf("load managed backup %s: %w", recordPath, err)
		}
		if backup.Connector != connectorName ||
			!sameManagedTargetPath(managedFileBackupPath(dataDir, backup.Connector, backup.LogicalName), recordPath) {
			return nil, fmt.Errorf("managed backup %s does not match its location", recordPath)
		}
		paths = append(paths, backup.Path)
	}
	return paths, nil
}

// CleanupConfigPathsForConnector names the agent config or managed plugin
// path the connector resolves in the worker's current home. Receipts can name
// an earlier home, so both sets of paths are included in a removal report.
func CleanupConfigPathsForConnector(conn Connector, opts SetupOpts) []string {
	if conn == nil {
		return nil
	}
	paths := append([]string(nil), ResolvedConnectorLocations(opts, conn).HookConfigPaths...)
	switch c := conn.(type) {
	case *hookOnlyConnector:
		paths = append(paths, c.configPath(opts))
	case *AMPConnector:
		paths = append(paths, c.configPath(opts))
	}
	return uniqueNonEmptyStrings(paths)
}
