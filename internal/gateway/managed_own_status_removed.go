// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"io"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownRemovedConnectorStates reads the guardian's removed-connectors record
// (managed.HookGuardianRemovedConnectorsFile) and returns, for the caller's
// own SID, a row for each connector the administrator took off the roster
// that the account had been enrolled for. Each row is neither protected nor
// pending: "not managed (removed from roster)". A missing, untrusted or
// unreadable record says nothing, and a connector the loaded config publishes
// again keeps the row of its own state.
func ownRemovedConnectorStates(cfg *config.Config, dataDir, sid string) map[string]any {
	path := managed.RemovedConnectorsPath(dataDir)
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	if err := validateManagedGuardianAuthorization(path, "removed connectors record"); err != nil {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, managed.RemovedConnectorsMaxBytes+1))
	if err != nil {
		return nil
	}
	entries, err := managed.ParseRemovedConnectors(data)
	if err != nil {
		return nil
	}
	rows := map[string]any{}
	for _, name := range managed.RemovedConnectorsForSID(entries, sid, func(name string) bool {
		return cfg != nil && enterprisepolicy.StandaloneConnectorPublished(cfg, name)
	}) {
		rows[name] = map[string]any{"protected": false, "state": managed.NotManagedRemovedFromRoster}
	}
	if len(rows) == 0 || strings.TrimSpace(sid) == "" {
		return nil
	}
	return rows
}
