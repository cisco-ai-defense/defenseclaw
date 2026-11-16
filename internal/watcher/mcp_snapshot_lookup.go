// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// mcpSnapshotForServer uses only a versioned tuple key whose stored identity
// agrees with that key. Older snapshots have no reliable account scope and
// enter the normal admission path once after an upgrade.
func mcpSnapshotForServer(store *audit.Store, server config.MCPServerEntry) (*audit.SnapshotRow, error) {
	path := MCPEventPath(server)
	row, err := store.GetTargetSnapshot(string(InstallMCP), path)
	if err != nil {
		return nil, err
	}
	identity, ok := mcpStoredSnapshotIdentity(path, row)
	if !ok || identity != mcpIdentityForServer(server) {
		return nil, sql.ErrNoRows
	}
	return row, nil
}

func (w *InstallWatcher) mcpSnapshotForEvent(evt InstallEvent) (*audit.SnapshotRow, error) {
	identity, ok := decodeMCPEventPath(evt.Path)
	if !ok || identity.Name != evt.Name ||
		(evt.Connector != "" && !strings.EqualFold(identity.Connector, evt.Connector)) {
		return nil, sql.ErrNoRows
	}
	return mcpSnapshotForServer(w.store, identity.server())
}

// mcpStoredSnapshotIdentity requires the versioned key and an identity bound
// to the snapshot's baseline hash. Neither an old key nor a hash alone can
// establish account scope.
func mcpStoredSnapshotIdentity(path string, row *audit.SnapshotRow) (mcpSnapshotIdentity, bool) {
	if row == nil || row.ContentHash == "" {
		return mcpSnapshotIdentity{}, false
	}
	var hashes map[string]string
	if json.Unmarshal([]byte(row.ConfigHashes), &hashes) != nil {
		return mcpSnapshotIdentity{}, false
	}
	encoded, ok := hashes[mcpSnapshotIdentityKey]
	if !ok {
		return mcpSnapshotIdentity{}, false
	}
	var identity mcpSnapshotIdentity
	if json.Unmarshal([]byte(encoded), &identity) != nil || identity.Name == "" ||
		hashes["mcp.servers."+identity.Name] != row.ContentHash || path != MCPEventPath(identity.server()) {
		return mcpSnapshotIdentity{}, false
	}
	return identity, true
}
