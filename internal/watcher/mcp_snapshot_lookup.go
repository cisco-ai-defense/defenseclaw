// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// mcpSnapshotForServer reads the versioned key first. An older row can be
// reused only when its stored identity names this tuple, or when a named
// pre-identity row has the exact unscoped legacy key for this server.
func mcpSnapshotForServer(store *audit.Store, server config.MCPServerEntry) (*audit.SnapshotRow, error) {
	row, err := store.GetTargetSnapshot(string(InstallMCP), MCPEventPath(server))
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	oldPath := legacyMCPEventPath(server)
	row, err = store.GetTargetSnapshot(string(InstallMCP), oldPath)
	if err != nil {
		return nil, err
	}
	if !mcpLegacySnapshotMatchesServer(oldPath, row, server) {
		return nil, sql.ErrNoRows
	}
	return row, nil
}

func (w *InstallWatcher) mcpSnapshotForEvent(evt InstallEvent) (*audit.SnapshotRow, error) {
	row, err := w.store.GetTargetSnapshot(string(InstallMCP), evt.Path)
	if err == nil || !errors.Is(err, sql.ErrNoRows) {
		return row, err
	}
	server, err := w.lookupMCPServer(evt)
	if err != nil {
		return nil, sql.ErrNoRows
	}
	return mcpSnapshotForServer(w.store, *server)
}

func mcpLegacySnapshotMatchesServer(path string, row *audit.SnapshotRow, server config.MCPServerEntry) bool {
	if row == nil || row.ContentHash == "" || path != legacyMCPEventPath(server) {
		return false
	}
	var hashes map[string]string
	if json.Unmarshal([]byte(row.ConfigHashes), &hashes) != nil ||
		hashes["mcp.servers."+server.Name] != row.ContentHash {
		return false
	}
	if encoded, ok := hashes[mcpSnapshotIdentityKey]; ok {
		var stored mcpSnapshotIdentity
		return json.Unmarshal([]byte(encoded), &stored) == nil && stored == mcpIdentityForServer(server)
	}
	// A pre-identity project key is ambiguous with punctuation in a home.
	// Its scope cannot be established from the key alone.
	return server.Project == ""
}
