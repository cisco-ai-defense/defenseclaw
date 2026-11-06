// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

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
	hash, err := mcpDefinitionHash(server)
	return err == nil && mcpLegacySnapshotMatchesHash(path, row, server, hash)
}

func mcpLegacySnapshotMatchesHash(path string, row *audit.SnapshotRow, server config.MCPServerEntry, hash string) bool {
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
	// A pre-identity key alone cannot distinguish a project from a home
	// containing the same delimiters. Its complete definition hash must
	// also match before it can be reused, migrated or retired.
	return hash != "" && hash == row.ContentHash
}

// mcpLegacySnapshotCanMove requires an unambiguous scope before a legacy
// snapshot or its journal action can be moved or retired. Even an equal
// definition hash cannot recover home and project fields, which were not
// included in that hash.
func mcpLegacySnapshotCanMove(path string, row *audit.SnapshotRow, server config.MCPServerEntry, hash string) bool {
	if !mcpLegacySnapshotMatchesHash(path, row, server, hash) {
		return false
	}
	if _, ok := mcpStoredSnapshotIdentity(path, row); ok {
		return true
	}
	return server.Project == "" && !strings.Contains(server.Home, "@"+server.Connector+"#")
}

// mcpStoredSnapshotIdentity returns only an identity recorded with the
// snapshot and bound to its path and baseline hash. A legacy path never
// supplies scope by itself.
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
		hashes["mcp.servers."+identity.Name] != row.ContentHash {
		return mcpSnapshotIdentity{}, false
	}
	server := identity.server()
	if path != MCPEventPath(server) && path != legacyMCPEventPath(server) {
		return mcpSnapshotIdentity{}, false
	}
	return identity, true
}
