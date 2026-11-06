// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/mcpkey"
)

// MCPAdmissionQuery names the MCP server a tool call reaches.
type MCPAdmissionQuery struct {
	// Connector is the hook's connector, Server the server name as the
	// tool call spells it (mcp__<server>__<tool>).
	Connector, Server string
	// Home is the caller's home on a gateway that serves several
	// accounts, "" on a per-user gateway. CWD is the agent's working
	// folder, "" when the hook did not send one.
	Home, CWD string
}

// MCPAdmissionStatus is the current admission state of one configured server.
// An empty state means no pending or failed admission applies to this call.
type MCPAdmissionStatus struct {
	Name        string
	Pending     bool
	Failed      bool
	Unavailable bool
	RetryAfter  time.Duration
}

type mcpKnownDefinition struct {
	server config.MCPServerEntry
	hash   string
}

const mcpSnapshotIdentityKey = "mcp.snapshot.identity.v1"

// mcpSnapshotIdentity keeps the fields needed to match a call when the source
// list is unavailable and validates versioned snapshot paths.
type mcpSnapshotIdentity mcpkey.Identity

func mcpIdentityForServer(server config.MCPServerEntry) mcpSnapshotIdentity {
	return mcpSnapshotIdentity{server.Name, server.Connector, server.Home, server.Project}
}

func (identity mcpSnapshotIdentity) server() config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: identity.Name, Connector: identity.Connector, Home: identity.Home, Project: identity.Project,
	}
}

// MCPAdmissionPending reports an MCP server with no admission outcome yet
// and queues admission now (GAP-0112). A server whose definition changed
// since its outcome is pending the same way (GAP-0216). The hook applies the
// selected tier to a pending result. The returned name is the configured one.
//
// A server the first rescan cycle lists at start stays with that cycle,
// which admits or baselines it (an upgrade from 0.8.x only baselines), so
// the calls of a server configured before the start are decided as before.
// Nothing is pending where the watcher does not enforce MCP admission
// (take_action off), where it has no MCP source, before it has listed the
// servers present at start, or on Secure Client (issue #1092).
func (w *InstallWatcher) MCPAdmissionPending(q MCPAdmissionQuery) (string, bool) {
	status := w.MCPAdmissionStatus(q)
	return status.Name, status.Pending
}

// MCPAdmissionStatus distinguishes a scan still in progress from a completed
// scan failure for the server's current definition. A failed scan stays
// visible even when the admission policy kept the server installed.
func (w *InstallWatcher) MCPAdmissionStatus(q MCPAdmissionQuery) MCPAdmissionStatus {
	if w == nil || !w.admitNewMCP || w.store == nil || w.secureClientActive() ||
		strings.TrimSpace(q.Server) == "" {
		return MCPAdmissionStatus{}
	}
	firstCycle := !w.firstCycleDone.Load()
	servers, err := w.readMCPServers()
	if err != nil {
		if failed := w.mcpFailedFromLastRead(q); failed.Failed {
			return failed
		}
		return MCPAdmissionStatus{Name: q.Server, Unavailable: true, RetryAfter: defaultScanTimeout}
	}
	var pending []string
	var pendingPath string
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		path := MCPEventPath(server)
		row, err := mcpSnapshotForServer(w.store, server)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return MCPAdmissionStatus{Name: server.Name, Unavailable: true, RetryAfter: defaultScanTimeout}
		}
		matched := err == nil && mcpBaselineMatches(row, server)
		if matched && mcpSnapshotFailed(row) {
			return MCPAdmissionStatus{Name: server.Name, Failed: true}
		}
		if matched {
			continue
		}
		if firstCycle && (!w.mcpStartupListed.Load() || w.listedAtStartup(path)) {
			continue
		}
		if !w.takeActionFor(InstallEvent{Type: InstallMCP}) {
			continue
		}
		// No outcome yet, or one for another definition of the server:
		// admission says why when it runs.
		pending = append(pending, server.Name)
		if pendingPath == "" {
			pendingPath = path
		}
	}
	if len(pending) == 0 {
		return MCPAdmissionStatus{}
	}
	w.AdmitAddedMCPServers(pending)
	return MCPAdmissionStatus{Name: pending[0], Pending: true, RetryAfter: w.mcpRetryAfter(pendingPath)}
}

// mcpFailedFromLastRead uses a prior successful listing only to keep a
// completed failed scan effective during a source-list outage. The cache
// holds identity and definition hash, not an old allow or pending verdict.
func (w *InstallWatcher) mcpFailedFromLastRead(q MCPAdmissionQuery) MCPAdmissionStatus {
	w.mcpAdmissionMu.RLock()
	known := append([]mcpKnownDefinition(nil), w.mcpAdmissionKnown...)
	listed := w.mcpAdmissionListed
	w.mcpAdmissionMu.RUnlock()
	for _, definition := range known {
		if definition.server.Bundled || !mcpServerServesQuery(definition.server, q) {
			continue
		}
		row, err := mcpSnapshotForServer(w.store, definition.server)
		if err == nil && row != nil && row.ContentHash == definition.hash && mcpSnapshotFailed(row) {
			return MCPAdmissionStatus{Name: definition.server.Name, Failed: true}
		}
	}
	// After a restart the watcher can have durable failed snapshots but no
	// successful source listing yet. Match their scoped paths until a fresh
	// listing establishes the definition identities above.
	if !listed {
		paths, err := w.store.ListTargetSnapshotPaths(string(InstallMCP))
		if err == nil {
			for _, path := range paths {
				row, err := w.store.GetTargetSnapshot(string(InstallMCP), path)
				if err == nil && mcpSnapshotFailed(row) && mcpFailedSnapshotServesQuery(path, row, q) {
					return MCPAdmissionStatus{Name: q.Server, Failed: true}
				}
			}
		}
	}
	return MCPAdmissionStatus{}
}

// A failed baseline is usable only when its stored identity matches its
// versioned key. Older rows cannot establish an account scope.
func mcpFailedSnapshotServesQuery(path string, row *audit.SnapshotRow, q MCPAdmissionQuery) bool {
	identity, ok := mcpStoredSnapshotIdentity(path, row)
	return ok && mcpServerServesQuery(identity.server(), q)
}

func mcpSnapshotFailed(row *audit.SnapshotRow) bool {
	if row == nil {
		return false
	}
	fingerprint := row.ScannerFingerprint
	return strings.HasSuffix(fingerprint, mcpScanFailedMark) ||
		strings.HasSuffix(fingerprint, mcpLauncherRefusedMark) ||
		strings.HasSuffix(fingerprint, unverifiedMCPMark)
}

// mcpBaselineMatches reports whether the baseline admission recorded for an
// MCP server is for its current definition. A verdict is for a definition,
// not a name: a server whose command, arguments, folder or environment
// changed under the same name keeps nothing of the old verdict until
// admission has run on the new one (GAP-0216).
func mcpBaselineMatches(row *audit.SnapshotRow, server config.MCPServerEntry) bool {
	hash, err := mcpDefinitionHash(server)
	return err == nil && row != nil && row.ContentHash != "" && row.ContentHash == hash
}

// mcpServerServesQuery reports whether a watched server can be the one the
// tool call reaches: same connector and name, the caller's own server on a
// gateway of several accounts, and a project server only for an agent
// working in that project.
func mcpServerServesQuery(server config.MCPServerEntry, q MCPAdmissionQuery) bool {
	if c := strings.TrimSpace(server.Connector); c != "" && !strings.EqualFold(c, strings.TrimSpace(q.Connector)) {
		return false
	}
	if !config.SameMCPToolServer(q.Connector, server.Name, q.Server) {
		return false
	}
	if q.Home != "" && server.Home != "" && !sameMCPFolder(server.Home, q.Home) {
		return false
	}
	if q.CWD != "" && server.Project != "" && !mcpFolderWithin(q.CWD, server.Project) {
		return false
	}
	return true
}

func mcpFolderKey(dir string) string {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if runtime.GOOS == "windows" {
		return strings.ToLower(dir)
	}
	return dir
}

func sameMCPFolder(a, b string) bool { return mcpFolderKey(a) == mcpFolderKey(b) }

// mcpFolderWithin reports whether dir is root or a folder inside it.
func mcpFolderWithin(dir, root string) bool {
	rel, err := filepath.Rel(mcpFolderKey(root), mcpFolderKey(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
