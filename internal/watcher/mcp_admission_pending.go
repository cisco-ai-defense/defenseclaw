// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
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
	path   string
	hash   string
}

const mcpSnapshotIdentityKey = "mcp.snapshot.identity.v1"

// mcpSnapshotIdentity keeps the fields needed to match a call when the source
// list is unavailable. MCPEventPath is not an unambiguous encoding of them.
type mcpSnapshotIdentity struct {
	Name      string `json:"name"`
	Connector string `json:"connector"`
	Home      string `json:"home"`
	Project   string `json:"project"`
}

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
		row, err := w.store.GetTargetSnapshot(string(InstallMCP), path)
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
		row, err := w.store.GetTargetSnapshot(string(InstallMCP), definition.path)
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

// A stored MCP baseline includes the configured name in its config hashes.
// Use it as the name boundary: MCPEventPath does not escape punctuation in a
// name, home or project, so splitting the path alone can select another server.
func mcpFailedSnapshotServesQuery(path string, row *audit.SnapshotRow, q MCPAdmissionQuery) bool {
	var hashes map[string]string
	if row != nil && json.Unmarshal([]byte(row.ConfigHashes), &hashes) == nil {
		if encoded, ok := hashes[mcpSnapshotIdentityKey]; ok {
			var identity mcpSnapshotIdentity
			if json.Unmarshal([]byte(encoded), &identity) != nil || identity.Name == "" ||
				row.ContentHash == "" || hashes["mcp.servers."+identity.Name] != row.ContentHash {
				return false
			}
			server := identity.server()
			return path == MCPEventPath(server) && mcpServerServesQuery(server, q)
		}
		name := ""
		hasStoredName := false
		for key, hash := range hashes {
			if !strings.HasPrefix(key, "mcp.servers.") {
				continue
			}
			hasStoredName = true
			if hash == row.ContentHash && hash != "" {
				if name != "" {
					return false
				}
				name = strings.TrimPrefix(key, "mcp.servers.")
			}
		}
		if name != "" {
			return mcpSnapshotNamedPathServesQuery(path, name, q)
		}
		if hasStoredName {
			return false
		}
	}
	return mcpSnapshotPathServesQuery(path, q)
}

// mcpSnapshotPathServesQuery handles older rows with no stored name. Scope
// parsing here is conservative when punctuation could also belong to a name.
func mcpSnapshotPathServesQuery(path string, q MCPAdmissionQuery) bool {
	if path == q.Server || (!strings.Contains(path, "@") && config.SameMCPToolServer(q.Connector, path, q.Server)) {
		return true
	}
	if q.Connector == "" {
		return false
	}
	marker := "@" + q.Connector
	for start := 0; start < len(path); {
		index := strings.IndexByte(path[start:], '@')
		if index < 0 {
			break
		}
		index += start
		start = index + 1
		if len(path)-index < len(marker) || !strings.EqualFold(path[index:index+len(marker)], marker) {
			continue
		}
		rest := path[index+len(marker):]
		if strings.HasPrefix(rest, "#") {
			// Without a stored identity the same bytes can also be a
			// server name. Require the caller's project to prove scope.
			if q.CWD == "" || !filepath.IsAbs(rest[1:]) || !mcpFolderWithin(q.CWD, rest[1:]) {
				continue
			}
		}
		if mcpSnapshotNamedPathServesQuery(path, path[:index], q) {
			return true
		}
	}
	return false
}

func mcpSnapshotNamedPathServesQuery(path, name string, q MCPAdmissionQuery) bool {
	if !config.SameMCPToolServer(q.Connector, name, q.Server) {
		return false
	}
	rest, ok := strings.CutPrefix(path, name)
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	marker := "@" + q.Connector
	if q.Connector == "" || len(rest) < len(marker) || !strings.EqualFold(rest[:len(marker)], marker) {
		return false
	}
	rest = rest[len(marker):]
	switch {
	case rest == "":
		return true
	case strings.HasPrefix(rest, "#"):
		return q.CWD == "" || mcpFolderWithin(q.CWD, rest[1:])
	case strings.HasPrefix(rest, ":"):
		return mcpSnapshotHomeServesQuery(rest[1:], marker, q)
	default:
		return false
	}
}

func mcpSnapshotHomeServesQuery(scope, marker string, q MCPAdmissionQuery) bool {
	projectMarker := marker + "#"
	if q.Home == "" {
		// A verified caller with no resolvable home cannot be compared
		// against an account. A known CWD still excludes another project.
		if q.CWD != "" {
			absoluteProject := false
			for start := 0; start < len(scope); {
				index := strings.IndexByte(scope[start:], '@')
				if index < 0 {
					break
				}
				index += start
				start = index + 1
				if len(scope)-index < len(projectMarker) || !strings.EqualFold(scope[index:index+len(projectMarker)], projectMarker) {
					continue
				}
				project := scope[index+len(projectMarker):]
				if filepath.IsAbs(project) {
					absoluteProject = true
					if mcpFolderWithin(q.CWD, project) {
						return true
					}
				}
			}
			if absoluteProject {
				return false
			}
		}
		return true
	}
	if !strings.Contains(strings.ToLower(scope), strings.ToLower(projectMarker)) && sameMCPFolder(scope, q.Home) {
		return true
	}
	for start := 0; start < len(scope); {
		index := strings.IndexByte(scope[start:], '@')
		if index < 0 {
			break
		}
		index += start
		start = index + 1
		if len(scope)-index < len(projectMarker) || !strings.EqualFold(scope[index:index+len(projectMarker)], projectMarker) {
			continue
		}
		if !sameMCPFolder(scope[:index], q.Home) {
			continue
		}
		project := scope[index+len(projectMarker):]
		if q.CWD == "" || mcpFolderWithin(q.CWD, project) {
			return true
		}
	}
	return false
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
