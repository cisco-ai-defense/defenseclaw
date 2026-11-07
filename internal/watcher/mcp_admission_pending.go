// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"path/filepath"
	"runtime"
	"strings"

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

// MCPAdmissionPending reports an MCP server the watcher admits that has no
// admission outcome yet, and queues its admission now (GAP-0112). Claude
// Code starts the servers of a project it opens at once, and the discovery
// poll finds a new project server up to its interval later, so a tool call
// in between reached a server nothing had scanned and was allowed, even one
// a later scan rejected. The hook refuses such a call until admission has
// run: the call fails closed and a retry once the verdict allows it goes
// through. A server whose definition changed since its outcome is pending
// the same way, because that outcome was for another program (GAP-0216). It
// returns the configured name of the server.
//
// A server the first rescan cycle lists at start stays with that cycle,
// which admits or baselines it (an upgrade from 0.8.x only baselines), so
// the calls of a server configured before the start are decided as before.
// Nothing is pending where the watcher does not enforce MCP admission
// (take_action off), where it has no MCP source, before it has listed the
// servers present at start, or on Secure Client (issue #1092).
func (w *InstallWatcher) MCPAdmissionPending(q MCPAdmissionQuery) (string, bool) {
	if w == nil || !w.admitNewMCP || w.store == nil || w.secureClientActive() ||
		!w.takeActionFor(InstallEvent{Type: InstallMCP}) || strings.TrimSpace(q.Server) == "" {
		return "", false
	}
	firstCycle := !w.firstCycleDone.Load()
	if firstCycle && !w.mcpStartupListed.Load() {
		return "", false
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return "", false
	}
	var pending []string
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		path := MCPEventPath(server)
		if firstCycle && w.listedAtStartup(path) {
			continue
		}
		if row, err := w.store.GetTargetSnapshot(string(InstallMCP), path); err == nil && mcpBaselineMatches(row, server) {
			continue
		}
		// No outcome yet, one that could not be read, or one for another
		// definition of the server: refused either way, and admission says
		// why when it runs.
		pending = append(pending, server.Name)
	}
	if len(pending) == 0 {
		return "", false
	}
	w.AdmitAddedMCPServers(pending)
	return pending[0], true
}

// MCPPublication is what the servers a watcher admits hold for a tool call.
type MCPPublication struct {
	// Entry is the published definition whose launch digest matched.
	Entry config.MCPServerEntry
	// Matched says a published server serving the call has that digest.
	Matched bool
	// Named says a published server serves the call at all, whatever its
	// definition: a definition that is not Matched would override it.
	Named bool
}

// MCPPublished looks, among the servers this watcher admits for the caller
// (q), for the definition the caller's agent runs, named by its launch digest
// (config.MCPLaunchDigest). A managed Windows gateway learns an enrolled
// account's Codex servers only from the record the enumerator publishes; a
// definition the agent runs that is not in it was never scanned. The digest
// covers the whole definition (URL, command, every argument, environment), so
// a bounded hook fact cannot make a changed or oversized definition look like
// the scanned one, and the published entry it returns is the complete one to
// judge (GAP-0686).
func (w *InstallWatcher) MCPPublished(q MCPAdmissionQuery, digest string) MCPPublication {
	var out MCPPublication
	if w == nil {
		return out
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return out
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		out.Named = true
		if digest != "" && config.MCPLaunchDigest(server) == digest {
			out.Entry, out.Matched = server, true
			return out
		}
	}
	return out
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
