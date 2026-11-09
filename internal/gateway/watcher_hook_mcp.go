// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/mcplocal"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// watcherUsesHookReportedMCP reports a standalone managed Linux or macOS
// gateway. Its service account may not read the home folders (the support
// matrix: /home and /root, /Users and /var/root), so it never saw a server
// an enrolled user added with claude mcp add: the watcher had no MCP source
// and the hooks allowed the server calls unscanned (GAP-2591). The hook runs
// as the user and sends, with each MCP tool call, the definition it read in
// the user files (assetfacts); the watcher admits the URL servers it learns
// that way, and the local (stdio) servers the scanner refuses from the
// definition alone (a python3 or node server, a command path, npx or uvx with
// an execution flag or without a package), so the refusal is recorded and the
// fail-closed tier blocks them like a refused URL server (GAP-0925). A local
// server the scanner would start (npx or uvx with a package) would start
// under the gateway service account, and nothing on these platforms starts it
// as its user, so it keeps the asset_policy lists the hooks apply.
func watcherUsesHookReportedMCP(cfg *config.Config) bool {
	return runtime.GOOS != "windows" && cfg != nil && cfg.StandaloneEnterprise() && !cfg.SecureClientIntegration()
}

// WatcherAdmitsOnlyHookReportedMCP reports whether the install watcher of a
// managed Linux or macOS gateway runs only for the MCP servers the hooks
// report: no skill or plugin folder is configured for the service to watch.
func WatcherAdmitsOnlyHookReportedMCP(cfg *config.Config) bool {
	if cfg == nil || !cfg.Gateway.Watcher.Enabled || !watcherUsesHookReportedMCP(cfg) {
		return false
	}
	w := cfg.Gateway.Watcher
	configuredDirs := (w.Skill.Enabled && len(w.Skill.Dirs) > 0) || (w.Plugin.Enabled && len(w.Plugin.Dirs) > 0)
	return !configuredDirs && !watcherUsesConnectorDirs(cfg) && !watcherUsesEnrolledUserDirs(cfg)
}

// hookReportedMCPLimit bounds the servers a gateway keeps from hook reports.
const hookReportedMCPLimit = 4096

// hookReportedMCPPerHomeLimit bounds the share of one account. The hook facts
// are the claim of the caller, so without it one user reporting many made-up
// servers filled the list and the new servers of every other user were left
// unscanned.
const hookReportedMCPPerHomeLimit = 256

// hookReportedMCPServers are the MCP servers the managed hooks reported, one
// per connector, account home and name, with the definition last reported.
type hookReportedMCPServers struct {
	mu      sync.Mutex
	servers map[string]config.MCPServerEntry
	perHome map[string]int
	// refused holds, per session and server name, the refused definitions
	// the session reported (heldMCPRefusals).
	refused map[string]*heldMCPRefusals
}

func (h *hookReportedMCPServers) list() ([]config.MCPServerEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]config.MCPServerEntry, 0, len(h.servers))
	for _, entry := range h.servers {
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return watcher.MCPEventPath(out[i]) < watcher.MCPEventPath(out[j]) })
	return out, nil
}

// note records entry and reports whether it is new or its definition changed.
func (h *hookReportedMCPServers) note(entry config.MCPServerEntry) bool {
	key := watcher.MCPEventPath(entry)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.servers == nil {
		h.servers = map[string]config.MCPServerEntry{}
		h.perHome = map[string]int{}
	}
	if old, ok := h.servers[key]; ok {
		if old.URL == entry.URL && old.Transport == entry.Transport && old.Command == entry.Command &&
			old.LocalRefusal == entry.LocalRefusal && old.ArgsCut == entry.ArgsCut && slices.Equal(old.Args, entry.Args) {
			return false
		}
	} else if len(h.servers) >= hookReportedMCPLimit || h.perHome[entry.Home] >= hookReportedMCPPerHomeLimit {
		return false
	} else {
		h.perHome[entry.Home]++
	}
	h.servers[key] = entry
	return true
}

// forget drops the server a hook reported earlier, whose definition no longer
// is one the scanner refuses and that no running session holds refused: it
// keeps the lists the hooks apply, and the refusal recorded for the old
// definition must not block the new one.
func (h *hookReportedMCPServers) forget(entry config.MCPServerEntry) {
	key := watcher.MCPEventPath(entry)
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.servers[key]; ok {
		delete(h.servers, key)
		h.perHome[entry.Home]--
	}
}

// noteHookReportedMCPServer records, on a managed Linux or macOS gateway,
// the server an MCP tool call about to run reaches, as the hook of the
// calling account defined it, so the pending check that follows refuses the
// call until the watcher has admitted the server (GAP-2591): a URL server,
// or a local one the scanner refuses from its definition (GAP-0925).
func (a *APIServer) noteHookReportedMCPServer(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) {
	if a == nil || a.hookMCP == nil || !probe.Matched || probe.Surface != "hook" || !mcpCallAboutToRun(hookEvent) {
		return
	}
	cfg := a.liveConfig()
	if !watcherUsesHookReportedMCP(cfg) {
		return
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if !serviceAccount || home == "" {
		return
	}
	entry, ok := a.lookupCallerMCPServer(ctx, cfg, connectorName, probe.WorkspaceDir, probe.ServerName)
	haveCurrent := ok && strings.TrimSpace(entry.Name) != ""
	var reported config.MCPServerEntry
	refused := false
	if haveCurrent {
		reported = config.MCPServerEntry{
			Name: strings.TrimSpace(entry.Name), URL: strings.TrimSpace(entry.URL), Transport: entry.Transport,
			Connector: connectorName, Home: home,
		}
		if reported.URL == "" {
			if entry.LocalRefusal == "" {
				// A definition read from the files is the complete one.
				entry.LocalRefusal = mcplocal.Class(entry.Command, entry.Args)
			}
			if refused = watcher.MCPLocalRefused(entry); refused {
				reported.Command = strings.TrimSpace(entry.Command)
				reported.Args = slices.Clone(entry.Args)
				reported.LocalRefusal = entry.LocalRefusal
				reported.ArgsCut = entry.ArgsCut
			}
		}
	}
	now := time.Now()
	if refused {
		// A call that names no session cannot be tied to an agent process, and
		// nothing would end the hold (mcpSessionStarted needs the id), so only
		// a named session keeps what it met.
		if probe.SessionID != "" {
			a.hookMCP.retainRefused(connectorName, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, reported, now)
		}
		a.hookMCP.note(reported)
		return
	}
	// The running agent keeps the connection to a refused definition after its
	// config is edited, so a refusal the session reported stays listed, and
	// blocks the calls, until the agent starts again (mcpSessionStarted).
	if held, _ := a.hookMCP.heldRefusals(connectorName, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, now); len(held) > 0 {
		a.hookMCP.note(held[len(held)-1])
		return
	}
	switch {
	case !haveCurrent:
	case reported.URL != "":
		a.hookMCP.note(reported)
	default:
		a.hookMCP.forget(reported)
	}
}
