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
	// reportedAt is when a hook last reported each listed server.
	reportedAt map[string]time.Time
	// refused holds, per session and server name, the refused definitions
	// the session reported (heldMCPRefusals).
	refused map[string]*heldMCPRefusals
	// overflow holds, per connector and account, the sessions the session
	// store was full for (holdOverflow).
	overflow map[string]map[string]*overflowHold
	// sessionStarts holds, per connector, account and session, when the
	// session started (noteSession).
	sessionStarts map[string]*mcpSessionStart
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
	return h.noteAt(entry, time.Now())
}

// noteAt is note at the time of the report. A list that has used its share
// first gives up the servers no hook reported within the memory time limit,
// which no config the hooks read lists any more; when every server is a live
// one the new server is not listed, and the caller decides its calls itself
// (unrecordedMCPDecision).
func (h *hookReportedMCPServers) noteAt(entry config.MCPServerEntry, now time.Time) bool {
	key := watcher.MCPEventPath(entry)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.servers == nil {
		h.servers = map[string]config.MCPServerEntry{}
		h.perHome = map[string]int{}
		h.reportedAt = map[string]time.Time{}
	}
	if old, ok := h.servers[key]; ok {
		h.reportedAt[key] = now
		if old.URL == entry.URL && old.Transport == entry.Transport && old.Command == entry.Command &&
			old.LocalRefusal == entry.LocalRefusal && old.ArgsCut == entry.ArgsCut && slices.Equal(old.Args, entry.Args) {
			return false
		}
	} else {
		if h.listFullLocked(entry.Home) {
			h.dropStaleLocked(entry.Home, now)
		}
		if h.listFullLocked(entry.Home) {
			return false
		}
		h.perHome[entry.Home]++
	}
	h.servers[key] = entry
	h.reportedAt[key] = now
	return true
}

func (h *hookReportedMCPServers) listFullLocked(home string) bool {
	return len(h.servers) >= hookReportedMCPLimit || h.perHome[home] >= hookReportedMCPPerHomeLimit
}

// dropStaleLocked drops the listed servers no hook reported within the memory
// time limit: the account's own when its share is used, any when the list is.
func (h *hookReportedMCPServers) dropStaleLocked(home string, now time.Time) {
	own := h.perHome[home] >= hookReportedMCPPerHomeLimit
	for key, entry := range h.servers {
		if (own && entry.Home != home) || now.Sub(h.reportedAt[key]) <= mcpResolvedTTL {
			continue
		}
		delete(h.servers, key)
		delete(h.reportedAt, key)
		h.perHome[entry.Home]--
	}
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
		delete(h.reportedAt, key)
		h.perHome[entry.Home]--
	}
}

// noteHookReportedMCPServer records, on a managed Linux or macOS gateway,
// the server an MCP tool call about to run reaches, as the hook of the
// calling account defined it, so the pending check that follows refuses the
// call until the watcher has admitted the server (GAP-2591): a URL server,
// or a local one the scanner refuses from its definition (GAP-0925).
//
// A definition the list or the session store cannot keep because the account
// used its share is not dropped: the call, and each later call that reports
// the same definition, gets the decision of a failed admission returned here
// (unrecordedMCPDecision), so a full store never turns a refusal into an
// allow. The decision is on that definition only: no other server of the
// account is held for it, and the session that met it keeps it in the
// overflow store (holdOverflow), by its own session and name.
func (a *APIServer) noteHookReportedMCPServer(ctx context.Context, connectorName, hookEvent string, probe mcpRuntimeProbe) (config.AssetPolicyDecision, bool) {
	if a == nil || a.hookMCP == nil || !probe.Matched || probe.Surface != "hook" || !mcpCallAboutToRun(hookEvent) {
		return config.AssetPolicyDecision{}, false
	}
	cfg := a.liveConfig()
	if !watcherUsesHookReportedMCP(cfg) {
		return config.AssetPolicyDecision{}, false
	}
	home, serviceAccount := callerHomeForAssets(ctx)
	if !serviceAccount || home == "" {
		return config.AssetPolicyDecision{}, false
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
		if reported.URL == "" && entry.LocalRefusal == "" {
			// A definition read from the files is the complete one.
			entry.LocalRefusal = mcplocal.Class(entry.Command, entry.Args)
		}
		// A server the scanner refuses from its definition alone, a launcher
		// or a loopback or private address, is the one an administrator allow
		// admits without a scan: the session keeps it (retainRefused).
		if refused = watcher.MCPScanRefused(entry); refused && reported.URL == "" {
			reported.Command = strings.TrimSpace(entry.Command)
			reported.Args = slices.Clone(entry.Args)
			reported.LocalRefusal = entry.LocalRefusal
			reported.ArgsCut = entry.ArgsCut
		}
	}
	now := time.Now()
	// unrecorded is the definition of this call that no store could keep.
	var unrecorded *config.MCPServerEntry
	if refused {
		// A call that names no session cannot be tied to an agent process, and
		// nothing would end the hold (mcpSessionStarted needs the id), so only
		// a named session keeps what it met. The list comes first: a session
		// whose definition the list holds is not given up for a newer one.
		a.hookMCP.noteAt(reported, now)
		kept := probe.SessionID == "" || a.hookMCP.retainRefused(connectorName, home, probe.SessionID, probe.ServerName, reported, now)
		if !kept {
			a.hookMCP.holdOverflow(connectorName, home, probe.SessionID, probe.ServerName, reported, now)
		}
		if !kept || !a.hookMCP.listedAs(reported) {
			unrecorded = &reported
		}
	} else if held, _ := a.hookMCP.heldRefusals(connectorName, home, probe.SessionID, probe.ServerName, now); len(held) > 0 {
		// The running agent keeps the connection to a refused definition after
		// its config is edited, so a refusal the session reported stays
		// listed, and blocks the calls, until the agent starts again
		// (mcpSessionStarted).
		last := held[len(held)-1]
		a.hookMCP.noteAt(last, now)
		if !a.hookMCP.listedAs(last) {
			unrecorded = &last
		}
	} else if haveCurrent {
		if reported.URL == "" {
			a.hookMCP.forget(reported)
		} else {
			a.hookMCP.noteAt(reported, now)
			if !a.hookMCP.listedAs(reported) {
				unrecorded = &reported
			}
		}
	}
	// A session the session store was full for stays refused after its config
	// is edited, with the cause of the definition it met first, not the one of
	// the edit (holdOverflow).
	if kept, ok := a.hookMCP.overflowHeld(connectorName, home, probe.SessionID, probe.ServerName, now); ok {
		unrecorded = &kept
	}
	if unrecorded != nil {
		return a.unrecordedMCPDecision(ctx, cfg, connectorName, hookEvent, probe, *unrecorded)
	}
	return config.AssetPolicyDecision{}, false
}
