// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// The agent keeps the connection to an MCP server for as long as its process
// lives, whatever its config says later. A definition whose admission failed
// (the scan could not complete, or the scanner refuses it) is therefore held
// for the session that met it, whichever tier decided the call: the tier is
// applied to the failed admission at each call, never recorded with it. A
// default-tier call that was allowed with a warning and a strict-tier call
// that was blocked meet the same hold, and once the entry is removed or edited
// the next call is judged on that definition again, on the tier in force then
// (GAP-0984). A managed Linux or macOS gateway holds the refused definitions
// its hooks report (noteHookReportedMCPServer); every other deployment holds
// them here, in the same session store.

// failedMCPSessionHold records, when the listed definition of the server of
// probe has a failed admission, that the session met it, and answers a call
// whose listed definition is not that one: the held definition is returned
// as a failed status for as long as the session lives and the config does not
// list it again with an admission that no longer fails. Secure Client and the
// managed hook-reported gateway never get here with a status to change.
func (a *APIServer) failedMCPSessionHold(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe,
	status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
	if a == nil || a.hookMCP == nil || strings.TrimSpace(probe.SessionID) == "" || watcherUsesHookReportedMCP(cfg) ||
		ctx.Value(unrecordedMCPKey{}) != nil || (status.Failed && status.Revoked) {
		return status
	}
	home, _ := callerHomeForAssets(ctx)
	now := time.Now()
	if status.Failed {
		if listed, ok := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName); ok {
			a.holdFailedMCP(connector, home, probe, heldMCPDefinition(listed, connector, home), now)
		}
		return status
	}
	defs, _ := a.hookMCP.heldRefusals(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, now)
	if over, ok := a.hookMCP.overflowHeld(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, now); ok {
		defs = append(defs, over)
	}
	if len(defs) == 0 {
		return status
	}
	listed, isListed := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName)
	var gone *config.MCPServerEntry
	for i := len(defs) - 1; i >= 0; i-- {
		if isListed && sameMCPDefinition(defs[i], listed) {
			// This very definition is listed and its admission no longer
			// fails: the allow or the clean scan that answered it ends its hold.
			a.hookMCP.releaseFailed(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, defs[i])
			continue
		}
		if gone == nil {
			gone = &defs[i]
		}
	}
	if gone == nil {
		return status
	}
	return watcher.FailedMCPStatus(*gone)
}

// heldMCPDefinition is the part of a listed definition the hold keeps: how the
// server is reached or started, never its environment or headers.
func heldMCPDefinition(entry config.MCPServerEntry, connector, home string) config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: strings.TrimSpace(entry.Name), URL: strings.TrimSpace(entry.URL), Transport: entry.Transport,
		Command: strings.TrimSpace(entry.Command), Args: slices.Clone(entry.Args), ArgsCut: entry.ArgsCut,
		LocalRefusal: entry.LocalRefusal, Connector: connector, Home: home,
	}
}

// holdFailedMCP keeps entry for the session; a session the full store cannot
// track is kept in the overflow store, by its own session and name.
func (a *APIServer) holdFailedMCP(connector, home string, probe mcpRuntimeProbe, entry config.MCPServerEntry, now time.Time) {
	if !a.hookMCP.retainRefused(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, entry, now) {
		a.hookMCP.holdOverflow(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, entry, now)
	}
}

// releaseFailed drops entry from what the session holds: its admission no
// longer fails, so the connection to it is no longer a failed one.
func (h *hookReportedMCPServers) releaseFailed(connector, home, session, cwd, name string, entry config.MCPServerEntry) {
	key := mcpResolvedKey(connector, home, session, cwd, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.refused[key]; ok {
		set.defs = slices.DeleteFunc(set.defs, func(held config.MCPServerEntry) bool { return sameMCPDefinition(held, entry) })
		if len(set.defs) == 0 && !set.overflow {
			delete(h.refused, key)
		}
	}
	holds := h.overflow[unrecordedKey(connector, home)]
	if hold, ok := holds[key]; ok && sameMCPDefinition(hold.entry, entry) {
		delete(holds, key)
	}
}
