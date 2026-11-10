// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
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
//
// A hold belongs to the agent session and the server name, not to the working
// directory of the call that met it: the agent holds one connection per name
// for as long as it lives, whatever directory a later hook reports or leaves
// out, so the hook of the session finds it from anywhere. The definition kept
// is the complete one, by a digest of it, with the config scope that listed it
// (heldScope): an edit of a header or of the environment is a different
// definition, and the failure of the old one is released only by a clean
// admission of the same definition in the same scope.
//
// A session that met more failed definitions of a name than it can keep is
// marked (overflow). The marker lasts as long as the session: no clean
// admission of a remembered definition releases it, and a call to a name the
// config no longer lists is a failed admission, which the strict tier blocks
// and the default tier warns on, because the definitions it forgot may still
// be the connection the agent holds.

// failedMCPSessionHold records, when the listed definition of the server of
// probe has a failed admission, that the session met it, and answers a call
// whose listed definition is not that one: the held definition is returned
// as a failed status for as long as the session lives and the config does not
// list it again with an admission that no longer fails. A listed definition
// whose admission is still pending, or cannot be read, has not been admitted:
// it does not release the hold. Secure Client never gets here with a status to
// change; a managed Linux or macOS gateway keeps its own holds
// (hookReportedSessionHold).
func (a *APIServer) failedMCPSessionHold(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe,
	status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
	if a == nil || a.hookMCP == nil || strings.TrimSpace(probe.SessionID) == "" || ctx.Value(unrecordedMCPKey{}) != nil {
		return status
	}
	if watcherUsesHookReportedMCP(cfg) {
		return a.hookReportedSessionHold(ctx, cfg, connector, probe, status)
	}
	if status.Failed && status.Revoked {
		return status
	}
	home, _ := callerHomeForAssets(ctx)
	now := time.Now()
	if status.Failed {
		if listed, isListed := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName); isListed {
			a.holdFailedMCP(connector, home, probe, heldMCPDefinition(listed, connector, home), now)
		}
		return status
	}
	// The ordinary call, with nothing held, reads no config: the agent state
	// file can be large and this runs at every MCP call.
	held, overflow := a.hookMCP.heldFailures(connector, home, probe.SessionID, probe.ServerName, now)
	if len(held) == 0 && !overflow {
		return status
	}
	listed, isListed := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName)
	var listedHeld config.MCPServerEntry
	if isListed {
		listedHeld = heldMCPDefinition(listed, connector, home)
	}
	var gone *config.MCPServerEntry
	for i := len(held) - 1; i >= 0; i-- {
		if isListed && sameHeldDefinition(held[i], listedHeld) {
			if !status.Pending && !status.Unavailable {
				// This very definition is listed in the scope that held it and its
				// admission no longer fails: the allow or the clean scan that
				// answered it ends its hold. A clean admission of the same bytes
				// in another scope is another connection.
				a.hookMCP.releaseFailed(connector, home, probe.SessionID, probe.ServerName, held[i])
			}
			continue
		}
		if gone == nil {
			gone = &held[i]
		}
	}
	if gone == nil && overflow && !isListed {
		// The definitions the session forgot are no longer listed and none was
		// scanned clean in this session: the call is a failed admission.
		gone = &config.MCPServerEntry{Name: probe.ServerName}
	}
	if gone == nil {
		return status
	}
	return watcher.FailedMCPStatus(*gone)
}

// heldMCPDefinition is the part of a listed definition the hold keeps: how the
// server is reached or started, and a digest of the complete definition, never
// its environment or headers, and the config scope that lists it.
func heldMCPDefinition(entry config.MCPServerEntry, connector, home string) config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: strings.TrimSpace(entry.Name), URL: strings.TrimSpace(entry.URL), Transport: entry.Transport,
		Command: strings.TrimSpace(entry.Command), Args: slices.Clone(entry.Args), ArgsCut: entry.ArgsCut,
		LocalRefusal: entry.LocalRefusal, Connector: connector, Home: home,
		Project: heldScope(entry), Fingerprint: watcher.MCPDefinitionHash(entry),
	}
}

// sameHeldDefinition reports whether two kept entries are one definition: the
// same server, listed in the same scope, and the same digest of everything
// else it was started with.
func sameHeldDefinition(a, b config.MCPServerEntry) bool {
	return sameMCPDefinition(a, b) && a.Project == b.Project && a.Fingerprint == b.Fingerprint
}

// heldScope is the config scope that lists entry: the project folder of a
// local or project scope, empty for the user scope.
func heldScope(entry config.MCPServerEntry) string {
	if project := strings.TrimSpace(entry.Project); project != "" {
		return filepath.Clean(project)
	}
	return ""
}

// heldFailures returns, within the memory time limit, the failed definitions
// the session holds for name, the latest last, and whether it met more than it
// could keep. Every hold, the per-user gateway and the managed hook alike, is
// under the session and the name alone, whatever directory the hook reports.
func (h *hookReportedMCPServers) heldFailures(connector, home, session, name string, now time.Time) (held []config.MCPServerEntry, overflow bool) {
	if h == nil || session == "" {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	holds := h.overflow[unrecordedKey(connector, home)]
	key := mcpResolvedKey(connector, home, session, "", name)
	if set, ok := h.refused[key]; ok {
		if now.Sub(set.seen) > mcpResolvedTTL {
			delete(h.refused, key)
		} else {
			set.seen = now
			overflow = set.overflow
			held = append(held, set.defs...)
		}
	}
	if hold, ok := holds[key]; ok {
		if !now.Before(hold.until) {
			delete(holds, key)
		} else {
			hold.until = now.Add(mcpResolvedTTL)
			overflow = overflow || hold.more
			held = append(held, hold.entry)
		}
	}
	return held, overflow
}

// holdFailedMCP keeps entry for the session; a session the full store cannot
// track is kept in the overflow store, by its own session and name.
func (a *APIServer) holdFailedMCP(connector, home string, probe mcpRuntimeProbe, entry config.MCPServerEntry, now time.Time) {
	if !a.hookMCP.retainRefused(connector, home, probe.SessionID, probe.ServerName, entry, now) {
		a.hookMCP.holdOverflow(connector, home, probe.SessionID, probe.ServerName, entry, now)
	}
}

// releaseFailed drops entry from what the session holds: its admission no
// longer fails, so the connection to it is no longer a failed one. A session
// marked overflow keeps its marker.
func (h *hookReportedMCPServers) releaseFailed(connector, home, session, name string, entry config.MCPServerEntry) {
	key := mcpResolvedKey(connector, home, session, "", name)
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.refused[key]; ok {
		set.defs = slices.DeleteFunc(set.defs, func(held config.MCPServerEntry) bool { return sameHeldDefinition(held, entry) })
		if len(set.defs) == 0 && !set.overflow {
			delete(h.refused, key)
		}
	}
	holds := h.overflow[unrecordedKey(connector, home)]
	if hold, ok := holds[key]; ok && !hold.more && sameHeldDefinition(hold.entry, entry) {
		delete(holds, key)
	}
}
