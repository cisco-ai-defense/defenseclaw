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
// A hold belongs to the config scope that lists the server, not to the working
// directory of the call that met it: a user-scope server is one connection
// whatever directory the agent works in later, and a local or project scope is
// the folder its entry names (heldScope). The definition kept is the complete
// one, by a digest of it, so an edit of a header or of the environment is a
// different definition and the failure of the old one is not released by the
// clean admission of the new one.

// failedMCPSessionHold records, when the listed definition of the server of
// probe has a failed admission, that the session met it, and answers a call
// whose listed definition is not that one: the held definition is returned
// as a failed status for as long as the session lives and the config does not
// list it again with an admission that no longer fails. A listed definition
// whose admission is still pending, or cannot be read, has not been admitted:
// it does not release the hold. Secure Client and the managed hook-reported
// gateway never get here with a status to change.
func (a *APIServer) failedMCPSessionHold(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe,
	status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
	if a == nil || a.hookMCP == nil || strings.TrimSpace(probe.SessionID) == "" || watcherUsesHookReportedMCP(cfg) ||
		ctx.Value(unrecordedMCPKey{}) != nil || (status.Failed && status.Revoked) {
		return status
	}
	home, _ := callerHomeForAssets(ctx)
	now := time.Now()
	listed, isListed := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName)
	if status.Failed {
		if isListed {
			a.holdFailedMCP(connector, home, probe, heldScope(listed), heldMCPDefinition(listed, connector, home), now)
		}
		return status
	}
	held, _ := a.hookMCP.heldFailures(connector, home, probe.SessionID, probe.ServerName, heldScopes(probe.WorkspaceDir), now)
	if len(held) == 0 {
		return status
	}
	var listedHeld config.MCPServerEntry
	if isListed {
		listedHeld = heldMCPDefinition(listed, connector, home)
	}
	var gone *config.MCPServerEntry
	for i := len(held) - 1; i >= 0; i-- {
		if isListed && sameHeldDefinition(held[i].def, listedHeld) {
			if !status.Pending && !status.Unavailable {
				// This very definition is listed and its admission no longer
				// fails: the allow or the clean scan that answered it ends its hold.
				a.hookMCP.releaseFailed(connector, home, probe.SessionID, held[i].scope, probe.ServerName, held[i].def)
			}
			continue
		}
		if gone == nil {
			gone = &held[i].def
		}
	}
	if gone == nil {
		return status
	}
	return watcher.FailedMCPStatus(*gone)
}

// heldMCPDefinition is the part of a listed definition the hold keeps: how the
// server is reached or started, and a digest of the complete definition, never
// its environment or headers.
func heldMCPDefinition(entry config.MCPServerEntry, connector, home string) config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: strings.TrimSpace(entry.Name), URL: strings.TrimSpace(entry.URL), Transport: entry.Transport,
		Command: strings.TrimSpace(entry.Command), Args: slices.Clone(entry.Args), ArgsCut: entry.ArgsCut,
		LocalRefusal: entry.LocalRefusal, Connector: connector, Home: home,
		Fingerprint: watcher.MCPDefinitionHash(entry),
	}
}

// sameHeldDefinition reports whether two kept entries are one definition: the
// same server and the same digest of everything else it was started with.
func sameHeldDefinition(a, b config.MCPServerEntry) bool {
	return sameMCPDefinition(a, b) && a.Fingerprint == b.Fingerprint
}

// heldScope is the config scope that lists entry: the project folder of a
// local or project scope, empty for the user scope.
func heldScope(entry config.MCPServerEntry) string {
	if project := strings.TrimSpace(entry.Project); project != "" {
		return filepath.Clean(project)
	}
	return ""
}

// heldScopes are the scopes a hold of a call from cwd can be under: the user
// scope, then each folder from the root down to the working directory, the
// folder of the call last.
func heldScopes(cwd string) []string {
	scopes := []string{""}
	cwd = strings.TrimSpace(cwd)
	if cwd == "" {
		return scopes
	}
	var chain []string
	for dir := filepath.Clean(cwd); ; {
		chain = append(chain, dir)
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	slices.Reverse(chain)
	return append(scopes, chain...)
}

// heldFailure is a failed definition a session holds, with the scope it is
// held under.
type heldFailure struct {
	scope string
	def   config.MCPServerEntry
}

// heldFailures returns, within the memory time limit, the failed definitions
// the session holds for name under any of scopes, the latest last, and
// whether it met more than it could keep.
func (h *hookReportedMCPServers) heldFailures(connector, home, session, name string, scopes []string, now time.Time) (held []heldFailure, overflow bool) {
	if h == nil || session == "" {
		return nil, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	holds := h.overflow[unrecordedKey(connector, home)]
	for _, scope := range scopes {
		key := mcpResolvedKey(connector, home, session, scope, name)
		if set, ok := h.refused[key]; ok {
			if now.Sub(set.seen) > mcpResolvedTTL {
				delete(h.refused, key)
			} else {
				set.seen = now
				overflow = overflow || set.overflow
				for _, def := range set.defs {
					held = append(held, heldFailure{scope: scope, def: def})
				}
			}
		}
		if hold, ok := holds[key]; ok {
			if !now.Before(hold.until) {
				delete(holds, key)
			} else {
				hold.until = now.Add(mcpResolvedTTL)
				held = append(held, heldFailure{scope: scope, def: hold.entry})
			}
		}
	}
	return held, overflow
}

// holdFailedMCP keeps entry for the session under scope; a session the full
// store cannot track is kept in the overflow store, by its own session, scope
// and name.
func (a *APIServer) holdFailedMCP(connector, home string, probe mcpRuntimeProbe, scope string, entry config.MCPServerEntry, now time.Time) {
	if !a.hookMCP.retainRefused(connector, home, probe.SessionID, scope, probe.ServerName, entry, now) {
		a.hookMCP.holdOverflow(connector, home, probe.SessionID, scope, probe.ServerName, entry, now)
	}
}

// releaseFailed drops entry from what the session holds under scope: its
// admission no longer fails, so the connection to it is no longer a failed one.
func (h *hookReportedMCPServers) releaseFailed(connector, home, session, scope, name string, entry config.MCPServerEntry) {
	key := mcpResolvedKey(connector, home, session, scope, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	if set, ok := h.refused[key]; ok {
		set.defs = slices.DeleteFunc(set.defs, func(held config.MCPServerEntry) bool { return sameHeldDefinition(held, entry) })
		if len(set.defs) == 0 && !set.overflow {
			delete(h.refused, key)
		}
	}
	holds := h.overflow[unrecordedKey(connector, home)]
	if hold, ok := holds[key]; ok && sameHeldDefinition(hold.entry, entry) {
		delete(holds, key)
	}
}
