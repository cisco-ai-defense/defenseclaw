// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// hookRefusedPerName bounds the distinct refused definitions one session
// keeps for one server name. A session that meets more is marked, and no
// administrator allow releases its calls (heldMCPRefusals.overflow).
const hookRefusedPerName = 16

// heldMCPRefusals are the definitions the scanner refuses that a session
// reported for one server name. The agent keeps its connection to a server
// for as long as its process lives, whatever its config says later, so a
// refused definition stays refused for the session after the file is edited
// to an ordinary one, to its allowed prefix or to anything else. Only the end
// of the session (mcpSessionStarted) or the memory time limit ends it.
type heldMCPRefusals struct {
	defs                     []config.MCPServerEntry
	overflow                 bool
	connector, home, session string
	seen                     time.Time
}

// retainRefused keeps entry, a definition the scanner refuses that the hook of
// the session reported for name, and reports whether the session holds it.
func (h *hookReportedMCPServers) retainRefused(connector, home, session, cwd, name string, entry config.MCPServerEntry, now time.Time) bool {
	key := mcpResolvedKey(connector, home, session, cwd, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.refused[key]
	if ok && now.Sub(set.seen) > mcpResolvedTTL {
		delete(h.refused, key)
		ok = false
	}
	if !ok {
		h.expireRefusedLocked(now)
		if len(h.refused) >= hookReportedMCPLimit || h.refusedPerHomeLocked(home) >= hookReportedMCPPerHomeLimit {
			return false
		}
		if h.refused == nil {
			h.refused = map[string]*heldMCPRefusals{}
		}
		set = &heldMCPRefusals{connector: connector, home: home, session: session}
		h.refused[key] = set
	}
	set.seen = now
	for i, held := range set.defs {
		if sameMCPDefinition(held, entry) {
			// The latest report is the last, so the listed record names it.
			set.defs = append(append(set.defs[:i:i], set.defs[i+1:]...), entry)
			return true
		}
	}
	if len(set.defs) >= hookRefusedPerName {
		set.overflow = true
		return false
	}
	set.defs = append(set.defs, entry)
	return true
}

// heldRefusals returns, within the memory time limit, the refused definitions
// the session reported for name, the latest last, and whether it met more
// than it could keep.
func (h *hookReportedMCPServers) heldRefusals(connector, home, session, cwd, name string, now time.Time) (defs []config.MCPServerEntry, overflow bool) {
	if h == nil {
		return nil, false
	}
	key := mcpResolvedKey(connector, home, session, cwd, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	set, ok := h.refused[key]
	if !ok {
		return nil, false
	}
	if now.Sub(set.seen) > mcpResolvedTTL {
		delete(h.refused, key)
		return nil, false
	}
	set.seen = now
	return append([]config.MCPServerEntry(nil), set.defs...), set.overflow
}

// forgetSession drops what a session held: its agent started again, so it
// connects to the servers its config lists now.
func (h *hookReportedMCPServers) forgetSession(connector, home, session string) {
	if h == nil {
		return
	}
	connector = strings.ToLower(connector)
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, set := range h.refused {
		if strings.ToLower(set.connector) == connector && set.home == home && set.session == session {
			delete(h.refused, key)
		}
	}
}

func (h *hookReportedMCPServers) expireRefusedLocked(now time.Time) {
	for key, set := range h.refused {
		if now.Sub(set.seen) > mcpResolvedTTL {
			delete(h.refused, key)
		}
	}
}

func (h *hookReportedMCPServers) refusedPerHomeLocked(home string) int {
	var n int
	for _, set := range h.refused {
		if set.home == home {
			n++
		}
	}
	return n
}

// heldRefusalsAllowed reports whether every refused definition the session
// reported for the server of probe is allowed by an administrator rule on the
// policy in force. A definition the running agent may still hold is judged
// like the one the config lists now, so an allow written for one definition
// does not release the calls of a session that met another.
func (a *APIServer) heldRefusalsAllowed(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe) bool {
	home, _ := callerHomeForAssets(ctx)
	defs, overflow := a.hookMCP.heldRefusals(connector, home, probe.SessionID, probe.WorkspaceDir, probe.ServerName, time.Now())
	if overflow {
		return false
	}
	for _, def := range defs {
		verdict := mcpProbeDecision(ctx, cfg, connector, mcpProbeWithEntry(probe, def, true))
		if !verdict.Enabled || verdict.Source != "admin-allow" {
			return false
		}
	}
	return true
}
