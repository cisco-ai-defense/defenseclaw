// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"hash/fnv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/watcher"
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
// the session reported for name, and reports whether the session is tracked:
// false only when the store is full (the caller then holds the session in the
// overflow table, holdOverflow). A session that met more definitions of the
// name than it can keep is tracked, marked overflow.
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
		return true
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
	if table := h.overflow[unrecordedKey(connector, home)]; table != nil {
		for i := range table {
			if table[i].session == session {
				table[i] = overflowSlot{}
			}
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
	if ctx.Value(unrecordedMCPKey{}) != nil {
		// The definition could not be recorded, so no allow written for it
		// has a record to release.
		return false
	}
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

// listedAs reports whether the report list holds entry as reported.
func (h *hookReportedMCPServers) listedAs(entry config.MCPServerEntry) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.listedLocked(entry)
}

func (h *hookReportedMCPServers) listedLocked(entry config.MCPServerEntry) bool {
	old, ok := h.servers[watcher.MCPEventPath(entry)]
	return ok && sameMCPDefinition(old, entry)
}

// unrecordedMCPKey marks the context of a call whose definition no store could
// record (heldRefusalsAllowed).
type unrecordedMCPKey struct{}

// unrecordedMCPDecision is the verdict on a call to the definition entry that
// no store could record: a failed admission, with the cause the definition
// shows. The fail-closed tiers block it with the administrator step, and the
// tiers that fail open allow it with the warning a failed scan gets. It
// applies to that definition only: another server of the account, and the
// same name with another definition, are decided on their own.
func (a *APIServer) unrecordedMCPDecision(ctx context.Context, cfg *config.Config, connector, hookEvent string, probe mcpRuntimeProbe, entry config.MCPServerEntry) (config.AssetPolicyDecision, bool) {
	ctx = context.WithValue(ctx, unrecordedMCPKey{}, true)
	return a.mcpAdmissionStatusDecision(ctx, cfg, connector, hookEvent, probe, watcher.FailedMCPStatus(entry))
}

// hookOverflowSlots is the size of the table that keeps the sessions the
// session store was full for (holdOverflow).
const hookOverflowSlots = 1024

// overflowSlot holds until its time the latest session and refused definition
// that mapped to it.
type overflowSlot struct {
	until   time.Time
	key     string
	session string
	entry   config.MCPServerEntry
}

func unrecordedKey(connector, home string) string {
	return strings.ToLower(connector) + "\x00" + home
}

func overflowIndex(key string) int {
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(key))
	return int(sum.Sum32() % hookOverflowSlots)
}

// holdOverflow keeps, for a session the full session store could not track,
// the refused definition it met, in a table of fixed size per connector and
// account that cannot fill: a session maps to one slot, and a slot is held
// until the memory time limit passes since the last call it held. The agent
// keeps its connection to the refused definition for as long as it lives, so
// the name of that session stays refused after the config is edited, with the
// cause the definition shows. Another session, another name and another
// account are held only if they map to a slot a held session also maps to,
// and only until that slot ends.
func (h *hookReportedMCPServers) holdOverflow(connector, home, session, cwd, name string, entry config.MCPServerEntry, now time.Time) {
	key := mcpResolvedKey(connector, home, session, cwd, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.overflow == nil {
		h.overflow = map[string]*[hookOverflowSlots]overflowSlot{}
	}
	account := unrecordedKey(connector, home)
	table := h.overflow[account]
	if table == nil {
		table = new([hookOverflowSlots]overflowSlot)
		h.overflow[account] = table
	}
	table[overflowIndex(key)] = overflowSlot{until: now.Add(mcpResolvedTTL), key: key, session: session, entry: entry}
}

// overflowHeld returns the refused definition the overflow table holds for the
// session and name of a call.
func (h *hookReportedMCPServers) overflowHeld(connector, home, session, cwd, name string, now time.Time) (config.MCPServerEntry, bool) {
	if h == nil || session == "" {
		return config.MCPServerEntry{}, false
	}
	key := mcpResolvedKey(connector, home, session, cwd, name)
	h.mu.Lock()
	defer h.mu.Unlock()
	table := h.overflow[unrecordedKey(connector, home)]
	if table == nil {
		return config.MCPServerEntry{}, false
	}
	slot := &table[overflowIndex(key)]
	if !now.Before(slot.until) {
		return config.MCPServerEntry{}, false
	}
	if slot.key == key {
		slot.until = now.Add(mcpResolvedTTL)
	}
	return slot.entry, true
}
