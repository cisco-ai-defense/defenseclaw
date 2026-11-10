// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
// overflow store, holdOverflow). A session that met more definitions of the
// name than it can keep is tracked, marked overflow.
func (h *hookReportedMCPServers) retainRefused(connector, home, session, name string, entry config.MCPServerEntry, now time.Time) bool {
	key := mcpResolvedKey(connector, home, session, "", name)
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
		if sameHeldDefinition(held, entry) {
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
func (h *hookReportedMCPServers) heldRefusals(connector, home, session, name string, now time.Time) (defs []config.MCPServerEntry, overflow bool) {
	if h == nil {
		return nil, false
	}
	key := mcpResolvedKey(connector, home, session, "", name)
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
	holds := h.overflow[unrecordedKey(connector, home)]
	for key, hold := range holds {
		if hold.session == session {
			delete(holds, key)
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
	_, unallowed := a.unallowedHeldRefusal(ctx, cfg, connector, probe, nil)
	return !unallowed
}

// unallowedHeldRefusal returns the latest definition the session reported
// for the server of probe that no administrator rule on the policy in force
// allows, skipping except (the definition the config lists, whose own
// admission decides it). A session marked overflow has definitions it
// forgot, so no allow covers it: the answer is the server by name.
func (a *APIServer) unallowedHeldRefusal(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe,
	except *config.MCPServerEntry) (config.MCPServerEntry, bool) {
	home, _ := callerHomeForAssets(ctx)
	held, overflow := a.hookMCP.heldFailures(connector, home, probe.SessionID, probe.ServerName, time.Now())
	if overflow {
		return config.MCPServerEntry{Name: probe.ServerName}, true
	}
	for i := len(held) - 1; i >= 0; i-- {
		if except != nil && sameMCPDefinition(held[i], *except) {
			continue
		}
		if !heldDefinitionAllowed(ctx, cfg, connector, probe, held[i]) {
			return held[i], true
		}
	}
	return config.MCPServerEntry{}, false
}

// hookReportedSessionHold is the hold of the running connection on a managed
// Linux or macOS gateway. The agent keeps the connection it opened to a
// definition for as long as it lives, whatever its config lists later, and
// the hook names the server, not the connection. A session that met a refused
// definition other than the listed one is therefore judged on that definition
// for the rest of its life: an allow or a clean admission of the listed
// replacement never speaks for the connection to the earlier one, and the
// calls stay failed admissions of it until every definition the session met
// is allowed by an administrator rule, or the agent starts again
// (mcpSessionStarted). A listed definition whose admission already failed is
// decided by mcpAdmissionStatusDecision with the same rule (GAP-0925).
func (a *APIServer) hookReportedSessionHold(ctx context.Context, cfg *config.Config, connector string, probe mcpRuntimeProbe,
	status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
	if status.Failed {
		return status
	}
	home, _ := callerHomeForAssets(ctx)
	// The ordinary call, with nothing held, reads no config.
	if held, overflow := a.hookMCP.heldFailures(connector, home, probe.SessionID, probe.ServerName, time.Now()); len(held) == 0 && !overflow {
		return status
	}
	var listed *config.MCPServerEntry
	if entry, ok := a.lookupCallerMCPServer(ctx, cfg, connector, probe.WorkspaceDir, probe.ServerName); ok {
		listed = &entry
	}
	if held, unallowed := a.unallowedHeldRefusal(ctx, cfg, connector, probe, listed); unallowed {
		return watcher.FailedMCPStatus(held)
	}
	return status
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

// hookOverflowPerAccount bounds the refused sessions the overflow store keeps
// for one connector and account (holdOverflow).
const hookOverflowPerAccount = 4096

// overflowHold is what the overflow store keeps for one session and server
// name: the first refused definition the session met, whose cause every later
// call of the session shows, and the time the hold ends.
type overflowHold struct {
	until   time.Time
	session string
	entry   config.MCPServerEntry
	// more says the session met another definition of the name that was not
	// kept: the hold is then never released by the admission of entry.
	more bool
}

func unrecordedKey(connector, home string) string {
	return strings.ToLower(connector) + "\x00" + home
}

// holdOverflow keeps, for a session the full session store could not track,
// the first refused definition it met for the server name, in a store per
// connector and account keyed by the session and the name, whatever directory
// a hook reports. The agent keeps its connection to the refused
// definition for as long as it lives, so the name of that session stays
// refused after the config is edited, with the cause of the definition it met
// first: a later report of another definition of the name does not replace
// it. A hold ends on its own memory time limit since the last call it held and
// by SessionStart of its session. No other session, name or account shares a
// hold, so a hold never blocks an ordinary server and no other session ends
// it. A store that is full of live holds first gives up the expired ones; when
// every hold is live the new session is not kept, and the call itself is
// decided as a failed admission (unrecordedMCPDecision).
func (h *hookReportedMCPServers) holdOverflow(connector, home, session, name string, entry config.MCPServerEntry, now time.Time) {
	key := mcpResolvedKey(connector, home, session, "", name)
	h.mu.Lock()
	defer h.mu.Unlock()
	account := unrecordedKey(connector, home)
	holds := h.overflow[account]
	held, present := holds[key]
	if present && now.Before(held.until) {
		held.until = now.Add(mcpResolvedTTL)
		held.more = held.more || !sameHeldDefinition(held.entry, entry)
		return
	}
	if !present && len(holds) >= hookOverflowPerAccount {
		for old, hold := range holds {
			if !now.Before(hold.until) {
				delete(holds, old)
			}
		}
		if len(holds) >= hookOverflowPerAccount {
			return
		}
	}
	if h.overflow == nil {
		h.overflow = map[string]map[string]*overflowHold{}
	}
	if holds == nil {
		holds = map[string]*overflowHold{}
		h.overflow[account] = holds
	}
	holds[key] = &overflowHold{until: now.Add(mcpResolvedTTL), session: session, entry: entry}
}

// overflowHeld returns the refused definition the overflow store holds for the
// session and name of a call.
func (h *hookReportedMCPServers) overflowHeld(connector, home, session, name string, now time.Time) (config.MCPServerEntry, bool) {
	if h == nil || session == "" {
		return config.MCPServerEntry{}, false
	}
	key := mcpResolvedKey(connector, home, session, "", name)
	h.mu.Lock()
	defer h.mu.Unlock()
	holds := h.overflow[unrecordedKey(connector, home)]
	hold, ok := holds[key]
	if !ok {
		return config.MCPServerEntry{}, false
	}
	if !now.Before(hold.until) {
		delete(holds, key)
		return config.MCPServerEntry{}, false
	}
	hold.until = now.Add(mcpResolvedTTL)
	return hold.entry, true
}
