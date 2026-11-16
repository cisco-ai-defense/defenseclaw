// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/watcher"
)

// mcpSessionStart is when the gateway first heard from an agent session, or
// from its process after a start or a resume.
type mcpSessionStart struct {
	started, seen time.Time
}

// noteSession records the hook of a session. A start or a resume is a new
// agent process, which connects to the servers its config lists now, so it
// sets the start time; any other hook only sets it for a session not yet
// known (a cleared or compacted conversation keeps its process). A session
// the full store cannot track is left unknown, which the callers judge as
// the oldest: no connection is ruled out for it.
func (h *hookReportedMCPServers) noteSession(connector, home, session string, restart bool, now time.Time) {
	if h == nil || session == "" {
		return
	}
	key := mcpResolvedKey(connector, home, session, "", "")
	h.mu.Lock()
	defer h.mu.Unlock()
	known, ok := h.sessionStarts[key]
	if ok && now.Sub(known.seen) > mcpResolvedTTL {
		delete(h.sessionStarts, key)
		ok = false
	}
	if !ok {
		if len(h.sessionStarts) >= hookReportedMCPLimit {
			for other, entry := range h.sessionStarts {
				if now.Sub(entry.seen) > mcpResolvedTTL {
					delete(h.sessionStarts, other)
				}
			}
		}
		if len(h.sessionStarts) >= hookReportedMCPLimit {
			return
		}
		if h.sessionStarts == nil {
			h.sessionStarts = map[string]*mcpSessionStart{}
		}
		known = &mcpSessionStart{started: now}
		h.sessionStarts[key] = known
	} else if restart {
		known.started = now
	}
	known.seen = now
}

// sessionStartedAt returns when the session started, within the memory time
// limit; false for a session the gateway has not heard from, or could not
// track.
func (h *hookReportedMCPServers) sessionStartedAt(connector, home, session string, now time.Time) (time.Time, bool) {
	if h == nil || session == "" {
		return time.Time{}, false
	}
	key := mcpResolvedKey(connector, home, session, "", "")
	h.mu.Lock()
	defer h.mu.Unlock()
	known, ok := h.sessionStarts[key]
	if !ok || now.Sub(known.seen) > mcpResolvedTTL {
		return time.Time{}, false
	}
	return known.started, true
}

// statusForSession is the admission status the watcher gave, narrowed to the
// session that asks. A revoked earlier definition (the entry was edited or
// removed after an allow admitted it, and the allow is gone) is a connection
// only an agent process that was running when the entry left can still hold:
// a session that started after it connects to the definition the config lists,
// and is judged on that one. The session that held the earlier definition
// keeps the revoked status, and so does a session the gateway cannot place in
// time. An exact allow of the replacement therefore admits the sessions that
// start after it at once (GAP-1016).
func (a *APIServer) statusForSession(ctx context.Context, connector string, probe mcpRuntimeProbe, status watcher.MCPAdmissionStatus) watcher.MCPAdmissionStatus {
	if !status.Revoked || status.Departed.IsZero() || status.Listed == nil || strings.TrimSpace(probe.SessionID) == "" {
		return status
	}
	home, _ := callerHomeForAssets(ctx)
	if started, known := a.hookMCP.sessionStartedAt(connector, home, probe.SessionID, time.Now()); known && started.After(status.Departed) {
		return *status.Listed
	}
	return status
}
