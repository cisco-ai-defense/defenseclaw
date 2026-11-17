// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// A refused attempt on another person's agent is audited as the person who
// made it (GAP-0434; threat model: "other access is audited as the person
// who did it"). The admin listener answers it exactly like a missing actor
// (404 actor_not_found, no probing), and the actor relay's session check
// refuses a session token for another actor; either way one substrate audit
// row names the acting person (principal and issuer#subject), the route
// pattern, the target agent and the outcome, and nothing names the owner. A
// probe loop is bounded like refused tokens: one row per caller, route and
// outcome per window, with the count of attempts it stands for (GAP-0402).

// substrateAccessWindow is how often one caller, route and outcome writes a
// row.
const substrateAccessWindow = time.Minute

// substrateAccessMaxKeys bounds the window map; past it the map starts
// again (a row per key is then written early, never dropped).
const substrateAccessMaxKeys = 4096

type substrateAccessCount struct {
	since time.Time // the last row
	count int       // attempts since that row, the one that writes the next row included
}

type substrateAccessRows struct {
	mu      sync.Mutex
	windows map[string]*substrateAccessCount
	now     func() time.Time
}

// substrateAccessAudit is the gateway's one bound for access rows.
var substrateAccessAudit = &substrateAccessRows{}

// note counts one attempt under key and reports whether it writes a row and
// how many attempts that row stands for.
func (s *substrateAccessRows) note(key string) (int, bool) {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windows == nil || len(s.windows) >= substrateAccessMaxKeys {
		s.windows = map[string]*substrateAccessCount{}
	}
	w := s.windows[key]
	if w == nil {
		w = &substrateAccessCount{}
		s.windows[key] = w
	}
	w.count++
	if !w.since.IsZero() && now.Sub(w.since) < substrateAccessWindow {
		return 0, false
	}
	n := w.count
	w.since, w.count = now, 0
	return n, true
}

// substrateAccessRow writes one bounded access row as the acting person.
func (a *APIServer) substrateAccessRow(st *substrateState, r *http.Request, severity, outcome, reason, principal, personID, target string) {
	route := r.Pattern
	if route == "" {
		route = r.Method + " " + r.URL.Path
	}
	// Keyed per listener state too, so a reconfigured gateway starts fresh.
	n, write := substrateAccessAudit.note(fmt.Sprintf("%p", st) + "\x00" + personID + "\x00" + route + "\x00" + outcome + "\x00" + reason)
	if !write {
		return
	}
	who := principal
	if who == "" {
		who = personID
	}
	if who == "" {
		who = "an unknown caller"
	}
	summary := fmt.Sprintf("%s %s on %s (%s): %s, %d attempt(s)", who, outcome, target, route, reason, n)
	details := map[string]any{
		"event": "access_" + outcome, "outcome": outcome, "reason": reason, "route": route, "target": target,
		"principal": principal, "person_id": personID, "count": n,
		"window_seconds": int(substrateAccessWindow / time.Second),
	}
	if a.logger != nil {
		_ = a.logger.LogAlertCtx(context.WithoutCancel(r.Context()), "substrate", severity, summary, details)
	}
	st.logRefusal("access %s on %s (%s): %s, %d attempt(s)", outcome, target, route, reason, n)
}

// substrateAuditDenied records a refused admin-listener attempt on another
// person's agent, as the caller.
func (a *APIServer) substrateAuditDenied(st *substrateState, r *http.Request, target, reason string) {
	c, ok := substrateCallerFrom(r.Context())
	if !ok {
		return
	}
	a.substrateAccessRow(st, r, "MEDIUM", "denied", reason, c.person.Principal, ownerOf(c.person).ID(), target)
}
