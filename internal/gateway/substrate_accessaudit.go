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

// A refused attempt on another person's agent is audited as whoever made it
// (GAP-0434, GAP-0435; threat model: "other access is audited as the person
// who did it"). On the admin listener that is the signed-in person: a
// person who is not an administrator gets the same 404 actor_not_found as
// for a missing actor (no probing), an administrator asking for a session
// on another person's agent gets 403 not_your_agent. On the relay check it
// is the calling actor and the person it is registered to; the person a
// refused session token names is recorded apart (token_person). Nothing
// names the owner of the target.
//
// Rows are bounded like refused tokens: one per caller, route, outcome,
// reason and target per window, with the count of attempts it stands for,
// so a probe loop cannot fill the store (GAP-0402); a full window map
// writes the counts it evicts. The row is written off the request path, so
// a refused attempt answers in the same time as a miss.

const (
	// substrateAccessWindow is how often one key writes a row.
	substrateAccessWindow = time.Minute
	// substrateAccessMaxKeys bounds the window map.
	substrateAccessMaxKeys = 4096
	// substrateAccessQueue bounds the rows waiting to be written; a row
	// past it is written on the request path (record).
	substrateAccessQueue = 256
)

// substrateAccessEvent is one refused attempt.
type substrateAccessEvent struct {
	a   *APIServer
	st  *substrateState
	ctx context.Context
	// at is when the attempt was made (record sets it), so the window
	// does not depend on when the writer gets to it.
	at time.Time

	severity, outcome, reason, route, target string
	// The acting identity: a signed-in person, or a calling actor and the
	// person it is registered to.
	principal, personID string
	actorRef, actorUID  string
	// tokenPerson is the person a refused session token names.
	tokenPerson string
	// render, when set, gives the row's event name, summary, extra details
	// and log line for n attempts (a refused token: substrate_authrefusal.go).
	render func(n int) (event, summary string, details map[string]any, line string)
}

func (ev substrateAccessEvent) key() string {
	return fmt.Sprintf("%p\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", ev.st, ev.personID, ev.actorUID, ev.route, ev.outcome, ev.reason, ev.target, ev.tokenPerson)
}

type substrateAccessCount struct {
	since time.Time // the last row
	count int       // attempts since that row
	last  substrateAccessEvent
}

type substrateAccessRows struct {
	mu      sync.Mutex
	windows map[string]*substrateAccessCount
	now     func() time.Time

	once  sync.Once
	queue chan substrateAccessRow
}

// substrateAccessAudit is the gateway's one recorder of access rows.
var substrateAccessAudit = &substrateAccessRows{}

// substrateAccessRow is one row that is due: n attempts of ev's key.
type substrateAccessRow struct {
	ev      substrateAccessEvent
	n       int
	flushed bool
}

// record counts ev on the request path (a map update under a mutex, the
// same work for every attempt) and queues only the rows that are due, so a
// flood of cheap attempts cannot crowd out another caller's row. A due row
// that finds the queue full is written at once: due rows are bounded (one
// per key per window), so this is bounded too, and no row is dropped.
func (s *substrateAccessRows) record(ev substrateAccessEvent) {
	s.once.Do(func() {
		s.queue = make(chan substrateAccessRow, substrateAccessQueue)
		go s.writer()
	})
	ev.ctx = context.WithoutCancel(ev.ctx)
	switch {
	case s.now != nil:
		ev.at = s.now()
	case ev.st != nil && ev.st.now != nil:
		ev.at = ev.st.now()
	default:
		ev.at = time.Now()
	}
	for _, row := range s.note(ev) {
		select {
		case s.queue <- row:
		default:
			row.ev.write(row.n, row.flushed)
		}
	}
}

// writer writes queued rows, and every half window the counts of keys whose
// window has passed with no later attempt, so the tail of a flood is
// written too.
func (s *substrateAccessRows) writer() {
	tick := time.NewTicker(substrateAccessWindow / 2)
	defer tick.Stop()
	for {
		select {
		case row := <-s.queue:
			row.ev.write(row.n, row.flushed)
		case now := <-tick.C:
			for _, row := range s.pending(now) {
				row.ev.write(row.n, row.flushed)
			}
		}
	}
}

// pending returns, and restarts, the windows that have passed with
// attempts not yet written.
func (s *substrateAccessRows) pending(now time.Time) []substrateAccessRow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var rows []substrateAccessRow
	for _, w := range s.windows {
		if w.count > 0 && now.Sub(w.since) >= substrateAccessWindow {
			rows = append(rows, substrateAccessRow{w.last, w.count, false})
			w.since, w.count = now, 0
		}
	}
	return rows
}

// note counts ev and returns the rows that are due: ev's when its window
// has passed, and an evicted key's pending count when the map is full.
func (s *substrateAccessRows) note(ev substrateAccessEvent) []substrateAccessRow {
	now := ev.at
	if now.IsZero() {
		now = time.Now()
	}
	var rows []substrateAccessRow
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.windows == nil {
		s.windows = map[string]*substrateAccessCount{}
	}
	k := ev.key()
	w := s.windows[k]
	if w == nil {
		if len(s.windows) >= substrateAccessMaxKeys {
			oldest := ""
			for key, c := range s.windows {
				if oldest == "" || c.since.Before(s.windows[oldest].since) {
					oldest = key
				}
			}
			if c := s.windows[oldest]; c.count > 0 {
				rows = append(rows, substrateAccessRow{c.last, c.count, true})
			}
			delete(s.windows, oldest)
		}
		w = &substrateAccessCount{}
		s.windows[k] = w
	}
	w.count++
	w.last = ev
	if w.since.IsZero() || now.Sub(w.since) >= substrateAccessWindow {
		rows = append(rows, substrateAccessRow{ev, w.count, false})
		w.since, w.count = now, 0
	}
	return rows
}

func (ev substrateAccessEvent) write(n int, flushed bool) {
	if ev.render != nil {
		event, summary, details, line := ev.render(n)
		details["event"], details["count"] = event, n
		details["window_seconds"] = int(substrateAccessWindow / time.Second)
		if flushed {
			details["flushed"] = true
		}
		if ev.st != nil && ev.st.audit != nil {
			ev.st.audit(ev.ctx, ev.severity, summary, details)
		}
		ev.st.logLine("%s", line)
		return
	}
	who := ev.principal
	if who == "" {
		who = ev.personID
	}
	if ev.actorRef != "" {
		who = "actor " + ev.actorRef
	}
	if who == "" {
		who = "an unknown caller"
	}
	summary := fmt.Sprintf("%s %s on %s (%s): %s, %d attempt(s)", who, ev.outcome, ev.target, ev.route, ev.reason, n)
	details := map[string]any{
		"event": "access_" + ev.outcome, "outcome": ev.outcome, "reason": ev.reason, "route": ev.route, "target": ev.target,
		"principal": ev.principal, "person_id": ev.personID, "count": n,
		"window_seconds": int(substrateAccessWindow / time.Second),
	}
	if ev.actorRef != "" {
		details["actor"], details["actor_uid"] = ev.actorRef, ev.actorUID
	}
	if ev.tokenPerson != "" {
		details["token_person"] = ev.tokenPerson
	}
	if flushed {
		details["flushed"] = true
	}
	if ev.a != nil && ev.a.logger != nil {
		_ = ev.a.logger.LogAlertCtx(ev.ctx, "substrate", ev.severity, summary, details)
	}
	ev.st.logRefusal("access %s on %s (%s): %s, %d attempt(s)", ev.outcome, ev.target, ev.route, ev.reason, n)
}

func substrateRoutePattern(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return r.Method + " " + r.URL.Path
}

// substrateAuditDenied records a refused admin-listener attempt on another
// person's agent, as the signed-in caller.
func (a *APIServer) substrateAuditDenied(st *substrateState, r *http.Request, target, reason string) {
	c, ok := substrateCallerFrom(r.Context())
	if !ok {
		return
	}
	severity := "MEDIUM"
	if c.admin {
		severity = "HIGH"
	}
	substrateAccessAudit.record(substrateAccessEvent{
		a: a, st: st, ctx: r.Context(), severity: severity, outcome: "denied", reason: reason,
		route: substrateRoutePattern(r), target: target, principal: c.person.Principal, personID: ownerOf(c.person).ID(),
	})
}

// substrateAuditRelayDenied records a refused relay session check, as the
// calling actor (verified by its token) and the person it is registered
// to; tokenPerson is the person the refused session token names, if any.
func (a *APIServer) substrateAuditRelayDenied(st *substrateState, r *http.Request, severity, reason, target, tokenPerson string) {
	ev := substrateAccessEvent{
		a: a, st: st, ctx: r.Context(), severity: severity, outcome: "denied", reason: reason,
		route: substrateRoutePattern(r), target: target, tokenPerson: tokenPerson,
	}
	if actor, ok := substrateActorFrom(r.Context()); ok {
		ev.actorRef, ev.actorUID = actor.Atespace+"/"+actor.Name, actor.UID
	}
	if reg, ok := substrateRegistrationFrom(r.Context()); ok && reg.Person.Subject != "" {
		ev.principal, ev.personID = reg.Person.Principal, reg.Person.ID()
	}
	substrateAccessAudit.record(ev)
}
