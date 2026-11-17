// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
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
	// substrateAccessQueue bounds the rows waiting to be written; past it
	// attempts are dropped and counted on the next row.
	substrateAccessQueue = 256
)

// substrateAccessEvent is one refused attempt.
type substrateAccessEvent struct {
	a   *APIServer
	st  *substrateState
	ctx context.Context

	severity, outcome, reason, route, target string
	// The acting identity: a signed-in person, or a calling actor and the
	// person it is registered to.
	principal, personID string
	actorRef, actorUID  string
	// tokenPerson is the person a refused session token names.
	tokenPerson string
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

	once    sync.Once
	queue   chan substrateAccessEvent
	dropped atomic.Int64
}

// substrateAccessAudit is the gateway's one recorder of access rows.
var substrateAccessAudit = &substrateAccessRows{}

// record queues ev; it never blocks the request.
func (s *substrateAccessRows) record(ev substrateAccessEvent) {
	s.once.Do(func() {
		s.queue = make(chan substrateAccessEvent, substrateAccessQueue)
		go func() {
			for ev := range s.queue {
				s.note(ev)
			}
		}()
	})
	ev.ctx = context.WithoutCancel(ev.ctx)
	select {
	case s.queue <- ev:
	default:
		s.dropped.Add(1)
	}
}

// note counts ev and writes the rows that are due: ev's when its window
// has passed, and an evicted key's pending count when the map is full.
func (s *substrateAccessRows) note(ev substrateAccessEvent) {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	type due struct {
		ev      substrateAccessEvent
		n       int
		flushed bool
	}
	var rows []due
	s.mu.Lock()
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
				rows = append(rows, due{c.last, c.count, true})
			}
			delete(s.windows, oldest)
		}
		w = &substrateAccessCount{}
		s.windows[k] = w
	}
	w.count++
	w.last = ev
	if w.since.IsZero() || now.Sub(w.since) >= substrateAccessWindow {
		rows = append(rows, due{ev, w.count, false})
		w.since, w.count = now, 0
	}
	s.mu.Unlock()
	for _, d := range rows {
		d.ev.write(d.n, d.flushed, s.dropped.Swap(0))
	}
}

func (ev substrateAccessEvent) write(n int, flushed bool, dropped int64) {
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
	if dropped > 0 {
		details["dropped"] = dropped
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
