// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package protectedfiles

import (
	"path/filepath"
	"sync"
	"time"
)

// Session names the agent tool call a change is attributed to.
type Session struct {
	Connector        string
	SessionID        string
	ToolInvocationID string
	// AgentIdentityID is the agt- id of the hook caller, when known.
	AgentIdentityID string
}

const (
	// maxOpenCall is how long a tool call without its result still counts
	// as running. A blocked call never gets a result, so it must expire.
	maxOpenCall = 15 * time.Minute
	// endedGrace keeps a finished call attributable for a short while: the
	// watch polls, so a write in the last moment of a call is seen after
	// the call's result arrived.
	endedGrace = 5 * time.Second
	maxOpen    = 1024
	maxEnded   = 256
)

type callKey struct {
	home      string
	connector string
	session   string
	tool      string
}

type openCall struct {
	begin   time.Time
	session Session
	// seq tells this call's entry in Activity.order from an older one of
	// the same key.
	seq uint64
}

// openEntry is a call of Activity.open in begin order. An entry whose key
// was ended, expired, dropped or begun again (another seq) is stale and is
// skipped.
type openEntry struct {
	key   callKey
	begin time.Time
	seq   uint64
}

// openOrder is a binary min-heap of openEntry by begin time (no
// container/heap: its interface boxes every entry it moves).
type openOrder []openEntry

func (h *openOrder) push(e openEntry) {
	*h = append(*h, e)
	h.up(len(*h) - 1)
}

func (h *openOrder) pop() openEntry {
	old := *h
	last := len(old) - 1
	old[0], old[last] = old[last], old[0]
	e := old[last]
	old[last] = openEntry{}
	*h = old[:last]
	h.down(0)
	return e
}

func (h *openOrder) up(j int) {
	o := *h
	for j > 0 {
		i := (j - 1) / 2
		if !o[j].begin.Before(o[i].begin) {
			break
		}
		o[i], o[j] = o[j], o[i]
		j = i
	}
}

func (h *openOrder) down(i int) {
	o := *h
	for {
		j := 2*i + 1
		if j >= len(o) {
			return
		}
		if r := j + 1; r < len(o) && o[r].begin.Before(o[j].begin) {
			j = r
		}
		if !o[j].begin.Before(o[i].begin) {
			return
		}
		o[i], o[j] = o[j], o[i]
		i = j
	}
}

func (h *openOrder) init() {
	for i := len(*h)/2 - 1; i >= 0; i-- {
		h.down(i)
	}
}

type endedCall struct {
	home       string
	begin, end time.Time
	session    Session
}

// Activity records the agent tool calls running per user home. The
// gateway's hook handler feeds it; the watch reads it to tell a change an
// agent made from one the user made.
//
// order keeps the open calls in begin order, so a Begin finds the calls to
// expire and the oldest call to drop without walking or sorting every open
// call. A call that gets no result (a PreToolUse without its PostToolUse:
// every blocked call, and connectors that send no result) stays open for
// maxOpenCall; with maxOpen of them, the sort ran on every Begin under mu,
// and every hook call of the gateway waited for it (rel-1-0-6 GAP-0381).
type Activity struct {
	mu    sync.Mutex
	now   func() time.Time
	open  map[callKey]openCall
	order openOrder
	seq   uint64
	ended []endedCall
}

// NewActivity returns an empty Activity. now is nil for the wall clock.
func NewActivity(now func() time.Time) *Activity {
	if now == nil {
		now = time.Now
	}
	return &Activity{now: now, open: map[callKey]openCall{}}
}

func cleanHome(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Clean(home)
}

// Begin records that a tool call started for home.
func (a *Activity) Begin(home string, s Session) {
	if a == nil || home == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	a.expireLocked(now)
	key := callKey{cleanHome(home), s.Connector, s.SessionID, s.ToolInvocationID}
	if _, ok := a.open[key]; !ok && len(a.open) >= maxOpen {
		a.dropOldestLocked()
	}
	a.seq++
	a.open[key] = openCall{begin: now, session: s, seq: a.seq}
	a.order.push(openEntry{key: key, begin: now, seq: a.seq})
	a.compactOrderLocked()
}

// End records that a tool call finished. An empty ToolInvocationID ends
// every open call of the session (a stop event, or a connector that sends
// no call id).
func (a *Activity) End(home string, s Session) {
	if a == nil || home == "" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	home = cleanHome(home)
	for key, call := range a.open {
		if key.home != home || key.connector != s.Connector || key.session != s.SessionID {
			continue
		}
		if s.ToolInvocationID != "" && key.tool != s.ToolInvocationID && key.tool != "" {
			continue
		}
		delete(a.open, key)
		a.ended = append(a.ended, endedCall{home: home, begin: call.begin, end: now, session: call.session})
	}
	if len(a.ended) > maxEnded {
		a.ended = a.ended[len(a.ended)-maxEnded:]
	}
}

// Attribute returns the agent tool call that ran for home at some time in
// [from, to]: one still running, or one that ended at most endedGrace
// before from.
func (a *Activity) Attribute(home string, from, to time.Time) (Session, bool) {
	if a == nil {
		return Session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.expireLocked(a.now())
	home = cleanHome(home)
	var best Session
	var bestAt time.Time
	found := false
	for key, call := range a.open {
		if key.home == home && !call.begin.After(to) && (!found || call.begin.After(bestAt)) {
			best, bestAt, found = call.session, call.begin, true
		}
	}
	if found {
		return best, true
	}
	for i := len(a.ended) - 1; i >= 0; i-- {
		call := a.ended[i]
		if call.home == home && !call.begin.After(to) && !call.end.Before(from.Add(-endedGrace)) {
			return call.session, true
		}
	}
	return Session{}, false
}

// expireLocked ends the open calls older than maxOpenCall: the front of
// order.
func (a *Activity) expireLocked(now time.Time) {
	for len(a.order) > 0 {
		front := a.order[0]
		call, ok := a.open[front.key]
		if ok && call.seq == front.seq {
			if now.Sub(call.begin) <= maxOpenCall {
				break
			}
			delete(a.open, front.key)
		}
		a.order.pop()
	}
	cut := 0
	for cut < len(a.ended) && now.Sub(a.ended[cut].end) > maxOpenCall {
		cut++
	}
	a.ended = a.ended[cut:]
}

// dropOldestLocked forgets the open call that began first.
func (a *Activity) dropOldestLocked() {
	for len(a.order) > 0 {
		front := a.order.pop()
		if call, ok := a.open[front.key]; ok && call.seq == front.seq {
			delete(a.open, front.key)
			return
		}
	}
}

// compactOrderLocked rebuilds order from the open calls once stale entries
// (calls that ended or began again) outnumber them, so order stays within
// a small multiple of maxOpen.
func (a *Activity) compactOrderLocked() {
	if len(a.order) <= 2*len(a.open)+64 {
		return
	}
	a.order = a.order[:0]
	for key, call := range a.open {
		a.order = append(a.order, openEntry{key: key, begin: call.begin, seq: call.seq})
	}
	a.order.init()
}
