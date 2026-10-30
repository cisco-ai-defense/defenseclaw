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
	"sort"
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
}

type endedCall struct {
	home       string
	begin, end time.Time
	session    Session
}

// Activity records the agent tool calls running per user home. The
// gateway's hook handler feeds it; the watch reads it to tell a change an
// agent made from one the user made.
type Activity struct {
	mu    sync.Mutex
	now   func() time.Time
	open  map[callKey]openCall
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
	a.open[key] = openCall{begin: now, session: s}
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
// before from. An empty home matches every home (a system path).
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
		if (home == "" || key.home == home) && !call.begin.After(to) && (!found || call.begin.After(bestAt)) {
			best, bestAt, found = call.session, call.begin, true
		}
	}
	if found {
		return best, true
	}
	for i := len(a.ended) - 1; i >= 0; i-- {
		call := a.ended[i]
		if (home == "" || call.home == home) && !call.begin.After(to) && !call.end.Before(from.Add(-endedGrace)) {
			return call.session, true
		}
	}
	return Session{}, false
}

func (a *Activity) expireLocked(now time.Time) {
	for key, call := range a.open {
		if now.Sub(call.begin) > maxOpenCall {
			delete(a.open, key)
		}
	}
	cut := 0
	for cut < len(a.ended) && now.Sub(a.ended[cut].end) > maxOpenCall {
		cut++
	}
	a.ended = a.ended[cut:]
}

func (a *Activity) dropOldestLocked() {
	keys := make([]callKey, 0, len(a.open))
	for key := range a.open {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return a.open[keys[i]].begin.Before(a.open[keys[j]].begin) })
	delete(a.open, keys[0])
}
