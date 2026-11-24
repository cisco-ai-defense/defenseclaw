// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"time"
)

// The first hook call after a resume (substrate-1 GAP-0486). Substrate
// resumes a suspended actor by itself when traffic reaches it, so no
// component sees the resume as it happens. The controller does see the
// actor suspended at a pass, and the leader relays that lifecycle record to
// the gateway: an actor seen suspended at time S runs a hook call only after
// it resumed, so the first hook call the gateway serves for that actor that
// started after S is the first one after the resume. Its audit row carries
// substrate_first_hook_after_resume=true and its round trip is recorded as
// defenseclaw.substrate.first_hook_after_resume. A hook call that started
// after S and was served before the record arrived was the first one: the
// mark is then dropped, never put on a later call, and so is the mark of a
// suspend and resume the controller saw inside one pass. The marks live on
// the replica that relays the record.

// maxSubstrateResumeActors bounds the actors the marks remember; past it the
// oldest record of each map is dropped (a missed mark, never a wrong one).
const maxSubstrateResumeActors = 4096

// substrateResumeMarks is the replica's memory of the suspends it relayed
// and of each actor's last hook call.
type substrateResumeMarks struct {
	mu        sync.Mutex
	suspended map[string]time.Time // actor UID -> when the controller saw it suspended
	lastHook  map[string]time.Time // actor UID -> start of its last hook call here
}

// suspendedAt records that the controller saw the actor suspended at at.
func (m *substrateResumeMarks) suspendedAt(uid string, at time.Time) {
	if uid == "" || at.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if last, ok := m.lastHook[uid]; ok && last.After(at) {
		// Its first call after the resume was served already, unmarked.
		delete(m.suspended, uid)
		return
	}
	if prev, ok := m.suspended[uid]; ok && prev.After(at) {
		return
	}
	m.suspended = boundedResumeMap(m.suspended, uid)
	m.suspended[uid] = at
}

// resumedAt drops a mark the resume record says cannot be told apart: a
// suspend and a resume the controller saw inside one pass (both records at
// the same time), whose first call may have run before that pass.
func (m *substrateResumeMarks) resumedAt(uid string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.suspended[uid]; ok && !at.After(s) {
		delete(m.suspended, uid)
	}
}

// forget drops a deleted actor.
func (m *substrateResumeMarks) forget(uid string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.suspended, uid)
	delete(m.lastHook, uid)
}

// hook notes a hook call of uid that started at start and reports whether it
// is the first one after a resume.
func (m *substrateResumeMarks) hook(uid string, start time.Time) bool {
	if uid == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if last, ok := m.lastHook[uid]; !ok || start.After(last) {
		m.lastHook = boundedResumeMap(m.lastHook, uid)
		m.lastHook[uid] = start
	}
	at, ok := m.suspended[uid]
	if !ok || !start.After(at) {
		return false
	}
	delete(m.suspended, uid)
	return true
}

// boundedResumeMap makes room for key in m (allocating it when nil),
// dropping the oldest entry when m is full.
func boundedResumeMap(m map[string]time.Time, key string) map[string]time.Time {
	if m == nil {
		return map[string]time.Time{}
	}
	if _, ok := m[key]; ok || len(m) < maxSubstrateResumeActors {
		return m
	}
	var oldest string
	var oldestAt time.Time
	for k, v := range m {
		if oldest == "" || v.Before(oldestAt) {
			oldest, oldestAt = k, v
		}
	}
	delete(m, oldest)
	return m
}

type substrateFirstHookAfterResumeKey struct{}

// withFirstHookAfterResume marks the request as the actor's first hook call
// after a resume.
func withFirstHookAfterResume(ctx context.Context) context.Context {
	return context.WithValue(ctx, substrateFirstHookAfterResumeKey{}, true)
}

func firstHookAfterResume(ctx context.Context) bool {
	v, _ := ctx.Value(substrateFirstHookAfterResumeKey{}).(bool)
	return v
}
