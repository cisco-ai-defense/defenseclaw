// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

import "sync"

// Benchmark-only: records, per session, the calls the task-scope floor would
// have raised in shadow mode (intent_scope.go), so the harness can score the
// floor without it changing a verdict.
type s7ScopeShadow struct {
	mu    sync.Mutex
	calls map[string][]string
}

// RecordScopeShadow installs the shadow observer. Call once after boot.
func (e *S7Engine) RecordScopeShadow() {
	rec := &s7ScopeShadow{calls: map[string][]string{}}
	e.scopeShadow = rec
	obs := func(sessionID, tool, reason string) {
		rec.mu.Lock()
		rec.calls[sessionID] = append(rec.calls[sessionID], tool+": "+reason)
		rec.mu.Unlock()
	}
	scopeShadowObserver.Store(&obs)
}

// TakeScopeShadow returns and clears the shadow findings recorded for sessionID.
func (e *S7Engine) TakeScopeShadow(sessionID string) []string {
	if e.scopeShadow == nil {
		return nil
	}
	e.scopeShadow.mu.Lock()
	defer e.scopeShadow.mu.Unlock()
	out := e.scopeShadow.calls[sessionID]
	delete(e.scopeShadow.calls, sessionID)
	return out
}
