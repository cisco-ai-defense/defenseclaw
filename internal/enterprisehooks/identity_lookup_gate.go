// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"sync"
)

// errIdentityLookupStillRunning: an earlier directory lookup of the same
// account has not returned, so no new one starts.
var errIdentityLookupStillRunning = errors.New("an earlier directory lookup of this account is still running")

// identityLookupGate runs the directory lookups of an identity pass in the
// background, one account key at a time, and waits for each only until its
// context ends. Some native lookups cannot be canceled (LookupAccountSid and
// TranslateNameW on Windows, Open Directory through os/user on a Mac), so a
// lookup that does not return is left to finish on its own, and its answer
// is not used. Until it returns, no new lookup of that account starts: the
// account keeps its previous record, and an account whose directory never
// answers holds one native call and no other account's turn. There is no
// limit across accounts, so one stalled account never stops the lookups of
// the others; the calls left running are at most one per account.
//
// An account whose last lookup did not answer in time is late, so a pass
// can take it after the others.
type identityLookupGate struct {
	mu sync.Mutex
	// running counts, per account key, the lookups that have not returned.
	running map[string]int
	// late holds the account keys whose last lookup did not answer before
	// its context ended.
	late map[string]bool
}

// isLate reports whether the last lookup of key did not answer in time.
func (g *identityLookupGate) isLate(key string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.late[key]
}

// identityLookupGated runs lookup for key through g. It returns ctx's error
// when ctx ended first, and errIdentityLookupStillRunning, without calling
// lookup, while an earlier lookup of key still runs.
func identityLookupGated[T any](ctx context.Context, g *identityLookupGate, key string, lookup func(context.Context) (T, error)) (T, error) {
	var zero T
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	g.mu.Lock()
	if g.running[key] > 0 {
		g.mu.Unlock()
		return zero, errIdentityLookupStillRunning
	}
	if g.running == nil {
		g.running = map[string]int{}
	}
	g.running[key]++
	g.mu.Unlock()
	type answer struct {
		value T
		err   error
	}
	done := make(chan answer, 1)
	go func() {
		value, err := lookup(ctx)
		g.mu.Lock()
		if g.running[key]--; g.running[key] <= 0 {
			delete(g.running, key)
		}
		g.mu.Unlock()
		done <- answer{value, err}
	}()
	select {
	case got := <-done:
		g.mu.Lock()
		delete(g.late, key)
		g.mu.Unlock()
		return got.value, got.err
	case <-ctx.Done():
		g.mu.Lock()
		if g.late == nil {
			g.late = map[string]bool{}
		}
		g.late[key] = true
		g.mu.Unlock()
		return zero, ctx.Err()
	}
}
