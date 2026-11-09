// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
)

// hookCorrelationSerial holds the hooks of one session of one connector to
// one correlation attempt at a time inside this gateway (rel-1-0-6 GAP-0490).
//
// The correlation ledger is written optimistically: an attempt reads the
// session cursor, then a write that another hook of the same session
// committed in between makes it stale and it starts over, up to
// hookCorrelationAttempts times. The ledger lives on the store one writer
// connection, so the attempts of a busy session gain nothing from running
// together: they only repeat each other reads and lose to each other writes.
// A sandbox that issues 22 to 24 calls a second on one session kept several
// of them stale at once, each repeating its reads and its busy wait, and
// that repeated work is what took the single writer past what the gateway
// could finish inside the hook answer window. Taking the session turns
// removes the in-process conflict; the stale retry stays for a writer outside
// this process.
type hookCorrelationSerial struct {
	mu      sync.Mutex
	entries map[string]*hookCorrelationSerialEntry
}

type hookCorrelationSerialEntry struct {
	turn chan struct{}
	refs int
}

// acquire waits for the key turn, or for ctx. The returned release may be
// called any number of times and must be called at least once when err is nil.
func (s *hookCorrelationSerial) acquire(ctx context.Context, key string) (release func(), err error) {
	s.mu.Lock()
	if s.entries == nil {
		s.entries = make(map[string]*hookCorrelationSerialEntry)
	}
	entry := s.entries[key]
	if entry == nil {
		entry = &hookCorrelationSerialEntry{turn: make(chan struct{}, 1)}
		s.entries[key] = entry
	}
	entry.refs++
	s.mu.Unlock()
	leave := func() {
		s.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(s.entries, key)
		}
		s.mu.Unlock()
	}
	select {
	case entry.turn <- struct{}{}:
	case <-ctx.Done():
		leave()
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			<-entry.turn
			leave()
		})
	}, nil
}
