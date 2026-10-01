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

package sandboxauth

import (
	"context"
	"sync"
	"time"
)

// InFlight counts authenticated ingress requests per binding and remembers
// when each binding was last active.
//
// Every OpenShell network-policy reload closes the sandbox's open
// connections, including a hook request that is waiting on a verdict. The
// approval batcher therefore applies policy changes only when a sandbox is
// quiescent: no request open and none for an idle interval.
type InFlight struct {
	now func() time.Time

	mu      sync.Mutex
	states  map[string]*inFlightState
	changed chan struct{}
}

type inFlightState struct {
	active int
	last   time.Time
}

// NewInFlight returns an empty counter. A nil now uses time.Now.
func NewInFlight(now func() time.Time) *InFlight {
	if now == nil {
		now = time.Now
	}
	return &InFlight{now: now, states: make(map[string]*inFlightState), changed: make(chan struct{})}
}

// Begin records the start of a request for bindingID and returns the
// matching end function, which is idempotent.
func (f *InFlight) Begin(bindingID string) (end func()) {
	f.mu.Lock()
	st := f.states[bindingID]
	if st == nil {
		st = &inFlightState{}
		f.states[bindingID] = st
	}
	st.active++
	st.last = f.now()
	f.broadcastLocked()
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			if st.active > 0 {
				st.active--
			}
			st.last = f.now()
			f.broadcastLocked()
			f.mu.Unlock()
		})
	}
}

// Active returns the number of open requests for bindingID.
func (f *InFlight) Active(bindingID string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.states[bindingID]; st != nil {
		return st.active
	}
	return 0
}

// LastActivity returns when bindingID last started or finished a request,
// or the zero time if it never has.
func (f *InFlight) LastActivity(bindingID string) time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.states[bindingID]; st != nil {
		return st.last
	}
	return time.Time{}
}

// Quiescent reports whether bindingID has no open request and has been
// idle for at least idle.
func (f *InFlight) Quiescent(bindingID string, idle time.Duration) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	ok, _ := f.quiescentLocked(bindingID, idle)
	return ok
}

// WaitQuiescent blocks until bindingID is quiescent or ctx ends.
func (f *InFlight) WaitQuiescent(ctx context.Context, bindingID string, idle time.Duration) error {
	for {
		f.mu.Lock()
		ok, wait := f.quiescentLocked(bindingID, idle)
		changed := f.changed
		f.mu.Unlock()
		if ok {
			return nil
		}
		var (
			timer   *time.Timer
			timeout <-chan time.Time
		)
		if wait > 0 {
			timer = time.NewTimer(wait)
			timeout = timer.C
		}
		select {
		case <-ctx.Done():
		case <-changed:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
}

// Forget drops bindingID's state, e.g. after revoke.
func (f *InFlight) Forget(bindingID string) {
	f.mu.Lock()
	delete(f.states, bindingID)
	f.broadcastLocked()
	f.mu.Unlock()
}

// quiescentLocked reports quiescence and, when idle time is the only thing
// missing, how long remains.
func (f *InFlight) quiescentLocked(bindingID string, idle time.Duration) (bool, time.Duration) {
	st := f.states[bindingID]
	if st == nil {
		return true, 0
	}
	if st.active > 0 {
		return false, 0
	}
	elapsed := f.now().Sub(st.last)
	if elapsed >= idle {
		return true, 0
	}
	return false, idle - elapsed
}

func (f *InFlight) broadcastLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}
