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

import "sync"

// The two write lanes of a managed sandbox call (rel-1-0-6 GAP-0490). The
// journal rows (insert, decision, fallback, settlement) go to the audit
// store's durable connection, where concurrent writes share one commit and
// one flush. The audit verdict of a receipt goes to the store pool
// connection, which loses SQLITE_BUSY polling to a durable lane that is
// never idle, and fails the receipt. A gateway-wide mutex kept them apart,
// but it also made every call wait for the one before it, so the writes could
// not share a commit and the gateway finished only about 30 calls a second
// whatever the account budget. Calls of one lane now run together and the two
// lanes take turns.
const (
	journalLane = 0
	auditLane   = 1
)

// laneGate lets any number of holders of one lane run at once and makes the
// other lane wait for them. When the running lane drains, the lane that
// waited runs next, and every holder that was waiting for it runs together
// (that is what lets their writes share a commit); a holder that comes later
// waits for the following turn, so neither lane starves the other. The zero
// value is ready.
type laneGate struct {
	mu      sync.Mutex
	cond    *sync.Cond
	lane    int
	active  int
	waiting [2]int
	// quota is the number of waiting holders of lane that this turn admits.
	quota int
}

// enter returns once lane may run and gives back its leave function, which
// must be called exactly once.
func (g *laneGate) enter(lane int) (leave func()) {
	g.mu.Lock()
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	if (g.active == 0 && g.waiting[0]+g.waiting[1] == 0) || (g.lane == lane && g.waiting[1-lane] == 0) {
		g.lane = lane
	} else {
		g.waiting[lane]++
		for g.lane != lane || g.quota == 0 {
			g.cond.Wait()
		}
		g.quota--
		g.waiting[lane]--
	}
	g.active++
	g.mu.Unlock()
	return func() {
		g.mu.Lock()
		g.active--
		if g.active == 0 && g.waiting[1-g.lane] != 0 {
			g.lane = 1 - g.lane
			g.quota = g.waiting[g.lane]
			g.cond.Broadcast()
		}
		g.mu.Unlock()
	}
}
