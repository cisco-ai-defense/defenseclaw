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

package manager

import (
	"sort"
	"sync"
	"time"
)

// Flood limits: what one sandbox can put into the egress telemetry queue
// and the activity feed that every sandbox shares. A workload that makes
// thousands of refused requests a second would otherwise push the other
// sandboxes' events, and its own large-upload finding, out of both.
var (
	// blockCoalesceWindow folds repeats of one refusal (same sandbox,
	// destination, port, category and rule) into the first one's record
	// and a count.
	blockCoalesceWindow = 10 * time.Second
	// sinkFlushInterval is how often folded refusals are recorded.
	sinkFlushInterval = 2 * time.Second
	// heldBackInterval is how often the counts of the events a sandbox's
	// pacing held back are reported.
	heldBackInterval = 30 * time.Second
)

// Pacing of one sandbox's distinct refusals into the telemetry queue, and
// of its egress events onto the feed.
const (
	blockedBurst, blockedRate = 100, 20
	feedBurst, feedRate       = 30, 2
	// maxSinkOverflow bounds the findings kept while the queue is full.
	maxSinkOverflow = 4096
)

// rateGate paces events per key (a sandbox) with a token bucket and counts
// the events it holds back until drain reports them.
type rateGate struct {
	burst, rate float64

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	at     time.Time
	held   int
}

func newRateGate(burst, rate float64) *rateGate {
	return &rateGate{burst: burst, rate: rate, buckets: map[string]*tokenBucket{}}
}

// take reports whether key may pass one more event at now; one it holds
// back is counted.
func (g *rateGate) take(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	b := g.buckets[key]
	if b == nil {
		b = &tokenBucket{tokens: g.burst, at: now}
		g.buckets[key] = b
	}
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		b.tokens = min(g.burst, b.tokens+elapsed*g.rate)
		b.at = now
	}
	if b.tokens < 1 {
		b.held++
		return false
	}
	b.tokens--
	return true
}

// drain returns the keys that held events back since the last drain, with
// their counts, sorted by key, and forgets buckets that refilled.
func (g *rateGate) drain(now time.Time) []heldCount {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []heldCount
	for key, b := range g.buckets {
		if b.held > 0 {
			out = append(out, heldCount{key: key, n: b.held})
			b.held = 0
			continue
		}
		if b.tokens+now.Sub(b.at).Seconds()*g.rate >= g.burst {
			delete(g.buckets, key)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

type heldCount struct {
	key string
	n   int
}
