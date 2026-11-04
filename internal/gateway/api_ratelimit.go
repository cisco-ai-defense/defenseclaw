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
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// perIPLimiterEntry pairs a token-bucket limiter with the timestamp of the
// last request seen from that IP, so the eviction sweep can drop stale
// entries without locking the entire map for the duration of the scan.
//
// ("Rate limiter timestamp has an unsynchronized data
// race"): the previous implementation stored `time.Time` directly,
// which is a multiword struct that is not safe for concurrent
// unsynchronized read/write under the Go memory model. The sweeper
// goroutine compared `e.lastSeen.Before(cutoff)` while request
// goroutines wrote `entry.lastSeen = now()`, which the race detector
// flags and which can produce torn reads in production. We now store
// the last-seen UnixNano in an atomic int64 and convert at use sites
// — the resulting limiter behaviour is unchanged but reads/writes
// are race-free.
type perIPLimiterEntry struct {
	limiter      *rate.Limiter
	lastSeenUnix atomic.Int64
}

// touch records a fresh last-seen timestamp on the entry. Callers
// should always touch through this method so the atomic write site
// is centralised.
func (e *perIPLimiterEntry) touch(t time.Time) {
	e.lastSeenUnix.Store(t.UnixNano())
}

// lastSeen returns the entry's last-seen wallclock timestamp.
func (e *perIPLimiterEntry) lastSeen() time.Time {
	return time.Unix(0, e.lastSeenUnix.Load())
}

// perIPRateLimiter returns an http.Handler middleware that throttles each
// remote IP with its own rate.Limiter (rps requests per second, burst burst
// tokens). Loopback callers bypass the limiter — the gateway's own hook
// scripts (claude-code-hook.sh / codex-hook.sh / inspect-*.sh) all loop
// through localhost and would otherwise self-throttle and stall the agent.
//
// Entries idle for >5 minutes are evicted, keeping memory bounded under
// sustained scans of the IPv4/IPv6 address space (the `sync.Map` plus
// rate.Limiter pair is ~200 bytes per IP). The eviction sweep is a runtime
// timer (time.AfterFunc) armed when the first entry is added and re-armed
// every minute only while entries remain, so idle entries expire whatever
// traffic follows (loopback only, or none) and a limiter without remote
// entries owns neither a goroutine nor a timer. A sweeper goroutine with its
// own ticker had no way to stop, so every APIServer route table built (each
// test server, each managed hook socket) leaked one (rel-1-0-6:GAP-0550).
//
// rps and burst are intentionally small for /api/v1/inspect/* — see plan
// F19/A2: a misbehaving / compromised local agent should never be able to
// blast the inspect path; legitimate hook callers send <1 req/s per agent.
func perIPRateLimiter(rps, burst int) func(http.Handler) http.Handler {
	return newPerIPLimiterSet(rps, burst, perIPLimiterOptions{}).middleware
}

// perIPLimiterOptions are the eviction knobs; zero values take the
// production defaults (tests shorten or fake them).
type perIPLimiterOptions struct {
	idleEviction  time.Duration
	sweepInterval time.Duration
	now           func() time.Time
	// schedule runs f once after d (time.AfterFunc).
	schedule func(d time.Duration, f func())
	// swept, when set, is told what each sweep evicted and kept.
	swept func(evicted, remaining int)
}

// perIPLimiterSet is the per-IP limiter map and its self-ending sweep.
type perIPLimiterSet struct {
	rps, burst int
	opts       perIPLimiterOptions
	limiters   sync.Map

	mu    sync.Mutex
	armed bool
}

func newPerIPLimiterSet(rps, burst int, opts perIPLimiterOptions) *perIPLimiterSet {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps
	}
	if opts.idleEviction <= 0 {
		opts.idleEviction = 5 * time.Minute
	}
	if opts.sweepInterval <= 0 {
		opts.sweepInterval = 1 * time.Minute
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.schedule == nil {
		opts.schedule = func(d time.Duration, f func()) { time.AfterFunc(d, f) }
	}
	return &perIPLimiterSet{rps: rps, burst: burst, opts: opts}
}

// arm schedules a sweep unless one is already pending.
func (s *perIPLimiterSet) arm() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.armed {
		s.armed = true
		s.opts.schedule(s.opts.sweepInterval, s.sweep)
	}
}

// sweep evicts idle entries and re-arms only while entries remain. An entry
// stored after the count below arms again through arm, which waits for mu.
func (s *perIPLimiterSet) sweep() {
	cutoff := s.opts.now().Add(-s.opts.idleEviction)
	evicted, remaining := 0, 0
	s.limiters.Range(func(k, v interface{}) bool {
		if e, ok := v.(*perIPLimiterEntry); ok && e.lastSeen().Before(cutoff) {
			s.limiters.Delete(k)
			evicted++
		} else {
			remaining++
		}
		return true
	})
	s.mu.Lock()
	if remaining == 0 {
		s.armed = false
	} else {
		s.opts.schedule(s.opts.sweepInterval, s.sweep)
	}
	s.mu.Unlock()
	if s.opts.swept != nil {
		s.opts.swept(evicted, remaining)
	}
}

func (s *perIPLimiterSet) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if connector.IsLoopback(r) {
			next.ServeHTTP(w, r)
			return
		}
		ip := clientIPForLimiter(r)
		if ip == "" {
			// Unparseable RemoteAddr — refuse rather than fail open;
			// caller can retry with a well-formed source.
			writeJSONRefusal(w, `{"error":"unparseable client address"}`, http.StatusForbidden)
			return
		}
		current := s.opts.now()
		fresh := &perIPLimiterEntry{limiter: rate.NewLimiter(rate.Limit(s.rps), s.burst)}
		fresh.touch(current)
		val, loaded := s.limiters.LoadOrStore(ip, fresh)
		if !loaded {
			s.arm()
		}
		entry := val.(*perIPLimiterEntry)
		entry.touch(current)
		if !entry.limiter.Allow() {
			writeJSONRefusal(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIPForLimiter extracts the bare IP (no port) from r.RemoteAddr.
// Returns "" on parse failure so the caller can fail closed rather than
// bucket every malformed request into a single limiter.
func clientIPForLimiter(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host == "" {
		return ""
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}
