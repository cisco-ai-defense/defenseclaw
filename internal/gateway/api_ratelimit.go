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
	"time"

	"golang.org/x/time/rate"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// perIPLimiterEntry pairs a token-bucket limiter with the timestamp of the
// last request seen from that IP, so the eviction sweep can drop stale
// entries without locking the entire map for the duration of the scan.
type perIPLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// perIPRateLimiter returns an http.Handler middleware that throttles each
// remote IP with its own rate.Limiter (rps requests per second, burst burst
// tokens). Loopback callers bypass the limiter — the gateway's own hook
// scripts (claude-code-hook.sh / codex-hook.sh / inspect-*.sh) all loop
// through localhost and would otherwise self-throttle and stall the agent.
//
// The map of per-IP limiters is swept periodically (every minute) to evict
// entries idle for >5 minutes, keeping memory bounded under sustained
// scans of the IPv4/IPv6 address space (the `sync.Map` plus rate.Limiter
// pair is ~200 bytes per IP).
//
// rps and burst are intentionally small for /api/v1/inspect/* — see plan
// F19/A2: a misbehaving / compromised local agent should never be able to
// blast the inspect path; legitimate hook callers send <1 req/s per agent.
func perIPRateLimiter(rps, burst int) func(http.Handler) http.Handler {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = rps
	}
	limiters := &sync.Map{}
	now := func() time.Time { return time.Now() }
	const idleEviction = 5 * time.Minute
	const sweepInterval = 1 * time.Minute

	go func() {
		ticker := time.NewTicker(sweepInterval)
		defer ticker.Stop()
		for range ticker.C {
			cutoff := now().Add(-idleEviction)
			limiters.Range(func(k, v interface{}) bool {
				if e, ok := v.(*perIPLimiterEntry); ok && e.lastSeen.Before(cutoff) {
					limiters.Delete(k)
				}
				return true
			})
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if connector.IsLoopback(r) {
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIPForLimiter(r)
			if ip == "" {
				// Unparseable RemoteAddr — refuse rather than fail open;
				// caller can retry with a well-formed source.
				http.Error(w, `{"error":"unparseable client address"}`, http.StatusForbidden)
				return
			}
			val, _ := limiters.LoadOrStore(ip, &perIPLimiterEntry{
				limiter:  rate.NewLimiter(rate.Limit(rps), burst),
				lastSeen: now(),
			})
			entry := val.(*perIPLimiterEntry)
			entry.lastSeen = now()
			if !entry.limiter.Allow() {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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
