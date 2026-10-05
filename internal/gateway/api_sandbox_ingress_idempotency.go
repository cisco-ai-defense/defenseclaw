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
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

const (
	// maxIdempotencyEntriesPerBinding and maxIdempotencyEntries bound the
	// replay cache; a hook retry arrives within seconds, so a few hundred
	// recent keys per sandbox is ample.
	maxIdempotencyEntriesPerBinding = 256
	maxIdempotencyEntries           = 4096
	// maxIdempotentResponseBytes is the largest response kept for replay.
	// Hook verdicts are small JSON documents; anything larger is served but
	// not cached, so a retry re-evaluates.
	maxIdempotentResponseBytes = 256 << 10
)

// idempotencyKeyPattern admits UUIDs, ULIDs and similar opaque keys.
var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)

// idempotencyFingerprintHeaders are the request headers that change how a
// hook is evaluated. They are part of the fingerprint so a key can only
// replay the exact request it was first used with.
var idempotencyFingerprintHeaders = []string{
	"X-DefenseClaw-Hook-Event",
	"X-DefenseClaw-Hook-Contract",
	"X-DefenseClaw-Antigravity-Event",
	"X-DefenseClaw-Copilot-Event",
	"X-DefenseClaw-Kiro-Surface",
	"Content-Type",
}

// hookIdempotencyCache deduplicates retried sandbox hook posts per binding.
// The first request with a key evaluates; a concurrent or later retry with
// the same key and the same request fingerprint receives the first
// response; the same key with a different request is refused, so a key can
// never launder one verdict onto another tool call.
type hookIdempotencyCache struct {
	ttl time.Duration
	now func() time.Time

	mu      sync.Mutex
	entries map[idempotencyKey]*idempotencyEntry
	count   map[string]int
}

type idempotencyKey struct {
	binding string
	key     string
}

type idempotencyEntry struct {
	fingerprint [sha256.Size]byte
	created     time.Time
	done        chan struct{}

	// Set once done is closed.
	cached      bool
	expires     time.Time
	status      int
	contentType string
	body        []byte
}

func newHookIdempotencyCache(ttl time.Duration, now func() time.Time) *hookIdempotencyCache {
	if now == nil {
		now = time.Now
	}
	return &hookIdempotencyCache{
		ttl:     ttl,
		now:     now,
		entries: make(map[idempotencyKey]*idempotencyEntry),
		count:   make(map[string]int),
	}
}

var errIdempotencyKeyReused = errors.New("idempotency key reused for a different request")

// middleware applies the cache to hook and notify posts that carry a key.
func (c *hookIdempotencyCache) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get(SandboxHookIdempotencyHeader)
		route, _ := sandboxIngressRouteFrom(r.Context())
		binding, sandboxed := sandboxauth.FromContext(r.Context())
		if key == "" || !sandboxed || r.Method != http.MethodPost ||
			(route != sandboxauth.RouteHook && route != sandboxauth.RouteNotify) {
			next.ServeHTTP(w, r)
			return
		}
		if !idempotencyKeyPattern.MatchString(key) {
			writeSandboxIngressError(w, http.StatusBadRequest, "malformed "+SandboxHookIdempotencyHeader)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxBytes *http.MaxBytesError
			if errors.As(err, &maxBytes) {
				writeSandboxIngressError(w, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			writeSandboxIngressError(w, http.StatusBadRequest, "unreadable request body")
			return
		}
		_ = r.Body.Close()
		fingerprint := idempotencyFingerprint(r, body)
		id := idempotencyKey{binding: binding.ID, key: key}
		for {
			entry, leader, err := c.begin(id, fingerprint)
			if err != nil {
				writeSandboxIngressError(w, http.StatusUnprocessableEntity, err.Error())
				return
			}
			if leader {
				r.Body = io.NopCloser(bytes.NewReader(body))
				recorder := &idempotencyRecorder{ResponseWriter: w, status: http.StatusOK}
				defer func() {
					// A panic must not strand followers on an open entry.
					if recovered := recover(); recovered != nil {
						c.finish(id, entry, nil)
						panic(recovered)
					}
				}()
				next.ServeHTTP(recorder, r)
				c.finish(id, entry, recorder)
				return
			}
			select {
			case <-entry.done:
			case <-r.Context().Done():
				writeSandboxIngressError(w, http.StatusServiceUnavailable, "request cancelled")
				return
			}
			if entry.cached {
				replayIdempotentResponse(w, entry)
				return
			}
			// The first attempt produced nothing replayable (a server error
			// or an oversized body); evaluate this retry afresh.
		}
	})
}

// begin returns the entry for id. leader is true when the caller must run
// the request and finish the entry.
func (c *hookIdempotencyCache) begin(id idempotencyKey, fingerprint [sha256.Size]byte) (*idempotencyEntry, bool, error) {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[id]; ok {
		expired := entry.isDone() && (!entry.cached || !now.Before(entry.expires))
		if !expired {
			if entry.fingerprint != fingerprint {
				return nil, false, errIdempotencyKeyReused
			}
			return entry, false, nil
		}
		c.removeLocked(id)
	}
	entry := &idempotencyEntry{fingerprint: fingerprint, created: now, done: make(chan struct{})}
	if c.makeRoomLocked(id.binding, now) {
		c.entries[id] = entry
		c.count[id.binding]++
	}
	// Without room the request still runs; it simply is not replayable.
	return entry, true, nil
}

// finish publishes the leader's response and releases followers.
func (c *hookIdempotencyCache) finish(id idempotencyKey, entry *idempotencyEntry, rec *idempotencyRecorder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry.isDone() {
		return
	}
	if rec != nil && rec.cacheable() {
		entry.cached = true
		entry.status = rec.status
		entry.contentType = rec.Header().Get("Content-Type")
		entry.body = slices.Clone(rec.body.Bytes())
		entry.expires = c.now().Add(c.ttl)
	} else if current, ok := c.entries[id]; ok && current == entry {
		c.removeLocked(id)
	}
	close(entry.done)
}

func (c *hookIdempotencyCache) forget(bindingID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, entry := range c.entries {
		if id.binding == bindingID && entry.isDone() {
			c.removeLocked(id)
		}
	}
}

// makeRoomLocked evicts expired entries, then the oldest completed entry of
// the binding (or of the whole cache) when a bound is reached. It reports
// whether a new entry fits.
func (c *hookIdempotencyCache) makeRoomLocked(bindingID string, now time.Time) bool {
	if c.count[bindingID] < maxIdempotencyEntriesPerBinding && len(c.entries) < maxIdempotencyEntries {
		return true
	}
	for id, entry := range c.entries {
		if entry.isDone() && (!entry.cached || !now.Before(entry.expires)) {
			c.removeLocked(id)
		}
	}
	for c.count[bindingID] >= maxIdempotencyEntriesPerBinding {
		if !c.evictOldestLocked(func(id idempotencyKey) bool { return id.binding == bindingID }) {
			return false
		}
	}
	for len(c.entries) >= maxIdempotencyEntries {
		if !c.evictOldestLocked(func(idempotencyKey) bool { return true }) {
			return false
		}
	}
	return true
}

func (c *hookIdempotencyCache) evictOldestLocked(match func(idempotencyKey) bool) bool {
	var (
		oldest   idempotencyKey
		oldestAt time.Time
		found    bool
	)
	for id, entry := range c.entries {
		if !match(id) || !entry.isDone() {
			continue
		}
		if !found || entry.created.Before(oldestAt) {
			oldest, oldestAt, found = id, entry.created, true
		}
	}
	if found {
		c.removeLocked(oldest)
	}
	return found
}

func (c *hookIdempotencyCache) removeLocked(id idempotencyKey) {
	if _, ok := c.entries[id]; !ok {
		return
	}
	delete(c.entries, id)
	if c.count[id.binding]--; c.count[id.binding] <= 0 {
		delete(c.count, id.binding)
	}
}

func (e *idempotencyEntry) isDone() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func idempotencyFingerprint(r *http.Request, body []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = io.WriteString(h, r.Method+"\x00"+r.URL.Path+"\x00")
	for _, name := range idempotencyFingerprintHeaders {
		_, _ = io.WriteString(h, name+"="+strings.Join(r.Header.Values(name), ",")+"\x00")
	}
	_, _ = h.Write(body)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func replayIdempotentResponse(w http.ResponseWriter, entry *idempotencyEntry) {
	if entry.contentType != "" {
		w.Header().Set("Content-Type", entry.contentType)
	}
	w.Header().Set(sandboxIdempotentReplayHeader, "true")
	w.WriteHeader(entry.status)
	_, _ = w.Write(entry.body)
}

// idempotencyRecorder forwards the response and keeps a bounded copy.
type idempotencyRecorder struct {
	http.ResponseWriter
	status   int
	wrote    bool
	body     bytes.Buffer
	overflow bool
}

func (r *idempotencyRecorder) WriteHeader(status int) {
	if !r.wrote {
		r.status = status
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *idempotencyRecorder) Write(p []byte) (int, error) {
	r.wrote = true
	if !r.overflow {
		if r.body.Len()+len(p) > maxIdempotentResponseBytes {
			r.overflow = true
			r.body.Reset()
		} else {
			r.body.Write(p)
		}
	}
	return r.ResponseWriter.Write(p)
}

func (r *idempotencyRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// cacheable keeps verdicts and client errors, which a retry would only
// repeat, and drops server errors and throttling, which a retry may clear.
func (r *idempotencyRecorder) cacheable() bool {
	return !r.overflow && r.status < http.StatusInternalServerError && r.status != http.StatusTooManyRequests
}
