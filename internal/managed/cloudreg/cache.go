// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cloudreg

import (
	"context"
	"sync"
	"time"
)

// WithTokenCache decorates `inner` with an in-memory bearer-token cache so
// consumers that call Token() at a high cadence do not pay a fresh IPC
// round-trip to the underlying credential broker per call.
//
// Both currently-shipped Provider implementations (the Windows named-pipe
// ClientProvider in internal/managed/cmidbroker and the private macOS CMID
// daemon client registered from ai-common) make an IPC exchange on every
// Token() call — visible on macOS in the
// /Library/Logs/Cisco/SecureClient/CloudManagement/*_cmidapi.log dance per
// call — even though the tokens themselves live minutes to hours. Wrapping at
// the Provider level keeps a single caching layer for every consumer:
//
//   - the synchronous AI Defense inspect lane in
//     internal/gateway/cisco_inspect_defense_claw.go, called per hook
//     decision (hot path);
//   - the asynchronous managedaid POST in
//     internal/observability/destinations/managedaid, called per publish
//     batch;
//   - any future consumer of Sidecar.ensureCMIDProvider().
//
// TTL is the caller's choice. Set well inside the shortest expected token
// lifetime; typical bearer tokens live 5-15 minutes and 60s caching cuts the
// IPC dance rate 6-8x on a typical hook-decision hot path. A ttl <= 0
// disables caching and returns `inner` unchanged, which is useful for tests
// that need to observe every Token() invocation.
//
// Invalidation semantics:
//
//   - Invalidate() clears the cached value AND calls inner.Invalidate, so a
//     401-driven invalidation from a consumer (e.g.
//     doInspectHTTP.onUnauthorized in cisco_inspect_defense_claw.go, or the
//     managedaid remint path) forces the next Token() to re-fetch through
//     the broker.
//
//   - Refresh() calls inner.Refresh but does NOT clear the local cache.
//     Rationale: existing DefenseClaw code uses Refresh() as a cheap
//     availability probe against the broker's own state, not as a signal
//     that the caller has decided our current token is stale. Clearing the
//     cache on every Refresh would forcibly re-fetch on every availability
//     probe, defeating the point of caching. If a probe reveals the broker
//     has genuinely rotated the token underneath us, the next consumer call
//     will hit a 401 and drop the cache via Invalidate() — the authoritative
//     staleness signal.
//
// The wrapper is safe for concurrent Token() callers: readers hold a short
// lock only to inspect / update the cache. A concurrent cache-miss can
// result in overlapping inner.Token() calls — that is deliberately allowed
// because provider.Token is documented as thread-safe by every current
// implementation, and serializing under the wrapper's mutex would double
// the latency of the first miss on a cold start.
func WithTokenCache(inner Provider, ttl time.Duration) Provider {
	if inner == nil {
		return nil
	}
	if ttl <= 0 {
		return inner
	}
	return &cachingProvider{inner: inner, ttl: ttl}
}

type cachingProvider struct {
	inner Provider
	ttl   time.Duration

	mu sync.Mutex
	// generation is bumped on every Invalidate() call. A Token() miss
	// captures the current generation before releasing the lock to
	// fetch through inner.Token; the resulting token is stored back
	// into the cache only if the generation is unchanged at store
	// time. This closes the "restore invalidated token" race: an
	// in-flight fetch that started under generation N cannot repopulate
	// the cache after a concurrent Invalidate() bumped it to N+1.
	// Reported by CodeRabbit on PR #802.
	generation uint64
	token      string
	at         time.Time
}

func (c *cachingProvider) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Since(c.at) < c.ttl {
		cached := c.token
		c.mu.Unlock()
		return cached, nil
	}
	// Capture the generation so a concurrent Invalidate can invalidate
	// the value we're about to fetch — see cachingProvider.generation.
	generation := c.generation
	c.mu.Unlock()
	token, err := c.inner.Token(ctx)
	if err != nil || token == "" {
		return token, err
	}
	c.mu.Lock()
	if generation == c.generation {
		c.token = token
		c.at = time.Now()
	}
	// If generation drifted, the token we fetched is already
	// considered stale by the caller who invalidated. Return it to
	// this caller (they may still succeed with it — some brokers keep
	// old tokens live briefly) but do not pollute the cache. The 401
	// path will invalidate again if the token is truly rejected.
	c.mu.Unlock()
	return token, nil
}

func (c *cachingProvider) Refresh(ctx context.Context) error {
	// Deliberately does NOT touch the local cache. Refresh() is used by
	// Sidecar.ensureCMIDProvider as an availability probe; if we cleared
	// our cache here, every probe would force the next Token() to
	// re-fetch through the broker, which defeats the entire purpose of
	// wrapping the provider. If the broker rotated the token underneath
	// us during a probe, the next consumer request will observe a 401
	// and drop our cache via Invalidate() — the authoritative staleness
	// signal.
	return c.inner.Refresh(ctx)
}

func (c *cachingProvider) Invalidate() {
	// Hold the cache lock through inner.Invalidate so a concurrent
	// Token() miss cannot start fetching a stale token during the
	// broker-side invalidation window. Combined with the generation
	// counter above, this makes cache pollution impossible: any
	// in-flight fetch will observe the bumped generation on its
	// return-and-store path and skip the store; any new fetch is
	// blocked from starting until the invalidation completes.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.generation++
	c.token = ""
	c.at = time.Time{}
	c.inner.Invalidate()
}
