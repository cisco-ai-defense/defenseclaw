// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	bifrost "github.com/maximhq/bifrost/core"
	"github.com/maximhq/bifrost/core/schemas"
)

// rel-1-0-10:GAP-2141: the idle-tenant sweep (GAP-1760) shut down a client
// whose last request started bifrostTenantIdleTTL ago even when that request,
// a long stream, was still running, which cut the stream. A client with a
// request in flight is never idle; when its last request ends it counts as
// used then.
func TestIdleBifrostTenantSweepKeepsClientWithStreamInFlight(t *testing.T) {
	closeBifrostTenantsAfter(t)
	shutdowns := make(chan *bifrost.Bifrost, 4)
	originalShutdown := shutdownEvictedBifrostClient
	shutdownEvictedBifrostClient = func(c *bifrost.Bifrost) { shutdowns <- c }
	t.Cleanup(func() { shutdownEvictedBifrostClient = originalShutdown })

	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(oaChunk2233))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte(oaEnd2233))
	}))
	defer up.Close()
	const longKey = "sk-long-stream-tenant"
	prov, err := NewProviderWithBase("openai/gpt-5-mini", longKey, up.URL+"/v1")
	if err != nil {
		t.Fatal(err)
	}

	firstChunk := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		var once bool
		_, err := prov.ChatCompletionStream(context.Background(), &ChatRequest{Model: "gpt-5-mini", Stream: true, Messages: []ChatMessage{{Role: "user", Content: "hi"}}}, func(StreamChunk) {
			if !once {
				once = true
				close(firstChunk)
			}
		})
		done <- err
	}()
	select {
	case <-firstChunk:
	case <-time.After(10 * time.Second):
		close(release)
		t.Fatal("no first chunk from the stream")
	}

	// The stream started bifrostTenantIdleTTL ago and is still running.
	longID := bifrostKeyID(schemas.OpenAI, longKey)
	var longClient *bifrost.Bifrost
	bifrostTenantsMu.Lock()
	for k, e := range bifrostTenants {
		if k.keyID == longID {
			e.lastUsed = time.Now().Add(-2 * bifrostTenantIdleTTL)
			longClient = e.client
		}
	}
	bifrostTenantsMu.Unlock()
	if longClient == nil {
		close(release)
		t.Fatal("the stream's tenant client is not in the cache")
	}

	missAndCheck := func(apiKey, when string) {
		t.Helper()
		// A request for another tenant (a cache miss) runs the sweep.
		_, release, err := getBifrostClient(schemas.OpenAI, apiKey, "http://127.0.0.1:1", "gpt-x", tlsOverrides{}, nil, nil, nil, nil)
		if err != nil {
			t.Fatalf("getBifrostClient: %v", err)
		}
		release()
		select {
		case got := <-shutdowns:
			if got == longClient {
				t.Errorf("%s: the idle sweep shut down the client of the stream in flight", when)
			}
		case <-time.After(200 * time.Millisecond):
		}
	}
	missAndCheck("sk-other-tenant-1", "stream in flight")

	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream ended with %v, want a clean end", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the stream did not end")
	}
	// The stream just ended: the client was used now, not 2*TTL ago.
	missAndCheck("sk-other-tenant-2", "right after the stream ended")
}

// rel-1-0-10:GAP-2141: at the cap, the LRU eviction takes the oldest client
// with no request in flight, and a busy client only when every client is busy.
func TestEvictOldestBifrostTenantLockedSkipsBusyClients(t *testing.T) {
	bifrostTenantsMu.Lock()
	original := bifrostTenants
	bifrostTenants = make(map[tenantKey]*bifrostTenantEntry)
	bifrostTenantsMu.Unlock()
	t.Cleanup(func() {
		bifrostTenantsMu.Lock()
		bifrostTenants = original
		bifrostTenantsMu.Unlock()
	})
	base := time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)
	busyOld := tenantKey{provider: "openai", keyID: "busy-oldest"}
	idleMid := tenantKey{provider: "openai", keyID: "idle-mid"}
	idleNew := tenantKey{provider: "openai", keyID: "idle-newest"}
	bifrostTenantsMu.Lock()
	bifrostTenants[busyOld] = &bifrostTenantEntry{lastUsed: base, inFlight: 1}
	bifrostTenants[idleMid] = &bifrostTenantEntry{lastUsed: base.Add(time.Minute)}
	bifrostTenants[idleNew] = &bifrostTenantEntry{lastUsed: base.Add(2 * time.Minute)}
	evictOldestBifrostTenantLocked()
	_, busyKept := bifrostTenants[busyOld]
	_, midKept := bifrostTenants[idleMid]
	evictOldestBifrostTenantLocked()
	_, newKept := bifrostTenants[idleNew]
	evictOldestBifrostTenantLocked()
	left := len(bifrostTenants)
	bifrostTenantsMu.Unlock()
	if !busyKept || midKept || newKept || left != 0 {
		t.Fatalf("eviction order: busy kept after 1st=%v (want true), idle-mid kept=%v (want false), idle-newest kept after 2nd=%v (want false), left after 3rd=%d (want 0)", busyKept, midKept, newKept, left)
	}
}
