// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/google/uuid"
)

func TestGAP0490ReceiptIDsDoNotSerialize(t *testing.T) {
	var first string
	seen := map[uint32]string{}
	for i := 0; i < 4096; i++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		var hash uint32 = 2166136261
		for j := 0; j < len(id); j++ {
			hash = (hash ^ uint32(id[j])) * 16777619
		}
		stripe := hash % 1024
		if previous := seen[stripe]; previous != "" {
			first = previous
			seen[stripe] = id
			break
		}
		seen[stripe] = id
	}
	if first == "" {
		t.Fatal("fixture found no former-stripe collision")
	}
	var second string
	for _, id := range seen {
		if id != first {
			var hash uint32 = 2166136261
			for j := 0; j < len(id); j++ {
				hash = (hash ^ uint32(id[j])) * 16777619
			}
			var old uint32 = 2166136261
			for j := 0; j < len(first); j++ {
				old = (old ^ uint32(first[j])) * 16777619
			}
			if hash%1024 == old%1024 {
				second = id
				break
			}
		}
	}
	if second == "" {
		t.Fatal("fixture lost the collision")
	}
	unlockFirst := sandboxReceiptLocks.lock(first)
	defer unlockFirst()
	acquired := make(chan struct{})
	go func() {
		unlockSecond := sandboxReceiptLocks.lock(second)
		unlockSecond()
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("unrelated receipt waited behind another id")
	}
}

func TestGAP0490RetryAttachesToInFlight(t *testing.T) {
	binding := sandboxauth.Binding{ID: "g490-retry", Connector: "claudecode"}
	cache := newHookIdempotencyCache(time.Minute, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	h := cache.middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		close(entered)
		<-release
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	leader := httptest.NewRecorder()
	leaderDone := make(chan struct{})
	go func() {
		h.ServeHTTP(leader, gap0490RetryRequest(binding, sandboxauth.RouteHook, "g490-retry-key", `{}`))
		close(leaderDone)
	}()
	<-entered
	retry := httptest.NewRecorder()
	retryDone := make(chan bool, 1)
	go func() {
		retryDone <- cache.replayExisting(retry,
			gap0490RetryRequest(binding, sandboxauth.RouteHook, "g490-retry-key", `{}`),
			binding, sandboxauth.RouteHook)
	}()
	select {
	case <-retryDone:
		t.Fatal("retry returned before the in-flight answer")
	case <-time.After(20 * time.Millisecond):
	}
	wrong := httptest.NewRecorder()
	if !cache.replayExisting(wrong,
		gap0490RetryRequest(binding, sandboxauth.RouteHook, "g490-retry-key", `{"different":true}`),
		binding, sandboxauth.RouteHook) || wrong.Code != http.StatusUnprocessableEntity {
		t.Fatalf("different in-flight retry status=%d, want 422", wrong.Code)
	}
	close(release)
	<-leaderDone
	if !<-retryDone || retry.Code != http.StatusOK || retry.Body.String() != leader.Body.String() || calls.Load() != 1 {
		t.Fatalf("retry status=%d body=%q leader=%q calls=%d", retry.Code, retry.Body.String(), leader.Body.String(), calls.Load())
	}
	completed := httptest.NewRecorder()
	if cache.replayExisting(completed,
		gap0490RetryRequest(binding, sandboxauth.RouteHook, "g490-retry-key", `{}`),
		binding, sandboxauth.RouteHook) {
		t.Fatal("completed response skipped normal admission")
	}
}

func gap0490RetryRequest(binding sandboxauth.Binding, route sandboxauth.Route, key, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(body))
	req.Header.Set(SandboxHookIdempotencyHeader, key)
	ctx := sandboxauth.WithRequest(req.Context(), binding, nil)
	return req.WithContext(withSandboxIngressRoute(ctx, route))
}

// Each sandbox receipt window recovers its own journal row from a timer
// (scheduleSandboxHookReceiptRecovery), so rows of distinct receipts are
// recovered at the same time. Their per-row try counts are shared state: the
// race detector caught two timers forgetting settled rows at once in the
// 400-call capacity test (PR #1427 CI).
func TestGAP0490ConcurrentReceiptRecoveriesForgetTheirRows(t *testing.T) {
	f := newManagedHookAuditFixture(t, nil)
	const rows = 32
	entries := make([]audit.HookDeliveryJournalEntry, 0, rows)
	for i := 0; i < rows; i++ {
		p := &pendingHookOccurrence{
			ID:      uuid.NewString(),
			Request: pendingRequest(agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}),
			Settled: true,
			SandboxReceipt: &sandboxPendingHookReceipt{
				BindingID: "g490-recovery", OfferedAt: time.Now().Add(-2 * sandboxHookReceiptWindow),
			},
		}
		data, err := encodePendingHookOccurrence(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.store.JournalHookDelivery(t.Context(), p.ID, f.api.deliveryProcessID(), data, pendingHookJournalLimits); err != nil {
			t.Fatal(err)
		}
		entry, found, err := f.store.HookDelivery(t.Context(), p.ID)
		if err != nil || !found {
			t.Fatalf("journal row %s: found=%v err=%v", p.ID, found, err)
		}
		entries = append(entries, entry)
	}
	start := make(chan struct{})
	errs := make([]error, rows)
	var wg sync.WaitGroup
	for i, entry := range entries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = f.api.recoverPendingHook(t.Context(), entry)
		}()
	}
	close(start)
	wg.Wait()
	for i, entry := range entries {
		if errs[i] != nil {
			t.Errorf("recovery of %s: %v", entry.ID, errs[i])
		}
		if _, found, err := f.store.HookDelivery(t.Context(), entry.ID); err != nil || found {
			t.Errorf("settled row %s after its recovery: found=%v err=%v", entry.ID, found, err)
		}
	}
}
