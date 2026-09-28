// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestHookCallerLimiterBoundsEachCallerSeparately(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	limiter := &hookCallerLimiter{now: func() time.Time { return now }, rate: 2, burst: 2, inFlight: 3}
	admit := func(caller string) (func(), bool) {
		release, ok, _ := limiter.acquire(caller)
		return release, ok
	}
	for i := 0; i < 2; i++ {
		release, ok := admit("1001")
		if !ok {
			t.Fatalf("request %d inside the burst refused", i)
		}
		release()
	}
	if _, ok := admit("1001"); ok {
		t.Fatal("a caller past its burst was admitted")
	}
	if release, ok := admit("1002"); !ok {
		t.Fatal("another caller was limited by the first caller's burst")
	} else {
		release()
	}
	now = now.Add(time.Second)
	if release, ok := admit("1001"); !ok {
		t.Fatal("the caller's budget did not refill")
	} else {
		release()
	}

	// In-flight cap: requests that have not finished count against it.
	limiter = &hookCallerLimiter{now: func() time.Time { return now }, rate: 1000, burst: 1000, inFlight: 3}
	var releases []func()
	for i := 0; i < 3; i++ {
		release, ok := admit("1001")
		if !ok {
			t.Fatalf("in-flight request %d refused", i)
		}
		releases = append(releases, release)
	}
	if _, ok := admit("1001"); ok {
		t.Fatal("a caller past its in-flight cap was admitted")
	}
	if release, ok := admit("1002"); !ok {
		t.Fatal("another caller was limited by the first caller's in-flight requests")
	} else {
		release()
	}
	releases[0]()
	releases[0]() // release is idempotent
	if release, ok := admit("1001"); !ok {
		t.Fatal("a finished request did not free its in-flight slot")
	} else {
		release()
	}
	if got := limiter.callers["1001"].inFlight; got != 2 {
		t.Fatalf("in-flight count = %d, want 2", got)
	}
}

func TestAdmitHookCallerAnswersRateLimited(t *testing.T) {
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 1}
	first := httptest.NewRecorder()
	release := api.admitHookCaller(first, "1001", "/api/v1/inspect/tool", "/api/v1/inspect/tool")
	if release == nil {
		t.Fatal("first request refused")
	}
	release()
	refused := httptest.NewRecorder()
	if api.admitHookCaller(refused, "1001", "/api/v1/inspect/tool", "/api/v1/inspect/tool") != nil {
		t.Fatal("second request inside one second admitted")
	}
	if refused.Code != http.StatusTooManyRequests || refused.Header().Get("Retry-After") == "" ||
		!strings.Contains(refused.Body.String(), managedHookReasonRateLimited) {
		t.Fatalf("refusal = %d %v %q", refused.Code, refused.Header(), refused.Body.String())
	}
}

// A user's OTLP export has its own budget: a telemetry burst that uses up
// the export budget must not refuse that user's next hook request, which
// would deny the tool call.
func TestHookCallerTelemetryDoesNotUseTheHookBudget(t *testing.T) {
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 2}
	for _, path := range []string{"/v1/logs", "/v1/traces", "/otlp/codex/tok/v1/metrics"} {
		release := api.admitHookCaller(httptest.NewRecorder(), "1001", "otlp", path)
		if release != nil {
			release()
		}
	}
	refused := httptest.NewRecorder()
	if api.admitHookCaller(refused, "1001", "otlp", "/v1/logs") != nil {
		t.Fatal("premise: the telemetry burst used up the export budget")
	}
	for i := 0; i < 2; i++ {
		hook := httptest.NewRecorder()
		release := api.admitHookCaller(hook, "1001", "/api/v1/codex/hook", "/api/v1/codex/hook")
		if release == nil {
			t.Fatalf("hook request %d refused after a telemetry burst: %d %s", i, hook.Code, hook.Body.String())
		}
		release()
	}
	if got := hookCallerBudgetKey("1001", "/api/v1/inspect/tool"); got != "1001" {
		t.Fatalf("hook budget key = %q", got)
	}
}

// TestForeignHookSessionExchangesDoNotWaitOnOtherIdentities: each identity
// has its own session store, so an exchange in progress for one account must
// not hold up another account's exchange (whose hook denies when its bounded
// exchange deadline passes).
func TestForeignHookSessionExchangesDoNotWaitOnOtherIdentities(t *testing.T) {
	alice, bob := "1001", "1002"
	if runtime.GOOS == "windows" {
		alice, bob = "S-1-5-21-1111-2222-3333-1001", "S-1-5-21-1111-2222-3333-1002"
	}
	api, _, _ := newUserScopedTestServer(t, true, &userScopedTestLedger{}, nil)
	dataDir := api.configDataDir()
	if !filepath.IsAbs(dataDir) {
		t.Fatalf("test data dir %q is not absolute", dataDir)
	}
	exchange := func(identity string) <-chan int {
		done := make(chan int, 1)
		go func() {
			body, _ := json.Marshal(map[string]any{
				"key":           map[string]any{"connector": "claudecode", "session": "s-" + identity, "process": "p-" + identity},
				"session_start": true,
				"decision":      map[string]any{"deny": false},
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/foreign-hook-session/claudecode", bytes.NewReader(body))
			ctx := withAuthenticatedHookConnector(req.Context(), "claudecode")
			ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
			response := httptest.NewRecorder()
			api.handleForeignHookSession(response, req.WithContext(ctx))
			done <- response.Code
		}()
		return done
	}

	unlock := api.foreignHookSessionLocks.lock(foreignHookSessionStateDir(dataDir, alice))
	aliceDone := exchange(alice)
	select {
	case code := <-exchange(bob):
		if code != http.StatusOK {
			t.Fatalf("bob's exchange = %d", code)
		}
	case <-time.After(3 * time.Second):
		unlock()
		t.Fatal("bob's exchange waited on alice's session lock")
	}
	select {
	case code := <-aliceDone:
		unlock()
		t.Fatalf("alice's exchange ran while her own session store was locked (%d)", code)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	if code := <-aliceDone; code != http.StatusOK {
		t.Fatalf("alice's exchange = %d", code)
	}
}
