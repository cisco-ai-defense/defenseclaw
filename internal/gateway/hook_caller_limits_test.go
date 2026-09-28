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

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestHookCallerLimiterBoundsEachCallerSeparately(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	limiter := &hookCallerLimiter{now: func() time.Time { return now }, rate: 2, burst: 2, inFlight: 3}
	admit := func(caller string) (func(), bool) {
		release, _, ok, _ := limiter.acquire(caller)
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
	_, release := api.admitHookCaller(first, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil), "1001", "/api/v1/inspect/tool")
	if release == nil {
		t.Fatal("first request refused")
	}
	release()
	refused := httptest.NewRecorder()
	if _, release := api.admitHookCaller(refused, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", nil), "1001", "/api/v1/inspect/tool"); release != nil {
		t.Fatal("second request inside one second admitted")
	}
	if refused.Code != http.StatusTooManyRequests || refused.Header().Get("Retry-After") == "" ||
		!strings.Contains(refused.Body.String(), managedHookReasonRateLimited) {
		t.Fatalf("refusal = %d %v %q", refused.Code, refused.Header(), refused.Body.String())
	}
}

// A flood could run up to its in-flight cap at once, and another account's
// hook shared the CPU with all of those requests. A caller now runs only as
// many requests as it has run slots; the rest wait for its own slot, while
// another caller's request starts at once.
func TestAdmitHookCallerRunsACallersRequestsInItsOwnSlots(t *testing.T) {
	const route = "/api/v1/inspect/tool"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, running: 1}
	admit := func(identity string, r *http.Request) func() {
		_, release := api.admitHookCaller(httptest.NewRecorder(), r, identity, route)
		return release
	}
	request := func() *http.Request { return httptest.NewRequest(http.MethodPost, route, nil) }
	first := admit("1001", request())
	if first == nil {
		t.Fatal("first request refused")
	}
	started := make(chan func(), 1)
	go func() { started <- admit("1001", request()) }()
	other := admit("1002", request())
	if other == nil {
		t.Fatal("another caller's request was refused")
	}
	other()
	select {
	case <-started:
		t.Fatal("the caller's second request ran beside its first")
	case <-time.After(100 * time.Millisecond):
	}
	first()
	select {
	case second := <-started:
		if second == nil {
			t.Fatal("the caller's waiting request was refused")
		}
		second()
	case <-time.After(5 * time.Second):
		t.Fatal("the caller's waiting request did not start when its first finished")
	}

	// A request waiting on Cisco AI Defense uses no gateway CPU, so the
	// caller's next request runs meanwhile instead of waiting out that round
	// trip, and the scan takes a slot back when AI Defense answers.
	aid := heldAIDInspector{called: make(chan struct{}), reply: make(chan struct{})}
	api.scannerCfg, api.ciscoInspector = &config.Config{}, aid
	serve := func(handler http.HandlerFunc) chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			api.serveUserScoped(httptest.NewRecorder(), request(), route, "1001", handler, nil)
		}()
		return done
	}
	scanned := serve(func(_ http.ResponseWriter, r *http.Request) { api.hookAIDInspect(r.Context(), "Bash", "ls") })
	<-aid.called
	next := serve(func(http.ResponseWriter, *http.Request) {})
	select {
	case <-next:
	case <-time.After(5 * time.Second):
		close(aid.reply)
		t.Fatal("the caller's next request waited for another request's AI Defense answer")
	}
	close(aid.reply)
	select {
	case <-scanned:
	case <-time.After(5 * time.Second):
		t.Fatal("the scanned request did not finish after AI Defense answered")
	}
	if budget := api.hookCallerLimits.callers["1001"]; budget.inFlight != 0 || len(budget.running) != 0 {
		t.Fatalf("in-flight = %d, running = %d, want 0 and 0", budget.inFlight, len(budget.running))
	}
}

// heldAIDInspector answers an AI Defense inspection once reply is closed.
type heldAIDInspector struct{ called, reply chan struct{} }

func (h heldAIDInspector) Inspect(context.Context, []ChatMessage) *ScanVerdict {
	h.called <- struct{}{}
	<-h.reply
	return nil
}

func (heldAIDInspector) bindObservabilityV8(hookLifecycleMetricV8Runtime) {}

// A user's OTLP export has its own budget: a telemetry burst that uses up
// the export budget must not refuse that user's next hook request, which
// would deny the tool call.
func TestHookCallerTelemetryDoesNotUseTheHookBudget(t *testing.T) {
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1, burst: 2}
	for _, path := range []string{"/v1/logs", "/v1/traces", "/otlp/codex/tok/v1/metrics"} {
		_, release := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil), "1001", "otlp")
		if release != nil {
			release()
		}
	}
	refused := httptest.NewRecorder()
	if _, release := api.admitHookCaller(refused, httptest.NewRequest(http.MethodPost, "/v1/logs", nil), "1001", "otlp"); release != nil {
		t.Fatal("premise: the telemetry burst used up the export budget")
	}
	for i := 0; i < 2; i++ {
		hook := httptest.NewRecorder()
		_, release := api.admitHookCaller(hook, httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", nil), "1001", "/api/v1/codex/hook")
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
