// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestHookCallerLimiterBoundsEachCallerSeparately(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	limiter := &hookCallerLimiter{now: func() time.Time { return now }, rate: 2, burst: 2, inFlight: 3}
	admit := func(caller string) (func(), bool) {
		release, _, refusal, _ := limiter.acquire(caller)
		return release, refusal == ""
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

func TestHookCallerLimiterReservesGlobalCapacityForOtherAccounts(t *testing.T) {
	limiter := &hookCallerLimiter{rate: 1000, burst: 1000, inFlight: 32, globalInFlight: 32}
	var releases []func()
	for i := 0; i < 8; i++ {
		release, _, refusal, _ := limiter.acquire("1001")
		if refusal != "" {
			t.Fatalf("first caller request %d refused: %s", i, refusal)
		}
		releases = append(releases, release)
	}
	if release, _, refusal, _ := limiter.acquire("1001"); release != nil || refusal == "" {
		t.Fatal("one caller consumed more than its fair share of the global bound")
	}
	if release, _, refusal, _ := limiter.acquire("1002"); refusal != "" {
		t.Fatalf("second caller starved: %s", refusal)
	} else {
		release()
	}
	for _, release := range releases {
		release()
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

// 200 accounts under their own caps can still hold more requests than the
// gateway answers before the hook deadline, and then every hook times out. The
// gateway also bounds the requests it holds at once: the next one gets an
// immediate 429 with its own reason whoever sends it, and a finished request
// frees a place. A client that left before it had a slot costs nothing.
func TestAdmitHookCallerBoundsAllCallersTogether(t *testing.T) {
	const route = "/api/v1/inspect/tool"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, globalInFlight: 2}
	admit := func(identity string) (*httptest.ResponseRecorder, func()) {
		w := httptest.NewRecorder()
		_, release := api.admitHookCaller(w, httptest.NewRequest(http.MethodPost, route, nil), identity, route)
		return w, release
	}
	_, first := admit("1001")
	_, second := admit("1002")
	if first == nil || second == nil {
		t.Fatal("requests inside the gateway-wide bound were refused")
	}
	refused, third := admit("1003")
	if third != nil || refused.Code != http.StatusTooManyRequests || refused.Header().Get("Retry-After") == "" ||
		!strings.Contains(refused.Body.String(), managedHookReasonOverloaded) {
		t.Fatalf("request past the bound = %d %v %q", refused.Code, refused.Header(), refused.Body.String())
	}
	first()
	_, again := admit("1003")
	if again == nil {
		t.Fatal("a finished request did not free its place")
	}
	again()
	second()

	gone, hangUp := context.WithCancel(t.Context())
	hangUp()
	if _, release := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, route, nil).WithContext(gone), "1004", route); release != nil {
		t.Fatal("a request whose client had left was admitted")
	}
	if got := api.hookCallerLimits.total; got != 0 {
		t.Fatalf("%d requests still counted after all finished", got)
	}
}

// A timed-out hook can keep auditing for its bounded completion grace. Its
// admission must be returned when the client leaves, so later hooks are not
// refused for the entire grace period.
func TestTimedOutHookReleasesAdmissionBeforeAuditCompletes(t *testing.T) {
	const path = "/api/v1/claude-code/hook"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, globalInFlight: 1}
	ctx, cancel := context.WithCancel(t.Context())
	_, first := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil).WithContext(ctx), "1001", path)
	if first == nil {
		t.Fatal("first hook refused")
	}
	defer first()
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		api.hookCallerLimits.mu.Lock()
		total := api.hookCallerLimits.total
		api.hookCallerLimits.mu.Unlock()
		if total == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed-out hook kept its admission while its handler remained active")
		}
		time.Sleep(time.Millisecond)
	}
	_, next := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, path, nil), "1001", path)
	if next == nil {
		t.Fatal("next hook refused after the previous client's deadline")
	}
	next()
}

// OTLP exporters share the host bound, with half of it reserved for hooks.
func TestOTLPBatchesShareHostAdmissionBound(t *testing.T) {
	limiter := &hookCallerLimiter{rate: 1000, burst: 1000, globalInFlight: 4}
	first, _, refusal, _ := limiter.acquire("1001" + hookCallerTelemetryBudget)
	if refusal != "" {
		t.Fatalf("first OTLP batch refused: %s", refusal)
	}
	second, _, refusal, _ := limiter.acquire("1002" + hookCallerTelemetryBudget)
	if refusal != "" {
		t.Fatalf("second OTLP batch refused: %s", refusal)
	}
	if release, _, refusal, _ := limiter.acquire("1003" + hookCallerTelemetryBudget); release != nil || refusal != managedHookReasonOverloaded {
		t.Fatalf("OTLP batch over host reserve: release=%v refusal=%s", release != nil, refusal)
	}
	hook, _, refusal, _ := limiter.acquire("1003")
	if refusal != "" {
		t.Fatalf("hook lost reserved capacity: %s", refusal)
	}
	hook()
	first()
	second()
	if limiter.total != 0 || limiter.telemetryTotal != 0 {
		t.Fatalf("admission counts after release = %d, %d", limiter.total, limiter.telemetryTotal)
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
	// trip, and the scan takes a slot back when AI Defense answers. Both
	// senders, the text form and the tool call, give the slot up.
	serve := func(handler http.HandlerFunc) chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			api.serveUserScoped(httptest.NewRecorder(), request(), route, "1001", handler, nil)
		}()
		return done
	}
	for _, scan := range []struct {
		name string
		run  func(context.Context)
	}{
		{"text", func(ctx context.Context) { api.hookAIDInspect(ctx, "Bash", "ls") }},
		{"tool call", func(ctx context.Context) {
			args := `{"command":"ls"}`
			api.hookAIDInspectToolCall(ctx, aidToolCall{Name: "Bash", Args: json.RawMessage(args)}, args)
		}},
	} {
		aid := heldAIDInspector{called: make(chan struct{}), reply: make(chan struct{})}
		api.scannerCfg, api.ciscoInspector = &config.Config{}, aid
		scanned := serve(func(_ http.ResponseWriter, r *http.Request) { scan.run(r.Context()) })
		<-aid.called
		next := serve(func(http.ResponseWriter, *http.Request) {})
		select {
		case <-next:
		case <-time.After(5 * time.Second):
			close(aid.reply)
			t.Fatalf("%s: the caller's next request waited for another request's AI Defense answer", scan.name)
		}
		close(aid.reply)
		select {
		case <-scanned:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the scanned request did not finish after AI Defense answered", scan.name)
		}
		if budget := api.hookCallerLimits.callers["1001"]; budget.inFlight != 0 || len(budget.running) != 0 {
			t.Fatalf("%s: in-flight = %d, running = %d, want 0 and 0", scan.name, budget.inFlight, len(budget.running))
		}
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
	guardianDir := t.TempDir()
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, guardianDir)
	previous := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = previous })
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
			response := newDeadlineRecorder()
			api.handleForeignHookSession(response, req.WithContext(ctx))
			done <- response.Code
		}()
		return done
	}

	unlock := api.foreignHookSessionLocks.lock(enterprisepolicy.ForeignHookSessionStoreDir(dataDir, alice))
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

// GAP-0186: a managed flood of one account at 10 hook calls a second was
// refused with enterprise_managed_rate_limited once each call took 6-7 s:
// the calls held the caller's in-flight slots far past the rate budget.
// GAP-1790: on a host of two processors the caller held only 8, so 10 calls
// a second answered in 1 to 3 s under CPU load, inside the 3.5 s answer
// budget, were refused. None of those is refused now; the in-flight bound
// still refuses a caller whose calls each take longer than the budget.
func TestHookCallerLimiterAdmitsTenCallsASecondOfOneAccount(t *testing.T) {
	flood := func(service time.Duration) (refused int) {
		now := time.Unix(4_000_000, 0)
		// The global minimum, as on a host of two processors.
		limiter := &hookCallerLimiter{now: func() time.Time { return now }, globalInFlight: hookGlobalInFlightMin}
		type held struct {
			until   time.Time
			release func()
		}
		var running []held
		for call := range 600 {
			now = time.Unix(4_000_000, 0).Add(time.Duration(call) * 50 * time.Millisecond)
			kept := running[:0]
			for _, request := range running {
				if request.until.After(now) {
					kept = append(kept, request)
				} else {
					request.release()
				}
			}
			running = kept
			release, _, refusal, _ := limiter.acquire("1001")
			if refusal != "" {
				refused++
				continue
			}
			running = append(running, held{until: now.Add(service), release: release})
		}
		return refused
	}
	for _, service := range []time.Duration{40 * time.Millisecond, 500 * time.Millisecond, time.Second, 3 * time.Second} {
		if refused := flood(service); refused != 0 {
			t.Fatalf("20 calls a second taking %s each: %d of 600 refused, want 0", service, refused)
		}
	}
	if refused := flood(4 * time.Second); refused == 0 {
		t.Fatal("20 calls a second taking 4 s each were all admitted; the in-flight bound did not apply")
	}
}

// GAP-1693: a burst of an operator's read-only sandbox CLI reads is not
// refused; the sandbox policy writes keep their own small budget. The reads
// include the views a POST asks (policy explain, policy test): a few
// back-to-back `sandbox policy explain` calls were refused (es:GAP-0023).
func TestSandboxCLIReadBurstIsNotThrottled(t *testing.T) {
	api := &APIServer{}
	for i := range 40 {
		for _, read := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/sandbox/policy/packs"},
			{http.MethodPost, "/api/v1/sandbox/policy/explain"},
			{http.MethodPost, "/api/v1/sandbox/policy/test"},
		} {
			rec := httptest.NewRecorder()
			_, release := api.admitHookCaller(rec, httptest.NewRequest(read.method, read.path, nil), "1001", read.path)
			if release == nil {
				t.Fatalf("%s %s %d of a sandbox CLI burst refused: %d %s", read.method, read.path, i, rec.Code, rec.Body.String())
			}
			release()
		}
	}
	refused := false
	for range 40 {
		rec := httptest.NewRecorder()
		_, release := api.admitHookCaller(rec,
			httptest.NewRequest(http.MethodPost, "/api/v1/sandbox/decisions", nil), "1001", "/api/v1/sandbox/decisions")
		if release == nil {
			refused = true
			break
		}
		release()
	}
	if !refused {
		t.Fatal("sandbox policy writes lost their budget")
	}
}

// Once a request has offered its answer, what it still does (wait for the
// delivery receipt, write the call's audit rows) must not take a run slot
// back from the caller's next hook. With one slot (a host of two or three
// processors) and slow audit writes (a cold page cache on a large store),
// every new hook of a 10 calls a second load queued behind the previous
// calls' audit writes and was blocked as a gateway no-answer (GAP-1790).
func TestAnsweredRequestDoesNotTakeTheRunSlotBackFromTheNextHook(t *testing.T) {
	const route = "/api/v1/claude-code/hook"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, running: 1}
	request := func() *http.Request { return httptest.NewRequest(http.MethodPost, route, nil) }
	answered, releaseAnswered := api.admitHookCaller(httptest.NewRecorder(), request(), "1001", route)
	if releaseAnswered == nil {
		t.Fatal("first request refused")
	}
	next := make(chan func(), 1)
	go func() {
		_, release := api.admitHookCaller(httptest.NewRecorder(), request(), "1001", route)
		next <- release
	}()
	select {
	case <-next:
		t.Fatal("the caller's second request ran beside its first before the first answered")
	case <-time.After(100 * time.Millisecond):
	}

	// The first request offers its answer: the next hook starts.
	resume := pauseHookRunSlot(answered.Context())
	var releaseNext func()
	select {
	case releaseNext = <-next:
		if releaseNext == nil {
			t.Fatal("the caller's next request was refused")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the next hook did not start when the first request offered its answer")
	}

	// The answered request goes on to its audit writes while the next hook
	// still runs: it neither waits for nor takes that hook's slot.
	resumed := make(chan struct{})
	go func() {
		resume()
		close(resumed)
	}()
	select {
	case <-resumed:
	case <-time.After(2 * time.Second):
		releaseNext()
		t.Fatal("the answered request waited for the next hook's run slot before its audit writes")
	}
	budget := api.hookCallerLimits.callers["1001"]
	if got := len(budget.running); got != 1 {
		t.Fatalf("running = %d while the next hook runs, want 1 (its own slot only)", got)
	}
	releaseAnswered()
	releaseNext()
	if budget.inFlight != 0 || len(budget.running) != 0 {
		t.Fatalf("in-flight = %d, running = %d, want 0 and 0", budget.inFlight, len(budget.running))
	}
}

// GAP-0050: the calls of one parallel tool turn whose sessions the gateway
// has not seen all wait for their session starts at the same time. A call
// that waits for its start uses no gateway CPU, so it is parked and does not
// hold back the turn's next calls at the caller's in-flight cap; before,
// those were refused until the first calls' arrival wait ended, then paid
// their own, and a 60-way turn ran past the managed answer budget. Parking
// stays bounded: the caller's parked calls never exceed its in-flight cap.
func TestCallsWaitingForTheirSessionStartsDoNotHoldBackTheTurnsOtherCalls(t *testing.T) {
	const route = "/api/v1/inspect/tool"
	api := &APIServer{}
	api.hookCallerLimits = hookCallerLimiter{rate: 1000, burst: 1000, inFlight: 2, running: 4}
	gate := &sessionStartGate{}
	allowed := func(context.Context) (bool, string) { return false, "" }
	sessions := []string{"s0", "s1", "s2", "s3", "s4"}
	waiting := make(chan struct{}, len(sessions))
	var wg sync.WaitGroup
	call := func(i int) bool {
		r, release := api.admitHookCaller(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, route, nil), "1001", route)
		if release == nil {
			return false
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer release()
			waiting <- struct{}{}
			if reason, refused := gate.await(r.Context(), "claudecode\x00user:1001\x00"+sessions[i], 5*time.Second,
				400*time.Millisecond, allowed); refused {
				t.Errorf("call %d refused: %q", i, reason)
			}
		}()
		return true
	}
	for i := range 2 {
		if !call(i) {
			t.Fatalf("call %d of the turn was refused inside the caller's in-flight cap", i)
		}
	}
	<-waiting
	<-waiting
	admitted := 0
	for next, deadline := 2, time.Now().Add(300*time.Millisecond); next < 4 && time.Now().Before(deadline); {
		if call(next) {
			next++
			admitted++
			continue
		}
		time.Sleep(5 * time.Millisecond)
	}
	if admitted != 2 {
		wg.Wait()
		t.Fatalf("admitted %d of the turn's next 2 calls while its first 2 waited for their session starts, want 2", admitted)
	}
	if call(4) {
		t.Error("a fifth call was admitted past the caller's in-flight and parked bounds")
	}
	wg.Wait()
	limits := &api.hookCallerLimits
	limits.mu.Lock()
	defer limits.mu.Unlock()
	if budget := limits.callers["1001"]; budget.inFlight != 0 || len(budget.running) != 0 || limits.total != 0 {
		t.Fatalf("after the turn in-flight = %d, running = %d, total = %d, want 0", budget.inFlight, len(budget.running), limits.total)
	}
}

// A relayed hook's delivery receipt confirms an answer the sandbox-hook class
// already admitted, so it is counted in a class of its own: an account's
// tool calls spend the hook budget once each, and a run of calls never
// refuses (or queues behind evaluations) the receipt of an answer already
// given (rel-1-0-6 GAP-0490). The handler reads the body as sent.
func TestSandboxHookReceiptsHaveTheirOwnBudget(t *testing.T) {
	prev := sandboxBudgetLimits[sandboxBudgetHook]
	sandboxBudgetLimits[sandboxBudgetHook] = sandboxBudgetLimit{Rate: 1, Burst: 2, InFlight: 8}
	t.Cleanup(func() { sandboxBudgetLimits[sandboxBudgetHook] = prev })
	api := &APIServer{}
	path := sandboxrelay.PathHookPrefix + "claudecode"
	post := func(body string, receipt ...bool) (*httptest.ResponseRecorder, *http.Request, func()) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if len(receipt) != 0 && receipt[0] {
			r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		r, release := api.admitHookCaller(w, r, "1001", path)
		return w, r, release
	}
	event := `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`
	receipt := `{"delivery_receipt":"3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b","result":"ack"}`
	for i := 0; i < 2; i++ {
		if w, r, release := post(event); release == nil {
			t.Fatalf("hook %d refused early: %d", i, w.Code)
		} else {
			if err := chargeSandboxHookBudget(r.Context(), false); err != nil {
				t.Fatalf("hook %d refused after classification: %v", i, err)
			}
			release()
		}
	}
	w, r, release := post(receipt, true)
	if release == nil {
		t.Fatalf("the receipt of an admitted call was refused: %d %s", w.Code, w.Body.String())
	}
	got, err := io.ReadAll(r.Body)
	release()
	if err != nil || string(got) != receipt {
		t.Fatalf("the handler read %q (%v), want the receipt as sent", got, err)
	}
	if _, r, release := post(event); release != nil {
		if err := chargeSandboxHookBudget(r.Context(), false); err == nil {
			t.Fatal("the receipt refilled the hook budget")
		}
		release()
	}
	// The unmarked form used by older images is also receipt-bounded.
	api = &APIServer{}
	w, r, release = post(receipt)
	if release == nil || chargeSandboxHookBudget(r.Context(), true) != nil {
		t.Fatalf("unmarked receipt refused before its own budget: %d", w.Code)
	}
	release()
	w, r, release = post(event)
	if release == nil || chargeSandboxHookBudget(r.Context(), false) != nil {
		t.Fatalf("ordinary hook after unmarked receipt was refused: %d", w.Code)
	}
	release()
}

// The hook socket's rate and in-flight limits apply before a caller can stall
// the body of either an ordinary hook or a claimed receipt.
func TestSandboxHookCallerStalledBodiesAreAdmittedBeforeRead(t *testing.T) {
	for _, claim := range []bool{false, true} {
		name := "hook"
		if claim {
			name = "receipt"
		}
		t.Run(name, func(t *testing.T) {
			class := sandboxBudgetHook
			if claim {
				class = sandboxBudgetReceipt
			}
			old := sandboxBudgetLimits[class]
			sandboxBudgetLimits[class] = sandboxBudgetLimit{Rate: 1, Burst: 1, InFlight: 1}
			t.Cleanup(func() { sandboxBudgetLimits[class] = old })
			api := &APIServer{}
			path := sandboxrelay.PathHookPrefix + "claudecode"
			request := func(body *stalledHookCallerBody) *http.Request {
				r := httptest.NewRequest(http.MethodPost, path, nil)
				r.Body = body
				r.ContentLength = 73
				if claim {
					r.Header.Set("X-DefenseClaw-Hook-Receipt", "1")
				}
				return r
			}
			first := &stalledHookCallerBody{readCalled: make(chan struct{}), release: make(chan struct{})}
			second := &stalledHookCallerBody{readCalled: make(chan struct{}), release: make(chan struct{})}
			firstDone, secondDone := make(chan struct{}), make(chan struct{})
			secondReply := httptest.NewRecorder()
			go func() {
				r, release := api.admitHookCaller(httptest.NewRecorder(), request(first), "1001", path)
				if release != nil {
					_, _ = io.ReadAll(r.Body)
					release()
				}
				close(firstDone)
			}()
			select {
			case <-first.readCalled:
			case <-time.After(2 * time.Second):
				close(first.release)
				t.Fatal("first request did not reach its body")
			}
			go func() {
				_, release := api.admitHookCaller(secondReply, request(second), "1001", path)
				if release != nil {
					release()
				}
				close(secondDone)
			}()
			select {
			case <-secondDone:
				close(first.release)
				close(second.release)
				<-firstDone
				if secondReply.Code != http.StatusTooManyRequests {
					t.Fatalf("second request status %d, want immediate 429", secondReply.Code)
				}
			case <-time.After(2 * time.Second):
				close(first.release)
				close(second.release)
				<-firstDone
				<-secondDone
				t.Fatal("second request waited for its body before admission")
			}
		})
	}
}

type stalledHookCallerBody struct {
	readCalled chan struct{}
	release    chan struct{}
	once       sync.Once
}

func (b *stalledHookCallerBody) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.readCalled) })
	<-b.release
	return 0, io.EOF
}

func (*stalledHookCallerBody) Close() error { return nil }

func TestSandboxHookReceiptAdmissionKeys(t *testing.T) {
	receipt := `{"delivery_receipt":"3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b","result":"ack"}`
	for _, c := range []struct {
		method, path, body, marker, want string
	}{
		{http.MethodPost, sandboxrelay.PathHookPrefix + "codex", receipt, "1", "1001|" + sandboxBudgetReceipt},
		{http.MethodPost, sandboxrelay.PathHookPrefix + "codex", receipt, "", "1001|" + sandboxBudgetPending},
		{http.MethodPost, sandboxrelay.PathHookPrefix + "codex", `{"hook_event_name":"PreToolUse"}`, "", "1001|" + sandboxBudgetPending},
		{http.MethodPost, sandboxrelay.PathHookPrefix + "codex", `{"hook_event_name":"PreToolUse"}`, "1", "1001|" + sandboxBudgetReceipt},
		{http.MethodPost, sandboxrelay.PathHookPrefix + "codex", `{"delivery_receipt":"x","result":"ack"}`, "bogus", "1001|" + sandboxBudgetReceipt},
		{http.MethodPost, sandboxrelay.PathNotifyPrefix + "codex", receipt, "1", "1001|" + sandboxBudgetHook},
		{http.MethodPost, sandboxrelay.PathInspectPrefix + "tool", receipt, "1", "1001|" + sandboxBudgetHook},
		{http.MethodPost, "/api/v1/claudecode/hook", receipt, "1", "1001"},
		{http.MethodGet, sandboxrelay.PathPolicyCurrent, "", "", "1001" + hookCallerSandboxRead},
		{http.MethodPost, sandboxrelay.PathPolicyExplain, "{}", "", "1001" + hookCallerSandboxRead},
		{http.MethodPost, sandboxrelay.PathDecisions, "{}", "", "1001|" + sandboxBudgetPolicy},
	} {
		r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		if c.marker != "" {
			r.Header.Set(sandboxrelay.HookReceiptHeader, c.marker)
		}
		if got := hookCallerAdmissionKey("1001", r); got != c.want {
			t.Errorf("%s %s %.30s: key %q, want %q", c.method, c.path, c.body, got, c.want)
		}
		if body, _ := io.ReadAll(r.Body); string(body) != c.body {
			t.Errorf("%s %s: body %q after the key, want %q", c.method, c.path, body, c.body)
		}
	}
	var l hookCallerLimiter
	if rps, burst, inFlight, _ := l.limits("1001|" + sandboxBudgetReceipt); rps != sandboxUserHookRate || burst != sandboxUserHookBurst || inFlight != sandboxUserReceiptInFlight {
		t.Fatalf("receipt limits %d/%d/%d", rps, burst, inFlight)
	}
}

// Delivery receipts are posts in their own rate class. Several bindings of
// one account must not fill a second, 32-request user cap while each binding
// and the shared receipt bucket remain within their limits.
func TestGAP0490ConcurrentReceiptsAcrossBindings(t *testing.T) {
	now := time.Unix(4_000_000, 0)
	limiter := &hookCallerLimiter{now: func() time.Time { return now }}
	var releases []func()
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	for binding := 0; binding < 4; binding++ {
		for call := 0; call < 24; call++ {
			release, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetReceipt)
			if reason != "" {
				t.Fatalf("binding %d receipt %d refused within the 96-call aggregate: %s", binding, call, reason)
			}
			releases = append(releases, release)
		}
	}
	if host, _, reason, _ := limiter.acquire("1001"); reason != "" {
		t.Fatalf("host hook refused while sandbox receipts were held: %s", reason)
	} else {
		host()
	}
	for len(releases) < sandboxUserReceiptInFlight {
		// Advance the bucket as receipts arrive; keeping their slots held
		// exercises the concurrency boundary.
		now = now.Add(time.Second / sandboxUserHookRate)
		release, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetReceipt)
		if reason != "" {
			t.Fatalf("receipt %d below the aggregate bound refused: %s", len(releases), reason)
		}
		releases = append(releases, release)
	}
	if release, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetReceipt); release != nil || reason != managedHookReasonRateLimited {
		t.Fatalf("receipt above the aggregate bound: release=%t reason=%s", release != nil, reason)
	}
}

// Class selection does not read or replace the request body.
func TestClaimsSandboxHookReceiptLeavesBodyUnread(t *testing.T) {
	for _, marked := range []bool{false, true} {
		body := &oneShotHookCallerBody{}
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Body = body
		if marked {
			r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		if got := claimsSandboxHookReceipt(r); got != marked || body.read {
			t.Fatalf("marked=%t: claim=%t body read=%t", marked, got, body.read)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
	if claimsSandboxHookReceipt(r) {
		t.Fatal("a GET counted as a receipt")
	}
}

func TestSandboxHookAdmissionClaimHasNoAllocations(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, sandboxrelay.PathHookPrefix+"claudecode", nil)
	if got := testing.AllocsPerRun(1000, func() { _ = claimsSandboxHookReceipt(r) }); got != 0 {
		t.Fatalf("ordinary hook receipt-class check allocates %.1f times per call", got)
	}
}

type oneShotHookCallerBody struct{ read bool }

func (b *oneShotHookCallerBody) Read([]byte) (int, error) {
	b.read = true
	return 0, io.ErrUnexpectedEOF
}

func (*oneShotHookCallerBody) Close() error { return nil }

// TestSandboxHookFloodAtTheDocumentedUserRate is the per-user side of
// rel-1-0-6 GAP-0490: the documented relayed-hook budget of one account (40
// calls a second, burst 100), 10 s of allowed calls at that rate, each a
// relayed hook post and its delivery receipt, on a clock the test moves. No
// call and no receipt may be refused.
func TestSandboxHookFloodAtTheDocumentedUserRate(t *testing.T) {
	now := time.Unix(4_000_000, 0)
	api := &APIServer{}
	api.hookCallerLimits.now = func() time.Time { return now }
	path := sandboxrelay.PathHookPrefix + "claudecode"
	receipt := `{"delivery_receipt":"3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b","result":"ack"}`
	post := func(body string, receipt ...bool) bool {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if len(receipt) != 0 && receipt[0] {
			r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		_, release := api.admitHookCaller(httptest.NewRecorder(), r, "1001", path)
		if release != nil {
			release()
		}
		return release != nil
	}
	budget := sandboxBudgetLimits[sandboxBudgetHook]
	refusedHooks, refusedReceipts := 0, 0
	calls := budget.Rate * 10
	for i := 0; i < calls; i++ {
		if !post(`{"hook_event_name":"PreToolUse"}`) {
			refusedHooks++
		} else if !post(receipt, true) {
			refusedReceipts++
		}
		now = now.Add(time.Second / time.Duration(budget.Rate))
	}
	if refusedHooks != 0 || refusedReceipts != 0 {
		t.Fatalf("%d calls at %d a second: %d hooks and %d receipts refused", calls, budget.Rate, refusedHooks, refusedReceipts)
	}
}

// One account may spread its documented hook budget across several sandbox
// bindings. Each binding stays below its own 25/s and 32-in-flight limits;
// the account must not hit a second, smaller concurrency limit at the gateway.
func TestGAP0490MultipleSandboxBindingsShareTheUserBudget(t *testing.T) {
	type heldCall struct {
		binding int
		until   time.Time
		release func()
	}
	run := func(bindings, perBinding, seconds int, service time.Duration) (allowed, refused int) {
		t.Helper()
		start := time.Unix(4_000_000, 0)
		now := start
		limiter := &hookCallerLimiter{now: func() time.Time { return now }}
		active := make([]int, bindings)
		var held []heldCall
		perSecond := bindings * perBinding
		for i := 0; i < seconds*perSecond; i++ {
			now = start.Add(time.Duration(i) * time.Second / time.Duration(perSecond))
			kept := held[:0]
			for _, call := range held {
				if call.until.After(now) {
					kept = append(kept, call)
					continue
				}
				call.release()
				active[call.binding]--
				if receipt, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetReceipt); reason != "" {
					t.Fatalf("receipt of an admitted call refused: %s", reason)
				} else {
					receipt()
				}
			}
			held = kept
			binding := i % bindings
			if active[binding] >= 32 {
				t.Fatalf("binding %d exceeded its own in-flight limit", binding)
			}
			release, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetPending)
			if reason != "" {
				refused++
				continue
			}
			if reason = limiter.chargeClass("1001|" + sandboxBudgetHook); reason != "" {
				release()
				refused++
				continue
			}
			allowed++
			active[binding]++
			held = append(held, heldCall{binding, now.Add(service), release})
			if i == perSecond {
				// The relayed class does not consume the host hook's budget.
				host, _, reason, _ := limiter.acquire("1001")
				if reason != "" {
					t.Fatalf("host hook refused during the sandbox stream: %s", reason)
				}
				host()
			}
		}
		for _, call := range held {
			call.release()
		}
		return allowed, refused
	}

	if allowed, refused := run(1, 24, 10, time.Second); allowed != 240 || refused != 0 {
		t.Fatalf("one ordinary binding: %d allowed, %d refused", allowed, refused)
	}
	if allowed, refused := run(4, 10, 10, time.Second); allowed != 400 || refused != 0 {
		t.Fatalf("four ordinary bindings at the 40/s budget: %d allowed, %d refused", allowed, refused)
	}
	if allowed, refused := run(5, 8, 10, 1300*time.Millisecond); allowed != 400 || refused != 0 {
		t.Fatalf("five ordinary bindings at the 40/s budget: %d allowed, %d refused", allowed, refused)
	}
	if allowed, refused := run(8, 5, 10, 1500*time.Millisecond); allowed != 400 || refused != 0 {
		t.Fatalf("eight ordinary bindings at the 40/s budget: %d allowed, %d refused", allowed, refused)
	}
	if allowed, refused := run(20, 2, 10, 3400*time.Millisecond); allowed != 400 || refused != 0 {
		t.Fatalf("twenty ordinary bindings at the 40/s budget: %d allowed, %d refused", allowed, refused)
	}
	// Above the budget (130/s) the account is refused only what is over it:
	// no more than the burst and the rate over the run is admitted, and the
	// admitted calls are the whole budget, not a collapsed share of it.
	const overSeconds = 15
	allowed, refused := run(10, 13, overSeconds, 100*time.Millisecond)
	if refused == 0 || allowed > sandboxUserHookBurst+sandboxUserHookRate*overSeconds || allowed < sandboxUserHookRate*overSeconds {
		t.Fatalf("over-budget account at 130/s: %d allowed, %d refused", allowed, refused)
	}
}

// Managed sandbox requests can remain active for the rendered ingress
// attempt or receipt window. Calls spread across bindings must still use the
// account's rate bucket rather than a shorter shared concurrency allowance.
func TestGAP0490ManagedHookAndReceiptWindows(t *testing.T) {
	first, retry := connector.SandboxHookAttemptBudgets()
	for _, tc := range []struct {
		name     string
		class    string
		span     time.Duration
		bindings int
		// bound is the call past which the in-flight bound refuses (0: none):
		// the bounds hold one answer window at the account rate
		// (sandboxInFlightWindow), not the 12 s attempt or 15 s receipt
		// lifetime (S8 lead review P2-1).
		bound int
	}{
		{"hook-review-window", sandboxBudgetPending, 3510 * time.Millisecond, 20, 0},
		{"receipt-review-window", sandboxBudgetReceipt, 3510 * time.Millisecond, 20, 0},
		{"hook-full-window", sandboxBudgetPending, max(first, retry) - 10*time.Millisecond, 60, sandboxUserHookInFlight},
		{"receipt-full-window", sandboxBudgetReceipt, sandboxHookReceiptWindow - 10*time.Millisecond, 60, sandboxUserReceiptInFlight},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Unix(4_000_000, 0)
			now := start
			limiter := &hookCallerLimiter{now: func() time.Time { return now }}
			active := make([]int, tc.bindings)
			var releases []func()
			defer func() {
				for _, release := range releases {
					release()
				}
			}()
			calls := sandboxUserHookBurst + int(sandboxUserHookRate*tc.span/time.Second)
			for i := 0; i < calls; i++ {
				if i >= sandboxUserHookBurst {
					now = start.Add(time.Duration(i-sandboxUserHookBurst+1) * time.Second / sandboxUserHookRate)
				}
				binding := i % tc.bindings
				if active[binding] >= 32 {
					t.Fatalf("binding %d reached its own in-flight limit", binding)
				}
				release, _, reason, _ := limiter.acquire("1001|" + tc.class)
				if tc.bound > 0 && i >= tc.bound {
					if reason == "" {
						release()
						t.Fatalf("call %d held past the in-flight bound of %d was admitted", i+1, tc.bound)
					}
					break
				}
				if reason != "" {
					t.Fatalf("call %d of %d at %s refused: %s", i+1, calls, now.Sub(start), reason)
				}
				if tc.class == sandboxBudgetPending {
					if reason := limiter.chargeClass("1001|" + sandboxBudgetHook); reason != "" {
						release()
						t.Fatalf("hook call %d refused: %s", i+1, reason)
					}
				}
				releases = append(releases, release)
				active[binding]++
			}
			for _, key := range []string{"1001", "1002|" + sandboxBudgetReceipt} {
				release, _, reason, _ := limiter.acquire(key)
				if reason != "" {
					t.Fatalf("independent caller %s refused: %s", key, reason)
				}
				release()
			}
		})
	}

	t.Run("single-binding-ordinary", func(t *testing.T) {
		limiter := &hookCallerLimiter{}
		for i := 0; i < 24; i++ {
			release, _, reason, _ := limiter.acquire("1001|" + sandboxBudgetPending)
			if reason != "" {
				t.Fatalf("ordinary call %d refused: %s", i+1, reason)
			}
			release()
		}
	})
}

// A call refused for the account budget is answered 429 with the stable
// reason and a message that names the budget, whichever of the two places
// refuses it (the admission of the request, or the charge of the hook class
// once the body is read): the sandbox hook shows that message to the user, so
// a rate refusal is never read as an outage (rel-1-0-6 GAP-0490).
func TestGAP0490RefusalNamesTheBudget(t *testing.T) {
	check := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		var body struct{ Error, Reason, Message string }
		if w.Code != http.StatusTooManyRequests || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("refusal %d %s, want 429 with a JSON body", w.Code, w.Body.String())
		}
		if body.Reason != managedHookReasonRateLimited || body.Message != sandboxHookBudgetMessage() || w.Header().Get("Retry-After") != "1" {
			t.Fatalf("refusal %+v retry-after %q", body, w.Header().Get("Retry-After"))
		}
		if want := fmt.Sprintf("%d tool calls a second together (a burst of %d)", sandboxUserHookRate, sandboxUserHookBurst); !strings.Contains(body.Message, want) {
			t.Fatalf("message %q does not state the budget %q", body.Message, want)
		}
	}
	t.Run("admission", func(t *testing.T) {
		prev := sandboxBudgetLimits[sandboxBudgetReceipt]
		sandboxBudgetLimits[sandboxBudgetReceipt] = sandboxBudgetLimit{Rate: 1, Burst: 1, InFlight: 8}
		t.Cleanup(func() { sandboxBudgetLimits[sandboxBudgetReceipt] = prev })
		api := &APIServer{}
		path := sandboxrelay.PathHookPrefix + "claudecode"
		var last *httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			last = httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}"))
			r.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
			if _, release := api.admitHookCaller(last, r, "1001", path); release != nil {
				defer release()
			}
		}
		check(t, last)
	})
	t.Run("charge", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, sandboxrelay.PathHookPrefix+"claudecode", nil)
		r = r.WithContext(withSandboxHookBudgetCharge(r.Context(), func(bool) error { return errors.New(managedHookReasonRateLimited) }))
		(&APIServer{}).handleAgentHook("claudecode")(w, r)
		check(t, w)
	})
	t.Run("host hooks keep their message", func(t *testing.T) {
		if isSandboxHookClassKey("1001") || isSandboxHookClassKey("1001|"+sandboxBudgetPolicy) || isSandboxHookClassKey("1001|otlp") {
			t.Fatal("a host or policy key got the sandbox hook budget message")
		}
	})
}
