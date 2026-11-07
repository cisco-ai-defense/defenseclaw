// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// newManagedHookAuditFixtureInDir is the managed claudecode audit fixture with
// its stores under directory. Only this test runs it (it is not built on
// Windows), so it lives here, where the unused check on Windows sees no helper
// without a caller.
func newManagedHookAuditFixtureInDir(t *testing.T, directory string) managedHookAuditFixture {
	t.Helper()
	return newManagedHookAuditFixtureForExportingToInDir(t, directory, "claudecode", nil, nil)
}

// TestGAP0490SandboxReceiptCapacity sends 400 relayed tool calls, 20 at a
// time and inside the documented per-binding hook rate (above that rate the
// ingress answers 429 by design), the way the sandbox hook sends them
// (hooks/_sandbox.sh): the proposal and its receipt each carry an idempotency
// key, and an attempt that gets no answer, or a 502, 503 or 504, is posted
// once more with the same key. On a normal build each attempt waits 3 s, a
// third of the first attempt of the hook. A race build on a loaded runner is
// several times slower, so there each attempt waits what the rendered hook
// waits (connector.SandboxHookAttemptBudgets: 9 s, then 12 s). A retry after
// a 502, 503 or 504 fails the test: the gateway answered with an error, the
// SQLite-busy receipt failure GAP-0490 removed. Every call must still end in
// an allow, a receipt the gateway acknowledges and exactly one audited
// verdict: a retry joins its first attempt instead of evaluating the call
// again, so no call is offered twice and no offered answer is left
// unacknowledged.
func TestGAP0490SandboxReceiptCapacity(t *testing.T) {
	const calls, parallel = 400, 20
	// This disposable fixture writes hundreds of audit and receipt rows.
	// Keep its synchronous writes off the shared build disk when an
	// adequately sized private memory-backed test directory is available.
	scratch := sandboxReceiptScratchDir(t)
	if scratch == "" {
		scratch = t.TempDir()
	}
	f := newManagedHookAuditFixtureInDir(t, scratch)
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := bindings.Mint(sandboxauth.Spec{
		SandboxName: "g490-sandbox", Connector: "claudecode", AgentVersion: "2.1.156",
		HookContractID: "claudecode-hooks-v1", PolicyProfile: "open",
		Routes:   []sandboxauth.Route{sandboxauth.RouteHook},
		Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
		HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18971", Bindings: bindings}); err != nil {
		t.Fatal(err)
	}
	handler, err := f.api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	first, retry := 3*time.Second, 3*time.Second
	if hookAnswerRaceBuild {
		first, retry = connector.SandboxHookAttemptBudgets()
	}
	var retriedTimeout, retriedStatus atomic.Int32
	// Proposals start at 80% of the production hook rate and half its burst,
	// so a fast runner stays inside the budget the ingress enforces. A slow
	// runner is limited by the gateway, not by this pace.
	limits := sandboxauth.DefaultLimiterConfig()
	pace := rate.NewLimiter(rate.Limit(limits.HookRPS*0.8), limits.HookBurst/2)
	// post returns the final answer and the 5xx status that caused a retry
	// (0 when none did).
	post := func(body []byte, receipt bool) (int, []byte, int, error) {
		key := uuid.NewString()
		retriedAfter := 0
		for attempt := 1; ; attempt++ {
			wait := first
			if attempt > 1 {
				wait = retry
			}
			ctx, cancel := context.WithTimeout(t.Context(), wait)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/v1/claude-code/hook", bytes.NewReader(body))
			if err != nil {
				cancel()
				return 0, nil, retriedAfter, err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
			req.Header.Set(SandboxHookIdempotencyHeader, key)
			if receipt {
				req.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
			}
			var status int
			var out []byte
			resp, err := http.DefaultClient.Do(req)
			if err == nil {
				status = resp.StatusCode
				out, err = io.ReadAll(resp.Body)
				_ = resp.Body.Close()
			}
			cancel()
			serverError := status == http.StatusBadGateway ||
				status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
			if (err == nil && !serverError) || attempt == 2 {
				return status, out, retriedAfter, err
			}
			if serverError {
				retriedStatus.Add(1)
				retriedAfter = status
			} else {
				retriedTimeout.Add(1)
			}
		}
	}
	jobs := make(chan int, calls)
	for i := 0; i < calls; i++ {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	var mu sync.Mutex
	problems := make(map[string]int)
	receipts := make(map[string]string, calls)
	for worker := 0; worker < parallel; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				session := fmt.Sprintf("g490-%d", i)
				if err := pace.Wait(t.Context()); err != nil {
					mu.Lock()
					problems[fmt.Sprintf("pace %v", err)]++
					mu.Unlock()
					continue
				}
				status, out, retriedAfter, err := post([]byte(managedHookBody(session, "PreToolUse")), false)
				if retriedAfter != 0 {
					mu.Lock()
					problems[fmt.Sprintf("proposal retried after %d", retriedAfter)]++
					mu.Unlock()
				}
				if err != nil || status != http.StatusOK {
					mu.Lock()
					problems[fmt.Sprintf("proposal %d %s %v", status, out, err)]++
					mu.Unlock()
					continue
				}
				var answer struct {
					Action          string `json:"action"`
					DeliveryReceipt string `json:"delivery_receipt"`
				}
				if err := json.Unmarshal(out, &answer); err != nil || answer.Action != "allow" || answer.DeliveryReceipt == "" {
					mu.Lock()
					problems[fmt.Sprintf("proposal body %s %v", out, err)]++
					mu.Unlock()
					continue
				}
				mu.Lock()
				if other, dup := receipts[answer.DeliveryReceipt]; dup {
					problems[fmt.Sprintf("receipt %s offered to %s and %s", answer.DeliveryReceipt, other, session)]++
				}
				receipts[answer.DeliveryReceipt] = session
				mu.Unlock()
				ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
				status, out, retriedAfter, err = post(ack, true)
				if retriedAfter != 0 {
					mu.Lock()
					problems[fmt.Sprintf("receipt retried after %d", retriedAfter)]++
					mu.Unlock()
				}
				var received struct {
					Received bool `json:"received"`
				}
				if err != nil || status != http.StatusOK || json.Unmarshal(out, &received) != nil || !received.Received {
					mu.Lock()
					problems[fmt.Sprintf("receipt %d %s %v", status, out, err)]++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	t.Logf("%d calls at %d parallel, attempts of %v then %v: %d retried after no answer, %d after a 5xx",
		calls, parallel, first, retry, retriedTimeout.Load(), retriedStatus.Load())
	if len(problems) != 0 {
		t.Fatalf("%d calls at %d parallel: %v", calls, parallel, problems)
	}
	if len(receipts) != calls {
		t.Fatalf("distinct receipts = %d, want %d", len(receipts), calls)
	}
	// One audited verdict per call: the acknowledged allow.
	events, err := f.store.ListEvents(100 * calls)
	if err != nil {
		t.Fatal(err)
	}
	verdicts := make(map[string][]string, calls)
	for _, event := range events {
		if event.Action != string(audit.ActionConnectorHook) || !strings.HasPrefix(event.SessionID, "g490-") {
			continue
		}
		verdict := "?"
		for _, field := range strings.Fields(event.Details) {
			if action, ok := strings.CutPrefix(field, "action="); ok {
				verdict = action
			}
		}
		verdicts[event.SessionID] = append(verdicts[event.SessionID], verdict)
	}
	for i := 0; i < calls; i++ {
		session := fmt.Sprintf("g490-%d", i)
		if got := verdicts[session]; len(got) != 1 || got[0] != "allow" {
			t.Errorf("%s audited verdicts = %v, want one allow", session, got)
		}
	}
	// Every journaled offer was acknowledged: a retry that evaluated a call
	// again would leave its own offer unsettled.
	var after audit.HookDeliveryJournalEntry
	for {
		entries, err := f.store.HookDeliveries(t.Context(), after, 100, pendingHookJournalLimits.OccurrenceBytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			var pending pendingHookOccurrence
			if json.Unmarshal(entry.Occurrence, &pending) != nil || !pending.Settled {
				t.Errorf("journal row %s was offered and never acknowledged", entry.ID)
			} else if receipts[entry.ID] == "" {
				t.Errorf("journal row %s is not an offered receipt", entry.ID)
			}
			after = audit.HookDeliveryJournalEntry{ID: entry.ID, CreatedAt: entry.CreatedAt}
		}
		if len(entries) < 100 {
			break
		}
	}
}

func TestGAP0490CanceledRelayFreesBindingAdmission(t *testing.T) {
	entered := make(chan struct{})
	finish := make(chan struct{})
	var calls atomic.Int32
	f := newSandboxIngressFixture(t, func(cfg *SandboxIngressConfig) {
		cfg.Limiter = sandboxauth.NewLimiter(sandboxauth.LimiterConfig{
			HookRPS: 1000, HookBurst: 1000, MaxInFlight: 1,
		})
		cfg.OnRequest = func(_ sandboxauth.Binding, route sandboxauth.Route) {
			if route == sandboxauth.RouteHook && calls.Add(1) == 1 {
				close(entered)
				<-finish
			}
		}
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	first := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", bytes.NewBufferString(`{}`)).WithContext(ctx)
	first.RemoteAddr = "127.0.0.1:43210"
	first.Header.Set("Authorization", "Bearer "+f.claudeTok)
	first.Header.Set("Content-Type", "application/json")
	first.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
	done := make(chan struct{})
	go func() {
		defer close(done)
		f.handler.ServeHTTP(httptest.NewRecorder(), first)
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(finish)
		t.Fatal("first request was not admitted")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		second := f.do(t, http.MethodPost, "/api/v1/claude-code/hook", f.claudeTok, `{}`)
		if second.Code != http.StatusTooManyRequests {
			break
		}
		if time.Now().After(deadline) {
			close(finish)
			t.Fatal("canceled relay retained the binding admission slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(finish)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first handler did not finish")
	}
}
