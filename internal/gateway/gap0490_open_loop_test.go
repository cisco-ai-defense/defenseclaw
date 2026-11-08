// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/google/uuid"
)

// The three open-loop tests below measure wall-clock throughput: the managed
// gateway has to answer a steady stream inside the hook window of 3.5 s. A
// race build is several times slower and would measure the detector, not the
// gateway, so they are built without -race. The rate and queue logic that
// decides which calls are admitted is proven in every build, race included,
// on an injected clock (TestSandboxAccountBudgetSchedule).
//
// A box that is already overloaded cannot show the gateway answering in time,
// so every run carries a same-run control: the same offered stream, at the
// same time, straight to a handler that does nothing but answer (no relay, no
// limiter, no journal). The claims:
//   - No call is ever refused by a rate limit (HTTP 429). That is decided by
//     the limiter, not by load, so it holds on every runner.
//   - Every call is answered inside the window. If one is not, the test fails
//     when the control answered every call quickly (the gateway was slow on a
//     runner that could keep up) and is skipped, with the control numbers
//     named, only when the control itself could not reach the offered rate
//     there. The offered rate is never lowered.
//
// CI runs these three without -race in the Connector Matrix (packages and CLI)
// step "Gateway throughput tests (no race)" on Linux and in the "Unix
// Standalone Lifecycle (macos-latest darwin gateway and cli)" step on macOS.

// TestGAP0490OpenLoopSandboxStream drives the relayed hook the way the sandbox
// hook does (a proposal, then its delivery receipt) at a steady 22 calls a
// second, under the 25/s of its sandbox, that does not wait for the answers of
// the calls before it, the way an agent issues tool calls. No call may be
// refused or left without its answer inside the answer window. The gateway
// made the durable journal and audit writes of every call one after the
// other, so the answers queued until the sandbox binding reached its open
// request bound and the calls were refused 429 (rel-1-0-6 GAP-0490, IB10).
// The same stream from two sandboxes of one account (44/s) is over the
// account budget of 40/s for a moment, but its 10 s fit the burst of 100, so
// none of it may be refused.
func TestGAP0490OpenLoopSandboxStream(t *testing.T) {
	runGAP0490OpenLoop(t, 1, 22, 10*time.Second)
}

// The two-sandbox stream (44 calls a second for one account): before the
// managed call writes shared one write baton and one correlation turn per
// session the gateway answered it only some of the time (rel-1-0-6 GAP-0490,
// round 6).
func TestGAP0490OpenLoopTwoSandboxes(t *testing.T) {
	runGAP0490OpenLoop(t, 2, 22, 10*time.Second)
}

// The four-sandbox stream at the documented account budget (4 x 10 = 40 calls
// a second, sandboxUserHookRate): the managed gateway
// answers it inside the hook window of 3.5 s (p95 under a second on the shared
// build box). 96 calls a second (4 x 24) did not answer in time in half the
// runs there: a rate above the budget is refused at once with a 429 that
// names the budget (TestGAP0490RefusalNamesTheBudget), and raising the budget
// is a 1.0.10 performance row (rel-1-0-6 GAP-0490).
func TestGAP0490OpenLoopFourSandboxes(t *testing.T) {
	runGAP0490OpenLoop(t, 4, sandboxUserHookRate/4, 10*time.Second)
}

// openLoopPost sends one request of a call and returns its status and body.
type openLoopPost func(token string, body []byte, receipt bool) (int, []byte, error)

// openLoopResult is what one open-loop stream saw.
type openLoopResult struct {
	offered   int
	latencies []time.Duration
	problems  map[string]int
	refused   int // calls whose proposal or receipt got HTTP 429
}

func (r openLoopResult) percentile(p int) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), r.latencies...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	return sorted[len(sorted)*p/100]
}

func (r openLoopResult) answeredShare() float64 {
	if r.offered == 0 {
		return 1
	}
	return float64(len(r.latencies)) / float64(r.offered)
}

// openLoopWait is how long the hook waits for an answer.
const openLoopWait = 3500 * time.Millisecond

// openLoopControlHeadroom: a runner whose do-nothing handler needs more than
// the answer window divided by this to answer 95 of 100 calls has no room left
// to say anything about the gateway.
const openLoopControlHeadroom = 4

func newOpenLoopPost(t *testing.T, url string) openLoopPost {
	return func(token string, body []byte, receipt bool) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(t.Context(), openLoopWait)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/api/v1/claude-code/hook", bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-DefenseClaw-Client", "sandbox-hook/1.0")
		req.Header.Set(SandboxHookIdempotencyHeader, uuid.NewString())
		if receipt {
			req.Header.Set(sandboxrelay.HookReceiptHeader, sandboxrelay.HookReceiptHeaderValue)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		return resp.StatusCode, out, err
	}
}

// driveOpenLoop issues perSecond calls a second for duration from each token,
// without waiting for the calls before them, and waits for every answer.
func driveOpenLoop(post openLoopPost, tokens []string, perSecond int, duration time.Duration) openLoopResult {
	result := openLoopResult{problems: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	call := func(token string, session string, n int) {
		defer wg.Done()
		started := time.Now()
		body := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"cwd":"/tmp","tool_name":"Bash","tool_use_id":"%s-%d","tool_input":{"command":"echo ok"}}`, session, session, n)
		status, out, err := post(token, []byte(body), false)
		var answer struct {
			Action          string `json:"action"`
			DeliveryReceipt string `json:"delivery_receipt"`
		}
		if err == nil && status == http.StatusOK && json.Unmarshal(out, &answer) == nil && answer.Action == "allow" && answer.DeliveryReceipt != "" {
			ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
			status, out, err = post(token, ack, true)
		} else if err == nil && status == http.StatusOK {
			err = fmt.Errorf("proposal %s", out)
		}
		mu.Lock()
		defer mu.Unlock()
		if status == http.StatusTooManyRequests {
			result.refused++
		}
		if err != nil || status != http.StatusOK {
			result.problems[fmt.Sprintf("%d %.80s %v", status, out, err)]++
			return
		}
		result.latencies = append(result.latencies, time.Since(started))
	}
	total := int(duration.Seconds()) * perSecond
	result.offered = len(tokens) * total
	interval := time.Second / time.Duration(perSecond)
	start := time.Now()
	var launch sync.WaitGroup
	for i, token := range tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			session := fmt.Sprintf("g490-open-%d", i)
			for n := 0; n < total; n++ {
				if d := time.Until(start.Add(time.Duration(n) * interval)); d > 0 {
					time.Sleep(d)
				}
				wg.Add(1)
				go call(token, session, n)
			}
		}()
	}
	launch.Wait()
	wg.Wait()
	return result
}

func runGAP0490OpenLoop(t *testing.T, sandboxes, perSecond int, duration time.Duration) {
	f := newManagedHookAuditFixture(t, nil)
	bindings, err := sandboxauth.OpenFileStore(sandboxauth.DefaultStorePath(t.TempDir()), sandboxauth.WithRefreshInterval(0))
	if err != nil {
		t.Fatal(err)
	}
	tokens := make([]string, sandboxes)
	for i := range tokens {
		_, tokens[i], err = bindings.Mint(sandboxauth.Spec{
			SandboxName: fmt.Sprintf("g490-open-%d", i), Connector: "claudecode", AgentVersion: "2.1.156",
			HookContractID: "claudecode-hooks-v1", PolicyProfile: "open",
			Routes:   []sandboxauth.Route{sandboxauth.RouteHook},
			Workdir:  sandboxauth.Workdir{Mode: sandboxauth.WorkdirCopy},
			HostUser: sandboxauth.HostUser{UID: "1000", Name: "dev"},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := f.api.SetSandboxIngress(SandboxIngressConfig{Addr: "127.0.0.1:18972", Bindings: bindings}); err != nil {
		t.Fatal(err)
	}
	handler, err := f.api.SandboxIngressHandler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(handler)
	defer srv.Close()
	// The control: the same stream to a handler that only answers.
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		if r.Header.Get(sandboxrelay.HookReceiptHeader) != "" {
			_, _ = io.WriteString(w, `{}`)
			return
		}
		_, _ = io.WriteString(w, `{"action":"allow","delivery_receipt":"control"}`)
	}))
	defer control.Close()
	post := newOpenLoopPost(t, srv.URL)
	// Warm the sessions: the first call of an unseen session waits for its
	// start, which is not what this test measures.
	for i, token := range tokens {
		session := fmt.Sprintf("g490-open-%d", i)
		if status, out, err := post(token, []byte(managedHookBody(session, "UserPromptSubmit")), false); err != nil || status != http.StatusOK {
			t.Fatalf("session start %d %s %v", status, out, err)
		}
	}
	var controlResult openLoopResult
	var controlDone sync.WaitGroup
	controlDone.Add(1)
	go func() {
		defer controlDone.Done()
		controlResult = driveOpenLoop(newOpenLoopPost(t, control.URL), tokens, perSecond, duration)
	}()
	got := driveOpenLoop(post, tokens, perSecond, duration)
	controlDone.Wait()

	if got.refused != 0 {
		t.Fatalf("%d sandboxes at %d calls/s: %d of %d calls were refused with HTTP 429 (a rate limit, not load): %v",
			sandboxes, perSecond, got.refused, got.offered, got.problems)
	}
	if len(got.problems) != 0 {
		controlReached := len(controlResult.problems) == 0 &&
			controlResult.percentile(95) <= openLoopWait/openLoopControlHeadroom
		detail := fmt.Sprintf("%d sandboxes at %d calls/s: %d of %d calls unanswered inside %v (answered share %.3f; control answered share %.3f, control p95 %v): %v",
			sandboxes, perSecond, got.offered-len(got.latencies), got.offered, openLoopWait,
			got.answeredShare(), controlResult.answeredShare(), controlResult.percentile(95), got.problems)
		if !controlReached {
			t.Skipf("this runner cannot carry the offered load, so the stream says nothing about the gateway (the same stream straight to a handler that only answers: %d problems, p95 %v, limit %v): %s",
				len(controlResult.problems), controlResult.percentile(95), openLoopWait/openLoopControlHeadroom, detail)
		}
		t.Fatal(detail)
	}
	t.Logf("%d sandboxes at %d calls/s: %d calls, p50 %v, p95 %v (control p95 %v)", sandboxes, perSecond, len(got.latencies),
		got.percentile(50), got.percentile(95), controlResult.percentile(95))
}
