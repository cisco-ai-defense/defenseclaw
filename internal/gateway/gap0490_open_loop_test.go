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
	"strings"
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
// and a launcher that falls behind its schedule never offers the rate the test
// names, so every run is judged in this order:
//   - The offered rate is measured, not assumed. driveOpenLoop records the real
//     issue time of every call against its absolute slot; a call issued more
//     than one tick after its slot is late and does not count. The achieved rate
//     is the on-time calls over the window from the first to the last recorded
//     issue (plus one tick). If it is below 95% of the required rate, for the
//     stream or for its control, the run is INCONCLUSIVE and fails with that
//     word: a rate limit that was never challenged is not a pass. The required
//     rate and the answer window are never lowered.
//   - Every run carries a same-run control: the same offered stream, at the
//     same time, straight to a handler that does nothing but answer (no relay,
//     no limiter, no journal).
//   - No call is ever refused by a rate limit (HTTP 429). That is decided by
//     the limiter, not by load, so it holds on every runner.
//   - Every call (its proposal and its receipt together) is answered inside
//     one window of 3.5 s that both requests share. If one is not, the test
//     fails when the control answered every call of the same stream inside the
//     same window (the gateway was slow on a runner that could keep up) and is
//     skipped, with the control numbers named, only when the control itself
//     did not answer every offered call there.
//
// The judgement is a function of the two measured streams (judgeOpenLoop), and
// TestGAP0490OpenLoopCadence* run it against a stand-in with a rate cap: a
// launcher held to about 20 calls a second is INCONCLUSIVE, a real 44 calls a
// second against a 30/s cap fails on the 429s, and an uncapped stand-in passes.
//
// CI runs these without -race in the Connector Matrix (packages and CLI) step
// "Gateway throughput tests (no race)" on Linux.

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
type openLoopPost func(ctx context.Context, token string, body []byte, receipt bool) (int, []byte, error)

// openLoopPlan is one open-loop stream: perSecond calls a second from each
// token for duration. stall is test-only: an extra pause before every launch,
// to model a launcher that cannot keep its schedule.
type openLoopPlan struct {
	tokens    []string
	perSecond int
	duration  time.Duration
	stall     time.Duration
}

// required is the account-wide rate the plan names.
func (p openLoopPlan) required() float64 { return float64(len(p.tokens) * p.perSecond) }

// openLoopResult is what one open-loop stream saw.
type openLoopResult struct {
	offered   int
	onTime    int           // calls issued within one tick of their absolute slot
	late      int           // calls issued more than one tick after their slot
	window    time.Duration // first to last recorded issue, plus one tick
	latencies []time.Duration
	problems  map[string]int
	refused   int // calls whose proposal or receipt got HTTP 429
}

// achievedRate is the calls a second the launcher really issued on its
// schedule, from the recorded issue times: on-time calls over the window.
func (r openLoopResult) achievedRate() float64 {
	if r.window <= 0 {
		return 0
	}
	return float64(r.onTime) / r.window.Seconds()
}

func (r openLoopResult) percentile(p int) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), r.latencies...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	return sorted[min(len(sorted)*p/100, len(sorted)-1)]
}

func (r openLoopResult) answeredShare() float64 {
	if r.offered == 0 {
		return 1
	}
	return float64(len(r.latencies)) / float64(r.offered)
}

// openLoopWait is how long the hook waits for an answer.
const openLoopWait = 3500 * time.Millisecond

func newOpenLoopPost(url string) openLoopPost {
	return func(ctx context.Context, token string, body []byte, receipt bool) (int, []byte, error) {
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

// driveOpenLoop issues the plan on an absolute schedule (call n of a token at
// start + n ticks), without waiting for the calls before it, and waits for every
// answer. It records the real issue time of every call: one issued more than a
// tick after its slot is late and is left out of the achieved rate. A call has
// one deadline of openLoopWait, started with its proposal and shared by its
// receipt, and its measured latency is checked against that window as well, so
// a call that took longer is never counted as answered.
func driveOpenLoop(parent context.Context, post openLoopPost, plan openLoopPlan) openLoopResult {
	result := openLoopResult{problems: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	call := func(token string, session string, n int) {
		defer wg.Done()
		started := time.Now()
		ctx, cancel := context.WithTimeout(parent, openLoopWait)
		defer cancel()
		body := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"cwd":"/tmp","tool_name":"Bash","tool_use_id":"%s-%d","tool_input":{"command":"echo ok"}}`, session, session, n)
		status, out, err := post(ctx, token, []byte(body), false)
		var answer struct {
			Action          string `json:"action"`
			DeliveryReceipt string `json:"delivery_receipt"`
		}
		if err == nil && status == http.StatusOK && json.Unmarshal(out, &answer) == nil && answer.Action == "allow" && answer.DeliveryReceipt != "" {
			ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
			status, out, err = post(ctx, token, ack, true)
		} else if err == nil && status == http.StatusOK {
			err = fmt.Errorf("proposal %s", out)
		}
		elapsed := time.Since(started)
		if err == nil && status == http.StatusOK && elapsed > openLoopWait {
			err = fmt.Errorf("answered after the %v window", openLoopWait)
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
		result.latencies = append(result.latencies, elapsed)
	}
	total := int(plan.duration.Seconds()) * plan.perSecond
	result.offered = len(plan.tokens) * total
	interval := time.Second / time.Duration(plan.perSecond)
	start := time.Now()
	var first, last time.Time
	var launch sync.WaitGroup
	for i, token := range plan.tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			session := fmt.Sprintf("g490-open-%d", i)
			var onTime, late int
			var firstIssue, lastIssue time.Time
			for n := 0; n < total; n++ {
				slot := start.Add(time.Duration(n) * interval)
				if d := time.Until(slot); d > 0 {
					time.Sleep(d)
				}
				if plan.stall > 0 {
					time.Sleep(plan.stall)
				}
				issued := time.Now()
				if issued.Sub(slot) > interval {
					late++
				} else {
					onTime++
				}
				if firstIssue.IsZero() {
					firstIssue = issued
				}
				lastIssue = issued
				wg.Add(1)
				go call(token, session, n)
			}
			mu.Lock()
			defer mu.Unlock()
			result.onTime += onTime
			result.late += late
			if first.IsZero() || firstIssue.Before(first) {
				first = firstIssue
			}
			if lastIssue.After(last) {
				last = lastIssue
			}
		}()
	}
	launch.Wait()
	wg.Wait()
	if !first.IsZero() {
		result.window = last.Sub(first) + interval
	}
	return result
}

// openLoopMinCadence is the share of the required rate a stream has to have
// really issued on schedule before its answers say anything about a limit.
const openLoopMinCadence = 0.95

// openLoopVerdict is the judgement of one stream and its control.
type openLoopVerdict struct {
	kind   string // "ok", "inconclusive", "refused", "unanswered" or "skip"
	detail string
}

// judgeOpenLoop decides what the relay stream and its same-run control show.
// The offered cadence is judged first: a stream that did not issue the required
// rate on its absolute schedule did not challenge the limit, whatever it saw.
func judgeOpenLoop(plan openLoopPlan, got, control openLoopResult) openLoopVerdict {
	required := plan.required()
	sandboxes := len(plan.tokens)
	for _, side := range []struct {
		name   string
		result openLoopResult
	}{{"relay stream", got}, {"control stream", control}} {
		if side.result.achievedRate() < openLoopMinCadence*required {
			return openLoopVerdict{"inconclusive", fmt.Sprintf("INCONCLUSIVE: the %s of %d sandboxes at %d calls/s issued %.1f calls/s on its schedule (%d on time, %d late of %d, over %v), below %.0f%% of the required %.0f calls/s; the limit was not challenged, so this run says nothing about the gateway (%d calls refused with HTTP 429)",
				side.name, sandboxes, plan.perSecond, side.result.achievedRate(), side.result.onTime, side.result.late, side.result.offered,
				side.result.window.Round(time.Millisecond), openLoopMinCadence*100, required, got.refused)}
		}
	}
	if got.refused != 0 {
		return openLoopVerdict{"refused", fmt.Sprintf("%d sandboxes at %d calls/s (issued %.1f calls/s on schedule): %d of %d calls were refused with HTTP 429 (a rate limit, not load): %v",
			sandboxes, plan.perSecond, got.achievedRate(), got.refused, got.offered, got.problems)}
	}
	if len(got.latencies) != got.offered {
		// The runner carried the offered load when the control answered every
		// call of the same stream inside the same window.
		detail := fmt.Sprintf("%d sandboxes at %d calls/s: %d of %d calls unanswered inside %v (answered share %.3f; control answered share %.3f, control p95 %v): %v",
			sandboxes, plan.perSecond, got.offered-len(got.latencies), got.offered, openLoopWait,
			got.answeredShare(), control.answeredShare(), control.percentile(95), got.problems)
		if len(control.latencies) != control.offered {
			return openLoopVerdict{"skip", fmt.Sprintf("this runner cannot carry the offered load, so the stream says nothing about the gateway (the same stream straight to a handler that only answers: %d of %d calls answered inside %v, p95 %v): %s",
				len(control.latencies), control.offered, openLoopWait, control.percentile(95), detail)}
		}
		return openLoopVerdict{"unanswered", detail}
	}
	return openLoopVerdict{"ok", fmt.Sprintf("%d sandboxes at %d calls/s: %d calls issued at %.1f calls/s on schedule, p50 %v, p95 %v, max %v (control p95 %v)", sandboxes, plan.perSecond, len(got.latencies),
		got.achievedRate(), got.percentile(50), got.percentile(95), got.percentile(100), control.percentile(95))}
}

// streamOpenLoop drives the plan to the relay and, at the same time, to its
// control.
func streamOpenLoop(ctx context.Context, relay, control openLoopPost, plan openLoopPlan) (got, controlResult openLoopResult) {
	var controlDone sync.WaitGroup
	controlDone.Add(1)
	go func() {
		defer controlDone.Done()
		controlResult = driveOpenLoop(ctx, control, plan)
	}()
	got = driveOpenLoop(ctx, relay, plan)
	controlDone.Wait()
	return got, controlResult
}

// openLoopAnswerer is the control handler: it only answers.
func openLoopAnswerer(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get(sandboxrelay.HookReceiptHeader) != "" {
		_, _ = io.WriteString(w, `{}`)
		return
	}
	_, _ = io.WriteString(w, `{"action":"allow","delivery_receipt":"control"}`)
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
	control := httptest.NewServer(http.HandlerFunc(openLoopAnswerer))
	defer control.Close()
	post := newOpenLoopPost(srv.URL)
	// Warm the sessions: the first call of an unseen session waits for its
	// start, which is not what this test measures.
	for i, token := range tokens {
		session := fmt.Sprintf("g490-open-%d", i)
		warm, cancel := context.WithTimeout(t.Context(), openLoopWait)
		status, out, err := post(warm, token, []byte(managedHookBody(session, "UserPromptSubmit")), false)
		cancel()
		if err != nil || status != http.StatusOK {
			t.Fatalf("session start %d %s %v", status, out, err)
		}
	}
	plan := openLoopPlan{tokens: tokens, perSecond: perSecond, duration: duration}
	got, controlResult := streamOpenLoop(t.Context(), post, newOpenLoopPost(control.URL), plan)
	verdict := judgeOpenLoop(plan, got, controlResult)
	switch verdict.kind {
	case "ok":
		t.Log(verdict.detail)
	case "skip":
		t.Skip(verdict.detail)
	default:
		t.Fatal(verdict.detail)
	}
}

// openLoopCapStub stands in for a relay with an account rate cap: it answers a
// proposal with an allow and its receipt with an empty answer, and refuses a
// proposal with HTTP 429 once the cap (a token bucket of one second) is empty.
// A cap of 0 never refuses.
func openLoopCapStub(t *testing.T, callsPerSecond float64) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	tokens, last := callsPerSecond, time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if callsPerSecond > 0 && r.Header.Get(sandboxrelay.HookReceiptHeader) == "" {
			mu.Lock()
			now := time.Now()
			tokens = min(callsPerSecond, tokens+now.Sub(last).Seconds()*callsPerSecond)
			last = now
			admitted := tokens >= 1
			if admitted {
				tokens--
			}
			mu.Unlock()
			if !admitted {
				_, _ = io.Copy(io.Discard, r.Body)
				http.Error(w, "rate limited", http.StatusTooManyRequests)
				return
			}
		}
		openLoopAnswerer(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func openLoopStubPlan(sandboxes, perSecond int, duration, stall time.Duration) openLoopPlan {
	tokens := make([]string, sandboxes)
	for i := range tokens {
		tokens[i] = fmt.Sprintf("stub-%d", i)
	}
	return openLoopPlan{tokens: tokens, perSecond: perSecond, duration: duration, stall: stall}
}

// runOpenLoopStub judges the plan against a stand-in relay with the given cap
// and the usual answer-only control.
func runOpenLoopStub(t *testing.T, plan openLoopPlan, capPerSecond float64) (openLoopVerdict, openLoopResult) {
	t.Helper()
	relay := openLoopCapStub(t, capPerSecond)
	control := openLoopCapStub(t, 0)
	got, controlResult := streamOpenLoop(t.Context(), newOpenLoopPost(relay.URL), newOpenLoopPost(control.URL), plan)
	return judgeOpenLoop(plan, got, controlResult), got
}

// A stand-in with no cap, driven on schedule, passes: the benign twin of the
// two cap cases below.
func TestGAP0490OpenLoopCadenceBenignTwin(t *testing.T) {
	verdict, got := runOpenLoopStub(t, openLoopStubPlan(2, 22, 4*time.Second, 0), 0)
	if verdict.kind != "ok" {
		t.Fatalf("an uncapped stand-in driven at 2 x 22 calls/s was judged %s: %s", verdict.kind, verdict.detail)
	}
	if got.late != 0 {
		t.Logf("%d of %d calls were late on this runner (still above the required cadence)", got.late, got.offered)
	}
}

// A real 2 x 22 calls a second against a 30/s cap fails on the refusals, and
// on the rate the launcher really issued, not as INCONCLUSIVE.
func TestGAP0490OpenLoopCadenceCapFailsOnTheRealRate(t *testing.T) {
	verdict, got := runOpenLoopStub(t, openLoopStubPlan(2, 22, 4*time.Second, 0), 30)
	if verdict.kind != "refused" {
		t.Fatalf("a 30/s cap under 2 x 22 calls/s was judged %s, want refused: %s", verdict.kind, verdict.detail)
	}
	if got.refused == 0 || got.achievedRate() < openLoopMinCadence*44 {
		t.Fatalf("the refusal must come with the required cadence: %d refused, %.1f calls/s issued on schedule", got.refused, got.achievedRate())
	}
}

// A launcher held to about 20 calls a second never offers the 44 the test
// names, so a cap that would refuse the real stream is not challenged. The run
// is INCONCLUSIVE and fails with that word; it never passes. The 100 ms stall
// per launch is the way a delayed launcher gave a false pass in review.
func TestGAP0490OpenLoopCadenceSlowLauncherIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name         string
		plan         openLoopPlan
		capPerSecond float64
	}{
		{"two sandboxes against a 30/s account cap", openLoopStubPlan(2, 22, 2*time.Second, 100*time.Millisecond), 30},
		{"one sandbox against a 15/s cap", openLoopStubPlan(1, 22, 3*time.Second, 100*time.Millisecond), 15},
		{"two sandboxes with no cap", openLoopStubPlan(2, 22, 2*time.Second, 100*time.Millisecond), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict, got := runOpenLoopStub(t, tc.plan, tc.capPerSecond)
			if verdict.kind != "inconclusive" || !strings.Contains(verdict.detail, "INCONCLUSIVE") {
				t.Fatalf("a delayed launcher was judged %s, want inconclusive: %s", verdict.kind, verdict.detail)
			}
			if got.achievedRate() >= openLoopMinCadence*tc.plan.required() {
				t.Fatalf("the slowed launcher reached the required cadence (%.1f calls/s): %s", got.achievedRate(), verdict.detail)
			}
		})
	}
}
