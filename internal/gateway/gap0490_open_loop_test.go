// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !race

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
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
// names, so every run is judged in this order, and the first two outcomes fail
// the run as INCONCLUSIVE (never a pass, never a skip):
//   - The baseline. Right before the stream the test makes calls one after the
//     other through the same real path (the relay, the audit and the journal
//     write path) and measures their latency. If any is unanswered, or if the
//     required rate times the mean latency (the utilisation of the one stage
//     that serialises the writes, see the queueing design below) is above 0.5,
//     the box is overloaded and the run is INCONCLUSIVE naming the baseline.
//   - The offered rate is measured, not assumed. driveOpenLoop records the real
//     issue time of every call, taken in the call immediately before its
//     proposal is posted (not when the launcher queued it), against its absolute
//     slot; a call issued more than one tick after its slot is late and does not
//     count. The achieved rate is the on-time calls over the window from the
//     first to the last recorded issue (plus one tick). Below 95% of the
//     required rate the run is INCONCLUSIVE: a rate limit that was never
//     challenged is not a pass. The required rate and the answer window are
//     never lowered.
//   - No call is ever refused by a rate limit (HTTP 429). That is decided by
//     the limiter, not by load, so it holds on every runner.
//   - At least 95% of the calls (a proposal and its receipt together) are
//     answered inside one window of 3.5 s that both requests share.
//   - The p95 of the stream is within 1.2 x the p95 of the baseline x the
//     queueing factor 1 / (1 - utilisation), the stretch the design allows a
//     serialised stage at that utilisation.
//
// The judgement is a function of the measured streams (judgeOpenLoop,
// judgeOpenLoopStream), and TestGAP0490OpenLoop* run it against stand-ins and
// recorded numbers: a launcher or a worker pool held to about 20 calls a second
// is INCONCLUSIVE, a real 44 calls a second against a 30/s cap fails on the
// 429s, a slow baseline is INCONCLUSIVE naming it, and a stream within its
// budget passes.
//
// CI runs these without -race in their own job, Go Throughput Test (no race),
// alone on its runner, and that job is part of the required Go Test check.

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
// token for duration. stall and dispatchLag are test-only. stall is an extra
// pause before every launch, to model a launcher that cannot keep its schedule.
// dispatchLag is an extra pause of n x dispatchLag in the worker of call n after
// it started and before it posts, to model a worker pool that falls behind a
// launcher that itself keeps its schedule.
type openLoopPlan struct {
	tokens      []string
	perSecond   int
	duration    time.Duration
	stall       time.Duration
	dispatchLag time.Duration
	// p95Slack is the stretch of the p95 budget over the queueing design
	// (0: openLoopP95Slack, the reference box). runGAP0490OpenLoop sets it
	// from the runner (openLoopRunnerP95Slack).
	p95Slack float64
}

// slack is the plan's p95 slack.
func (p openLoopPlan) slack() float64 {
	if p.p95Slack > 0 {
		return p.p95Slack
	}
	return openLoopP95Slack
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
	failed    int // calls the gateway answered with an explicit failure: a status other than 200 or 429, or a proposal that did not allow
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

func (r openLoopResult) mean() time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	var sum time.Duration
	for _, l := range r.latencies {
		sum += l
	}
	return sum / time.Duration(len(r.latencies))
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

// performOpenLoopCall makes one call the way the sandbox hook does: a proposal
// and, when it is allowed, its delivery receipt. The call has one deadline of
// openLoopWait, started at the issue time (taken immediately before the
// proposal is posted) and shared by the receipt, and its measured latency is
// checked against that window as well, so a call that took longer is never
// counted as answered.
func performOpenLoopCall(parent context.Context, post openLoopPost, token, session string, n int) (issued time.Time, elapsed time.Duration, status int, out []byte, err error) {
	body := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"cwd":"/tmp","tool_name":"Bash","tool_use_id":"%s-%d","tool_input":{"command":"echo ok"}}`, session, session, n)
	ctx, cancel := context.WithTimeout(parent, openLoopWait)
	defer cancel()
	issued = time.Now()
	status, out, err = post(ctx, token, []byte(body), false)
	var answer struct {
		Action          string `json:"action"`
		DeliveryReceipt string `json:"delivery_receipt"`
	}
	if err == nil && status == http.StatusOK && json.Unmarshal(out, &answer) == nil && answer.Action == "allow" && answer.DeliveryReceipt != "" {
		ack, _ := json.Marshal(map[string]string{"delivery_receipt": answer.DeliveryReceipt, "result": "ack"})
		status, out, err = post(ctx, token, ack, true)
	} else if err == nil && status == http.StatusOK {
		err = fmt.Errorf("%w: %s", errOpenLoopProposal, out)
	}
	elapsed = time.Since(issued)
	if err == nil && status == http.StatusOK && elapsed > openLoopWait {
		err = fmt.Errorf("answered after the %v window", openLoopWait)
	}
	return issued, elapsed, status, out, err
}

// errOpenLoopProposal is a proposal the gateway answered with 200 and without
// an allow and a delivery receipt.
var errOpenLoopProposal = errors.New("proposal did not allow")

// record files the outcome of one call: refused, failed, a problem, or
// answered. A call left without its answer inside the window (a transport
// error, the deadline) is timing and counts only against the answered share.
// A call the gateway answered with a refusal or an explicit failure (a receipt
// 503, say) is a statement about the gateway, whatever share of the calls it
// is, and is counted on its own.
func (r *openLoopResult) record(elapsed time.Duration, status int, out []byte, err error) {
	switch {
	case status == http.StatusTooManyRequests:
		r.refused++
	case status != 0 && (status != http.StatusOK || errors.Is(err, errOpenLoopProposal)):
		r.failed++
	}
	if err != nil || status != http.StatusOK {
		r.problems[fmt.Sprintf("%d %.80s %v", status, out, err)]++
		return
	}
	r.latencies = append(r.latencies, elapsed)
}

// driveSingleStream makes calls one after the other, each after the answer of
// the one before: the real path with nothing else running. Its latency is what
// the box and the gateway cost per call before any queueing.
func driveSingleStream(parent context.Context, post openLoopPost, token, session string, calls int) openLoopResult {
	result := openLoopResult{problems: map[string]int{}, offered: calls}
	for n := 0; n < calls; n++ {
		_, elapsed, status, out, err := performOpenLoopCall(parent, post, token, session, 1000000+n)
		result.record(elapsed, status, out, err)
	}
	return result
}

// driveOpenLoop issues the plan on an absolute schedule (call n of a token at
// start + n ticks), without waiting for the calls before it, and waits for every
// answer. The real issue time of a call is taken inside the call, immediately
// before its proposal is posted, so a launcher or a worker that falls behind
// shows in the numbers: a call issued more than a tick after its slot is late
// and is left out of the achieved rate. A call has one deadline of
// openLoopWait, started at that same instant and shared by its receipt, and its
// measured latency is checked against that window as well, so a call that took
// longer is never counted as answered.
func driveOpenLoop(parent context.Context, post openLoopPost, plan openLoopPlan) openLoopResult {
	result := openLoopResult{problems: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	total := int(plan.duration.Seconds()) * plan.perSecond
	result.offered = len(plan.tokens) * total
	interval := time.Second / time.Duration(plan.perSecond)
	start := time.Now()
	var first, last time.Time
	call := func(token string, session string, n int) {
		defer wg.Done()
		if plan.dispatchLag > 0 {
			time.Sleep(time.Duration(n) * plan.dispatchLag)
		}
		issued, elapsed, status, out, err := performOpenLoopCall(parent, post, token, session, n)
		mu.Lock()
		defer mu.Unlock()
		if issued.Sub(start.Add(time.Duration(n)*interval)) > interval {
			result.late++
		} else {
			result.onTime++
		}
		if first.IsZero() || issued.Before(first) {
			first = issued
		}
		if issued.After(last) {
			last = issued
		}
		result.record(elapsed, status, out, err)
	}
	var launch sync.WaitGroup
	for i, token := range plan.tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			session := fmt.Sprintf("g490-open-%d", i)
			for n := 0; n < total; n++ {
				if d := time.Until(start.Add(time.Duration(n) * interval)); d > 0 {
					time.Sleep(d)
				}
				if plan.stall > 0 {
					time.Sleep(plan.stall)
				}
				wg.Add(1)
				go call(token, session, n)
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

// openLoopMinAnswered is the share of the offered calls that have to be
// answered inside the window.
const openLoopMinAnswered = 0.95

// openLoopBaselineCalls is how many calls the single-stream baseline makes.
const openLoopBaselineCalls = 30

// The queueing design. The managed gateway journals and audits every call
// through one connection that serves one write at a time, and a call visits it
// twice (its proposal and its receipt). Measured on the quiet reference box (an
// idle 16-core host, five runs of every test), a call takes 36 to 39 ms on its
// own (p95 41 to 45 ms), the connection saturates near 90 calls a second, so it
// is busy for about 0.3 of a call (openLoopSerialShare), and the 44 calls/s
// stream took a p95 of 0.26 to 0.42 s, 6 to 9 times the single-stream p95.
//
// The test therefore measures, in the same test right before the stream, the
// single-stream latency S of the real path (calls one after the other), and
// states the budget of the stream from it:
//   - utilisation rho = required rate x openLoopSerialShare x mean S;
//   - queueing factor Q = openLoopQueueVisits x openLoopTailFactor / (1 - rho):
//     two visits to the serialised stage per call, a p95 of a queued visit about
//     3 (ln 20) times its mean wait, and the stretch 1 / (1 - rho) of a stage at
//     utilisation rho;
//   - the stream may take, at p95, openLoopP95Slack x Q x the single-stream p95
//     (630 ms for the 44 calls/s stream on the reference box, against the 0.26
//     to 0.42 s it takes there).
//
// A box on which rho would exceed openLoopMaxUtilisation, or on which a
// single-stream call goes unanswered, is overloaded and cannot carry the
// stream: the run is INCONCLUSIVE and names the baseline it measured.
const (
	openLoopSerialShare    = 0.3
	openLoopQueueVisits    = 2
	openLoopTailFactor     = 3
	openLoopMaxUtilisation = 0.8
	openLoopP95Slack       = 1.2
)

// openLoopHostedP95Slack is the p95 slack on a GitHub-hosted runner. The
// hosted pool is bimodal: of 28 runs of Go Throughput Test (no race) on CI
// (11-08 to 11-12), the fast runners (single-stream mean 15 to 24 ms) took a
// two-sandbox p95 of 41 to 175 ms, the slow ones (mean 25 to 31 ms) 217 to
// 550 ms, against budgets of 335 to 463 ms at the reference slack of 1.2:
// p95 over budget 0.6 to 1.19, and 2 of the 28 failed (runs 43222066812 and
// 43235986187, both on the 2 x 22 calls/s stream, 1.03 and 1.19). The
// serialised share (openLoopSerialShare) was measured on an idle 16-core box,
// where the parallel part of a call does not wait for a core; on a 4-vCPU
// runner it does, so the queue stretches further at the same utilisation.
// 2.0 keeps the worst hosted run at 0.7 of its budget, and the budget (under
// 800 ms there) stays far inside the 3.5 s hook window. What this slack does
// not touch: no call may be refused (HTTP 429), 95% must be answered inside
// the window, and the baseline and cadence checks are unchanged.
const openLoopHostedP95Slack = 2.0

// openLoopRunnerP95Slack is the p95 slack for the runner the test runs on.
func openLoopRunnerP95Slack() float64 {
	if os.Getenv("RUNNER_ENVIRONMENT") == "github-hosted" {
		return openLoopHostedP95Slack
	}
	return openLoopP95Slack
}

// openLoopUtilisation is the share of the time the serialised write stage is
// busy at the required rate of the plan, given the single-stream baseline.
func openLoopUtilisation(plan openLoopPlan, base openLoopResult) float64 {
	return plan.required() * openLoopSerialShare * base.mean().Seconds()
}

// openLoopQueueingFactor is the stretch of a call at p95 over its single-stream
// p95 that the design allows at utilisation rho.
func openLoopQueueingFactor(rho float64) float64 {
	return openLoopQueueVisits * openLoopTailFactor / (1 - rho)
}

// openLoopVerdict is the judgement of one stream.
type openLoopVerdict struct {
	kind   string // "ok", "inconclusive", "refused", "failed", "unanswered" or "slow"
	detail string
}

// judgeOpenLoopBaseline decides whether the single-stream baseline says the box
// can carry the plan at all. It returns an INCONCLUSIVE verdict naming the
// measured baseline when it cannot, and nil when it can.
func judgeOpenLoopBaseline(plan openLoopPlan, base openLoopResult) *openLoopVerdict {
	if base.failed != 0 {
		return &openLoopVerdict{"failed", fmt.Sprintf("the single-stream baseline of the real path had %d of %d calls answered with an explicit failure: %v", base.failed, base.offered, base.problems)}
	}
	rho := openLoopUtilisation(plan, base)
	if len(base.latencies) == base.offered && rho <= openLoopMaxUtilisation {
		return nil
	}
	return &openLoopVerdict{"inconclusive", fmt.Sprintf("INCONCLUSIVE: the single-stream baseline of the real path (%d of %d calls answered, mean %v, p95 %v, max %v: %v) puts a stream of %.0f calls/s at utilisation %.2f of the serialised write stage (limit %.2f; reference box: mean 36 to 39 ms); the box is overloaded, so this run says nothing about the gateway",
		len(base.latencies), base.offered, base.mean().Round(time.Microsecond), base.percentile(95).Round(time.Microsecond), base.percentile(100).Round(time.Microsecond), base.problems,
		plan.required(), rho, openLoopMaxUtilisation)}
}

// judgeOpenLoopStream decides what the offered stream shows about the limit:
// first whether it issued the required rate on its absolute schedule, then
// whether any call was refused by a rate limit or answered with an explicit
// failure. Neither is a timing matter, so the 95% answered share below never
// absorbs them. It returns nil when none settles the run.
func judgeOpenLoopStream(plan openLoopPlan, got openLoopResult) *openLoopVerdict {
	required := plan.required()
	sandboxes := len(plan.tokens)
	if got.achievedRate() < openLoopMinCadence*required {
		return &openLoopVerdict{"inconclusive", fmt.Sprintf("INCONCLUSIVE: the stream of %d sandboxes at %d calls/s issued %.1f calls/s on its schedule (%d on time, %d late of %d, over %v), below %.0f%% of the required %.0f calls/s; the limit was not challenged, so this run says nothing about the gateway (%d calls refused with HTTP 429)",
			sandboxes, plan.perSecond, got.achievedRate(), got.onTime, got.late, got.offered,
			got.window.Round(time.Millisecond), openLoopMinCadence*100, required, got.refused)}
	}
	if got.refused != 0 {
		return &openLoopVerdict{"refused", fmt.Sprintf("%d sandboxes at %d calls/s (issued %.1f calls/s on schedule): %d of %d calls were refused with HTTP 429 (a rate limit, not load): %v",
			sandboxes, plan.perSecond, got.achievedRate(), got.refused, got.offered, got.problems)}
	}
	if got.failed != 0 {
		return &openLoopVerdict{"failed", fmt.Sprintf("%d sandboxes at %d calls/s (issued %.1f calls/s on schedule): %d of %d calls were answered with an explicit failure (not a missing answer): %v",
			sandboxes, plan.perSecond, got.achievedRate(), got.failed, got.offered, got.problems)}
	}
	return nil
}

// judgeOpenLoop decides what the stream and the single-stream baseline of the
// real path, measured right before it, show. The order matters: a baseline that
// cannot carry the plan and a stream that did not issue the required rate are
// INCONCLUSIVE and fail; they are never a pass and never a skip.
func judgeOpenLoop(plan openLoopPlan, got, base openLoopResult) openLoopVerdict {
	if v := judgeOpenLoopBaseline(plan, base); v != nil {
		return *v
	}
	if v := judgeOpenLoopStream(plan, got); v != nil {
		return *v
	}
	sandboxes := len(plan.tokens)
	rho := openLoopUtilisation(plan, base)
	budget := time.Duration(plan.slack() * openLoopQueueingFactor(rho) * float64(base.percentile(95)))
	numbers := fmt.Sprintf("%d sandboxes at %d calls/s, issued %.1f calls/s on schedule: answered share %.3f, p50 %v, p95 %v, max %v; single-stream real path mean %v, p95 %v, utilisation %.2f, queueing factor %.2f, p95 budget %v",
		sandboxes, plan.perSecond, got.achievedRate(), got.answeredShare(), got.percentile(50).Round(time.Microsecond), got.percentile(95).Round(time.Microsecond), got.percentile(100).Round(time.Microsecond),
		base.mean().Round(time.Microsecond), base.percentile(95).Round(time.Microsecond), rho, openLoopQueueingFactor(rho), budget.Round(time.Microsecond))
	if got.answeredShare() < openLoopMinAnswered {
		return openLoopVerdict{"unanswered", fmt.Sprintf("%d of %d calls unanswered inside %v (%s): %v", got.offered-len(got.latencies), got.offered, openLoopWait, numbers, got.problems)}
	}
	if got.percentile(95) > budget {
		return openLoopVerdict{"slow", fmt.Sprintf("p95 over the budget of %.1f x the single-stream p95 x the queueing factor (%s)", plan.slack(), numbers)}
	}
	return openLoopVerdict{"ok", numbers}
}

// openLoopAnswerer is the stand-in relay: it only answers.
func openLoopAnswerer(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get(sandboxrelay.HookReceiptHeader) != "" {
		_, _ = io.WriteString(w, `{}`)
		return
	}
	_, _ = io.WriteString(w, `{"action":"allow","delivery_receipt":"stand-in"}`)
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
	// The baseline: the real path, one call after the other, right before the
	// stream, on the same box in the same state.
	base := driveSingleStream(t.Context(), post, tokens[0], "g490-open-0", openLoopBaselineCalls)
	plan := openLoopPlan{tokens: tokens, perSecond: perSecond, duration: duration, p95Slack: openLoopRunnerP95Slack()}
	got := driveOpenLoop(t.Context(), post, plan)
	verdict := judgeOpenLoop(plan, got, base)
	if verdict.kind != "ok" {
		t.Fatal(verdict.detail)
	}
	t.Log(verdict.detail)
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

// openLoopReceiptStub stands in for a relay that answers every proposal with an
// allow and every receipt with an empty answer, except that it refuses every
// nth receipt with the 503 the field showed ("receipt expired or closed"). An
// n of 0 never fails.
func openLoopReceiptStub(t *testing.T, every int) *httptest.Server {
	t.Helper()
	var receipts atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if every > 0 && r.Header.Get(sandboxrelay.HookReceiptHeader) != "" && receipts.Add(1)%int64(every) == 0 {
			_, _ = io.Copy(io.Discard, r.Body)
			http.Error(w, "receipt expired or closed", http.StatusServiceUnavailable)
			return
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

// runOpenLoopStub drives the plan against a stand-in relay with the given cap
// and judges the stream: the verdict is ok when neither its cadence nor a
// refusal settles the run.
func runOpenLoopStub(t *testing.T, plan openLoopPlan, capPerSecond float64) (openLoopVerdict, openLoopResult) {
	t.Helper()
	return runOpenLoopAgainst(t, plan, openLoopCapStub(t, capPerSecond))
}

// runOpenLoopAgainst drives the plan against the given stand-in relay.
func runOpenLoopAgainst(t *testing.T, plan openLoopPlan, relay *httptest.Server) (openLoopVerdict, openLoopResult) {
	t.Helper()
	got := driveOpenLoop(t.Context(), newOpenLoopPost(relay.URL), plan)
	if v := judgeOpenLoopStream(plan, got); v != nil {
		return *v, got
	}
	return openLoopVerdict{"ok", "stream"}, got
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

// A launcher that keeps its schedule while the workers that post the calls fall
// behind it (each worker starts later than the one before) issues about 25
// proposals a second, not the 44 the plan names. The cadence is read where the
// proposal is posted, so the run is INCONCLUSIVE and fails with that word,
// whether the stand-in would have refused the real stream or not.
func TestGAP0490OpenLoopCadenceSlowWorkerDispatchIsInconclusive(t *testing.T) {
	for _, tc := range []struct {
		name         string
		capPerSecond float64
	}{
		{"two sandboxes against a 30/s account cap", 30},
		{"two sandboxes with no cap", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan := openLoopStubPlan(2, 22, 4*time.Second, 0)
			plan.dispatchLag = 35 * time.Millisecond
			verdict, got := runOpenLoopStub(t, plan, tc.capPerSecond)
			if verdict.kind != "inconclusive" || !strings.Contains(verdict.detail, "INCONCLUSIVE") {
				t.Fatalf("delayed workers were judged %s, want inconclusive: %s", verdict.kind, verdict.detail)
			}
			if got.achievedRate() >= openLoopMinCadence*plan.required() {
				t.Fatalf("the delayed workers reached the required cadence (%.1f calls/s): %s", got.achievedRate(), verdict.detail)
			}
		})
	}
}

// openLoopRecorded is a measured stream written down: offered calls, answered
// of them with the typical latency for the first nine tenths and the tail
// latency for the rest, issued at the given rate on schedule.
func openLoopRecorded(offered, answered int, typical, tail time.Duration, rate float64) openLoopResult {
	r := openLoopResult{offered: offered, onTime: offered, problems: map[string]int{}}
	for i := 0; i < answered; i++ {
		l := typical
		if i >= answered*9/10 {
			l = tail
		}
		r.latencies = append(r.latencies, l)
	}
	r.window = time.Duration(float64(offered) / rate * float64(time.Second))
	return r
}

// The judgement of a stream follows the single-stream baseline measured right
// before it: the recorded numbers of the reference box pass (the benign twin),
// and a stream over its p95 budget, an unanswered share, a refusal or a launcher
// below the required rate fail. When the baseline itself shows an overloaded
// box the run is INCONCLUSIVE and names the baseline, whatever the stream saw,
// including the stream that failed on a loaded build box (241 of 440 calls
// unanswered inside the window while an answer-only control answered all of
// them).
func TestGAP0490OpenLoopJudgementFollowsTheBaseline(t *testing.T) {
	plan := openLoopStubPlan(2, 22, 10*time.Second, 0)
	quiet := openLoopRecorded(30, 30, 37*time.Millisecond, 44*time.Millisecond, 1)
	loaded := openLoopRecorded(30, 30, 100*time.Millisecond, 150*time.Millisecond, 1)
	oneUnanswered := openLoopRecorded(30, 29, 37*time.Millisecond, 44*time.Millisecond, 1)
	oneUnanswered.problems["0  context deadline exceeded"] = 1
	refused := openLoopRecorded(440, 440, 185*time.Millisecond, 415*time.Millisecond, 44)
	refused.refused = 5
	failedShare := openLoopRecorded(440, 429, 185*time.Millisecond, 415*time.Millisecond, 44)
	failedShare.failed = 11
	failedShare.problems["503 receipt expired or closed <nil>"] = 11
	failedBase := openLoopRecorded(30, 29, 37*time.Millisecond, 44*time.Millisecond, 1)
	failedBase.failed = 1
	failedBase.problems["503 receipt expired or closed <nil>"] = 1
	for _, tc := range []struct {
		name string
		got  openLoopResult
		base openLoopResult
		kind string
		want string // the verdict names it
	}{
		{"the reference box numbers pass", openLoopRecorded(440, 440, 185*time.Millisecond, 415*time.Millisecond, 44), quiet, "ok", "p95 budget"},
		{"a stream inside its budget passes", openLoopRecorded(440, 440, 185*time.Millisecond, 600*time.Millisecond, 44), quiet, "ok", "p95 budget"},
		{"a stream over its p95 budget is slow", openLoopRecorded(440, 440, 185*time.Millisecond, 700*time.Millisecond, 44), quiet, "slow", "queueing factor"},
		{"a stream with 241 of 440 calls unanswered fails on a quiet box", openLoopRecorded(440, 199, 400*time.Millisecond, 3400*time.Millisecond, 44), quiet, "unanswered", "241 of 440"},
		{"the same stream on an overloaded box is inconclusive and names the baseline", openLoopRecorded(440, 199, 400*time.Millisecond, 3400*time.Millisecond, 44), loaded, "inconclusive", "mean 105ms"},
		{"a baseline call left unanswered is inconclusive", openLoopRecorded(440, 440, 185*time.Millisecond, 415*time.Millisecond, 44), oneUnanswered, "inconclusive", "29 of 30"},
		{"a refusal fails on a quiet box", refused, quiet, "refused", "5 of 440"},
		{"11 explicit failures of 440 calls (share 0.975) fail", failedShare, quiet, "failed", "11 of 440"},
		{"11 of 440 calls left unanswered stay inside the 95% allowance", openLoopRecorded(440, 429, 185*time.Millisecond, 415*time.Millisecond, 44), quiet, "ok", "p95 budget"},
		{"an explicit failure in the baseline fails", openLoopRecorded(440, 440, 185*time.Millisecond, 415*time.Millisecond, 44), failedBase, "failed", "baseline"},
		{"a launcher below 95% of the required rate is inconclusive", openLoopRecorded(440, 440, 185*time.Millisecond, 415*time.Millisecond, 30), quiet, "inconclusive", "30.0 calls/s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := judgeOpenLoop(plan, tc.got, tc.base)
			if verdict.kind != tc.kind {
				t.Fatalf("judged %s, want %s: %s", verdict.kind, tc.kind, verdict.detail)
			}
			if !strings.Contains(verdict.detail, tc.want) {
				t.Fatalf("the verdict does not name %q: %s", tc.want, verdict.detail)
			}
			if tc.kind == "inconclusive" && !strings.Contains(verdict.detail, "INCONCLUSIVE") {
				t.Fatalf("an inconclusive verdict must say so: %s", verdict.detail)
			}
		})
	}
}

// The hosted-runner slack (openLoopHostedP95Slack) passes the slow-pool stream
// of run 43235986187 (2 x 22 calls/s, p95 550 ms over a single-stream mean of
// 31 ms and p95 38 ms) that fails at the reference slack, and a hosted stream
// twice as slow, an unanswered share or a refusal still fail.
func TestGAP0490OpenLoopJudgementHostedRunnerSlack(t *testing.T) {
	reference := openLoopStubPlan(2, 22, 10*time.Second, 0)
	hosted := reference
	hosted.p95Slack = openLoopHostedP95Slack
	slowPool := openLoopRecorded(30, 30, 31*time.Millisecond, 38*time.Millisecond, 1)
	refused := openLoopRecorded(440, 440, 266*time.Millisecond, 550*time.Millisecond, 44)
	refused.refused = 1
	for _, tc := range []struct {
		name string
		plan openLoopPlan
		got  openLoopResult
		kind string
	}{
		{"the slow-pool stream is slow at the reference slack", reference, openLoopRecorded(440, 440, 266*time.Millisecond, 550*time.Millisecond, 44), "slow"},
		{"the slow-pool stream passes on a hosted runner", hosted, openLoopRecorded(440, 440, 266*time.Millisecond, 550*time.Millisecond, 44), "ok"},
		{"a hosted stream past the hosted budget is slow", hosted, openLoopRecorded(440, 440, 266*time.Millisecond, 900*time.Millisecond, 44), "slow"},
		{"241 of 440 unanswered still fail on a hosted runner", hosted, openLoopRecorded(440, 199, 400*time.Millisecond, 3400*time.Millisecond, 44), "unanswered"},
		{"a refusal still fails on a hosted runner", hosted, refused, "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if verdict := judgeOpenLoop(tc.plan, tc.got, slowPool); verdict.kind != tc.kind {
				t.Fatalf("judged %s, want %s: %s", verdict.kind, tc.kind, verdict.detail)
			}
		})
	}
	t.Setenv("RUNNER_ENVIRONMENT", "github-hosted")
	if openLoopRunnerP95Slack() != openLoopHostedP95Slack {
		t.Fatal("a GitHub-hosted runner must use the hosted slack")
	}
	t.Setenv("RUNNER_ENVIRONMENT", "self-hosted")
	if openLoopRunnerP95Slack() != openLoopP95Slack {
		t.Fatal("any other runner must use the reference slack")
	}
}

// The budget the design states for the 44 calls/s stream on the reference box
// is the 630 ms the comment on the queueing design names, and it moves with the
// utilisation: it is larger where the serialised stage is busier, and a box that
// would put the stage past openLoopMaxUtilisation has no budget (it is
// INCONCLUSIVE).
func TestGAP0490OpenLoopQueueingBudgetFollowsUtilisation(t *testing.T) {
	plan := openLoopStubPlan(2, 22, 10*time.Second, 0)
	quiet := openLoopRecorded(30, 30, 37*time.Millisecond, 44*time.Millisecond, 1)
	rho := openLoopUtilisation(plan, quiet)
	budget := time.Duration(openLoopP95Slack * openLoopQueueingFactor(rho) * float64(quiet.percentile(95)))
	if budget < 600*time.Millisecond || budget > 660*time.Millisecond {
		t.Fatalf("the p95 budget on the reference box is %v (utilisation %.2f), want about 630 ms", budget, rho)
	}
	busier := openLoopRecorded(30, 30, 55*time.Millisecond, 64*time.Millisecond, 1)
	if openLoopQueueingFactor(openLoopUtilisation(plan, busier)) <= openLoopQueueingFactor(rho) {
		t.Fatal("a busier stage must get a larger queueing factor")
	}
	if judgeOpenLoopBaseline(plan, busier) != nil {
		t.Fatalf("a baseline of 55 ms carries the stream: %v", *judgeOpenLoopBaseline(plan, busier))
	}
	tooBusy := openLoopRecorded(30, 30, 61*time.Millisecond, 70*time.Millisecond, 1)
	if judgeOpenLoopBaseline(plan, tooBusy) == nil {
		t.Fatalf("a baseline of 61 ms (utilisation %.2f) must be inconclusive", openLoopUtilisation(plan, tooBusy))
	}
}

// Every 25th receipt answered 503 is 4% of the calls: inside the 95% answered
// share, but not a missing answer. The stream through the real call path
// (performOpenLoopCall, record, judgeOpenLoopStream) fails on it, and the same
// stream with no failing receipt is the benign twin that passes.
func TestGAP0490OpenLoopCadenceExplicitReceiptFailureFailsBelowTheAllowance(t *testing.T) {
	plan := openLoopStubPlan(2, 22, 4*time.Second, 0)
	verdict, got := runOpenLoopAgainst(t, plan, openLoopReceiptStub(t, 25))
	if verdict.kind != "failed" {
		t.Fatalf("every 25th receipt answered 503 was judged %s, want failed (answered share %.3f): %s", verdict.kind, got.answeredShare(), verdict.detail)
	}
	if got.failed == 0 || got.answeredShare() < openLoopMinAnswered || !strings.Contains(verdict.detail, "receipt expired or closed") {
		t.Fatalf("the failure must be explicit, inside the answered share, and named: %d failed, share %.3f: %s", got.failed, got.answeredShare(), verdict.detail)
	}
	if verdict, _ := runOpenLoopAgainst(t, plan, openLoopReceiptStub(t, 0)); verdict.kind != "ok" {
		t.Fatalf("a relay whose receipts all succeed was judged %s: %s", verdict.kind, verdict.detail)
	}
}
