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
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
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
// names, so every run is judged in this order, and the first two outcomes are
// INCONCLUSIVE (never a pass). An INCONCLUSIVE run is a skip that names
// rel-1-0-10 GAP-1456 and the measured numbers only when a probe that does not
// touch the gateway confirms the box was short of CPU (openLoopBoxProbe, read
// right before the baseline, between the baseline and the stream, and after the
// teardown: a spin on its own OS thread got less than openLoopProbeMinShare of a
// core, or the Linux CPU pressure of the box was openLoopProbeMaxPressure or
// more), and so are the two timing outcomes below (unanswered, over the p95
// budget) on such a box; on a box the probe finds quiet they fail,
// because the slow real path is then the gateway's own:
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
// Every test has its own deadline (openLoopTestDeadline, from its first call to
// its teardown) and every phase in it a bound of its own, so a starved box ends
// the test in about a minute and a half with its numbers; it never waits for
// the package timeout (rel-1-0-10 GAP-1456: under load the package ran into its
// 30 to 60 min timeout while these tests ran).
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

// The four-sandbox stream at the 1.0.9 account budget (4 x 10 = 40 calls a
// second): the managed gateway
// answers it inside the hook window of 3.5 s (p95 under a second on the shared
// build box). 96 calls a second (4 x 24) did not answer in time in half the
// runs there: a rate above the budget is refused at once with a 429 that
// names the budget (TestGAP0490RefusalNamesTheBudget), and raising the budget
// is a 1.0.10 performance row (rel-1-0-6 GAP-0490).
func TestGAP0490OpenLoopFourSandboxes(t *testing.T) {
	runGAP0490OpenLoop(t, 4, 10, 10*time.Second)
}

// TestGAP0490OpenLoopFourSandboxesAtTheAccountBudget is the same stream at
// the 1.0.10 account budget, 4 x 25 = 100 calls a second (rel-1-0-6
// GAP-0770, bar H1). It is opt-in (DC_GAP0490_OPEN_LOOP_BUDGET=1) until the
// one-record-per-decision change cuts the serialised write stage enough for
// a shared runner (S8 RESULTS.md: utilisation 1.77 of the write stage on the
// build box today).
func TestGAP0490OpenLoopFourSandboxesAtTheAccountBudget(t *testing.T) {
	if os.Getenv("DC_GAP0490_OPEN_LOOP_BUDGET") != "1" {
		t.Skip("set DC_GAP0490_OPEN_LOOP_BUDGET=1 to drive 4 x 25 calls a second")
	}
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
	// cores is the CPUs the gateway and the launcher share (GOMAXPROCS of
	// the test process); 0 leaves the CPU stage out of the budget.
	cores int
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
	// calls is each stream call's issue time, time to its answer and
	// whether it was answered (GAP-1041: the window a stall must overlap).
	calls   []openLoopCall
	refused int // calls whose proposal or receipt got HTTP 429
	failed  int // calls the gateway answered with an explicit failure: a status other than 200 or 429, or a proposal that did not allow
	// cpuPerCall is the process CPU time (user and system) one call of the
	// single-stream baseline took, launcher included; 0 when not measured.
	cpuPerCall time.Duration
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
		if err := parent.Err(); err != nil {
			// Past its deadline the baseline stops: the calls it never made
			// stay offered and unanswered.
			result.problems[fmt.Sprintf("%d calls not made: %v", calls-n, err)]++
			break
		}
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
		answered := len(result.latencies)
		result.record(elapsed, status, out, err)
		result.calls = append(result.calls, openLoopCall{issued: issued, elapsed: elapsed, answered: len(result.latencies) > answered})
	}
	var launch sync.WaitGroup
	for i, token := range plan.tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			session := fmt.Sprintf("g490-open-%d", i)
			for n := 0; n < total; n++ {
				// Past its deadline the launcher stops: the calls it never
				// issued stay offered and unanswered, and the achieved rate
				// says the stream fell short.
				if d := time.Until(start.Add(time.Duration(n) * interval)); d > 0 {
					select {
					case <-time.After(d):
					case <-parent.Done():
						return
					}
				} else if parent.Err() != nil {
					return
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
// The serialised share was measured on an idle 16-core box, where the rest of
// a call never waits for a core. On a box with few cores it does: the stream
// keeps the CPUs busy for its rate x the CPU time of a call, and the writer
// of the serialised stage then waits for a core as well, so every visit to
// it stretches by 1 / (1 - the CPU utilisation). The test measures that CPU
// time in the baseline (process user and system time over its calls) and
// multiplies the budget by that stretch:
//   - CPU utilisation rhoCPU = required rate x CPU per call / cores.
//
// CI showed why (Go Throughput Test (no race), 28 runs 11-08..11-12): on the
// 4-vCPU hosted runners the two-sandbox stream (44 calls/s) took a p95 of
// 217 to 550 ms where the baseline mean was 25 to 31 ms, and failed 2 runs
// at 1.03 and 1.19 of a budget without this term (runs 43222066812,
// 43235986187). A block profile of that stream shows the wait in the audit
// write group (writeGroup.do, the proposal and its receipt), not in the
// per-session correlation turn, and its process used 1.3 cores. On a box
// with many cores the stretch is near 1 and the budget is the design's.
//
// A box on which rho or rhoCPU would exceed openLoopMaxUtilisation, or on
// which a single-stream call goes unanswered, is overloaded and cannot carry
// the stream: the run is INCONCLUSIVE and names the baseline it measured.
const (
	openLoopSerialShare    = 0.3
	openLoopQueueVisits    = 2
	openLoopTailFactor     = 3
	openLoopMaxUtilisation = 0.8
	openLoopP95Slack       = 1.2
)

// openLoopUtilisation is the share of the time the serialised write stage is
// busy at the required rate of the plan, given the single-stream baseline.
func openLoopUtilisation(plan openLoopPlan, base openLoopResult) float64 {
	return plan.required() * openLoopSerialShare * base.mean().Seconds()
}

// openLoopCPUUtilisation is the share of the cores the stream keeps busy at
// the required rate of the plan, given the CPU time of a baseline call; 0
// when either is unknown.
func openLoopCPUUtilisation(plan openLoopPlan, base openLoopResult) float64 {
	if plan.cores <= 0 || base.cpuPerCall <= 0 {
		return 0
	}
	return plan.required() * base.cpuPerCall.Seconds() / float64(plan.cores)
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
	rhoCPU := openLoopCPUUtilisation(plan, base)
	if len(base.latencies) == base.offered && rho <= openLoopMaxUtilisation && rhoCPU <= openLoopMaxUtilisation {
		return nil
	}
	return &openLoopVerdict{"inconclusive", fmt.Sprintf("INCONCLUSIVE: the single-stream baseline of the real path (%d of %d calls answered, mean %v, p95 %v, max %v, CPU per call %v: %v) puts a stream of %.0f calls/s at utilisation %.2f of the serialised write stage and %.2f of %d cores (limit %.2f; reference box: mean 36 to 39 ms); the box is overloaded, so this run says nothing about the gateway",
		len(base.latencies), base.offered, base.mean().Round(time.Microsecond), base.percentile(95).Round(time.Microsecond), base.percentile(100).Round(time.Microsecond), base.cpuPerCall.Round(time.Microsecond), base.problems,
		plan.required(), rho, rhoCPU, plan.cores, openLoopMaxUtilisation)}
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
	rhoCPU := openLoopCPUUtilisation(plan, base)
	budget := openLoopBudget(plan, base)
	numbers := fmt.Sprintf("%d sandboxes at %d calls/s, issued %.1f calls/s on schedule: answered share %.3f, p50 %v, p95 %v, max %v; single-stream real path mean %v, p95 %v, CPU per call %v, utilisation %.2f, queueing factor %.2f, CPU utilisation %.2f of %d cores, p95 budget %v",
		sandboxes, plan.perSecond, got.achievedRate(), got.answeredShare(), got.percentile(50).Round(time.Microsecond), got.percentile(95).Round(time.Microsecond), got.percentile(100).Round(time.Microsecond),
		base.mean().Round(time.Microsecond), base.percentile(95).Round(time.Microsecond), base.cpuPerCall.Round(time.Microsecond), rho, openLoopQueueingFactor(rho), rhoCPU, plan.cores, budget.Round(time.Microsecond))
	if got.answeredShare() < openLoopMinAnswered {
		return openLoopVerdict{"unanswered", fmt.Sprintf("%d of %d calls unanswered inside %v (%s): %v", got.offered-len(got.latencies), got.offered, openLoopWait, numbers, got.problems)}
	}
	if got.percentile(95) > budget {
		return openLoopVerdict{"slow", fmt.Sprintf("p95 over the budget of %.1f x the single-stream p95 x the queueing factor (%s)", openLoopP95Slack, numbers)}
	}
	return openLoopVerdict{"ok", numbers}
}

// openLoopBudget is the p95 a stream may have: the slack times the queueing
// factor of the serialised stage times the single-stream p95, stretched by
// the CPU the stream leaves free.
func openLoopBudget(plan openLoopPlan, base openLoopResult) time.Duration {
	return time.Duration(openLoopP95Slack * openLoopQueueingFactor(openLoopUtilisation(plan, base)) / (1 - openLoopCPUUtilisation(plan, base)) * float64(base.percentile(95)))
}

// openLoopCall is one stream call.
type openLoopCall struct {
	issued   time.Time
	elapsed  time.Duration
	answered bool
}

// openLoopSpan is a stretch of wall time.
type openLoopSpan struct{ from, to time.Time }

func (a openLoopSpan) overlaps(b openLoopSpan) bool {
	return !a.to.Before(b.from) && !b.to.Before(a.from)
}

// without is the stream with the calls whose window overlaps one of spans set
// aside: an answered call's wait, an unanswered call's answer window. A call
// the launcher never issued stays offered and unanswered. left is how many
// calls were set aside.
func (r openLoopResult) without(spans []openLoopSpan) (rest openLoopResult, left int) {
	rest = openLoopResult{offered: r.offered}
	for _, c := range r.calls {
		w := openLoopSpan{c.issued, c.issued.Add(openLoopWait)}
		if c.answered {
			w.to = c.issued.Add(c.elapsed)
		}
		if openLoopAnyOverlap(w, spans) {
			rest.offered--
			left++
			continue
		}
		rest.calls = append(rest.calls, c)
		if c.answered {
			rest.latencies = append(rest.latencies, c.elapsed)
		}
	}
	return rest, left
}

// openLoopTiming is what a timing verdict (unanswered or slow) is judged on
// again once the calls a disk stall overlaps are set aside: the stream and
// its p95 budget.
type openLoopTiming struct {
	got    openLoopResult
	budget time.Duration
}

// passesWithout judges the stream again without the calls whose window
// overlaps one of spans: it passes when the rest are answered at
// openLoopMinAnswered or more and their p95 is inside the budget. It also
// says what the rest showed.
func (t openLoopTiming) passesWithout(spans []openLoopSpan) (bool, string) {
	rest, left := t.got.without(spans)
	ok := rest.answeredShare() >= openLoopMinAnswered && rest.percentile(95) <= t.budget
	return ok, fmt.Sprintf("without the %d calls a counted disk stall overlaps: %d of %d answered (share %.3f, need %.2f), p95 %v (budget %v)",
		left, len(rest.latencies), rest.offered, rest.answeredShare(), openLoopMinAnswered, rest.percentile(95).Round(time.Microsecond), t.budget.Round(time.Microsecond))
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

// The bounds of one open-loop test (rel-1-0-10 GAP-1456). The whole test, from
// its first call to its teardown, ends inside openLoopTestDeadline; inside it
// the baseline has openLoopBaselineDeadline (its 30 calls take about 1.2 s on
// the reference box), the stream its duration plus one answer window plus
// openLoopStreamSlack, and the teardown openLoopTeardownDeadline to see every
// request the ingress still holds end. None of them decides a pass: they only
// end a starved run early, and a run they end is judged on what it measured.
const (
	openLoopTestDeadline     = 90 * time.Second
	openLoopBaselineDeadline = 30 * time.Second
	openLoopStreamSlack      = 5 * time.Second
	openLoopTeardownDeadline = 20 * time.Second
)

// The box probe. A spin on its own OS thread for openLoopProbeSpin gets about
// one core on a box with a core to spare; a box whose cores are all busy (other
// test binaries, a CPU burner, or fewer cores than this process runs threads
// on) gives it less. Below openLoopProbeMinShare of a core the box is short of
// CPU, which says nothing about the gateway: the probe never calls it. The
// scheduler can still hand one fresh thread a whole core on a box whose cores
// are all taken (it read 1.00 with four burners a core), so on Linux the probe
// also reads the CPU pressure of the box over the same window
// (/proc/pressure/cpu, the share of the time some task waited for a core): at
// openLoopProbeMaxPressure or more the box is short of CPU as well. The
// gateway is idle while the probe runs.
const (
	openLoopProbeSpin        = 200 * time.Millisecond
	openLoopProbeMinShare    = 0.7
	openLoopProbeMaxPressure = 0.5
	// The calls the gateway answers each end in a journal and audit write
	// that is fsynced, so a box whose disk is busy (other test binaries
	// syncing) answers slowly with every core idle: the CPU readings above
	// read quiet while the baseline of the real path doubles (GAP-0865).
	// The probe times openLoopProbeSyncs write+fsync pairs of 4 KiB in the
	// temp directory and takes the median; it reads
	// 4.4 ms on the shared build box (EBS) with nothing else running, and 7 ms
	// while other processes fsync, where the baseline of the real path grew
	// from 36-39 ms to 58-64 ms and the run failed at utilisation 0.81 (limit
	// 0.80); openLoopProbeMaxSync sits between the two. A slower disk reads as
	// starved, so its run is inconclusive, never a pass.
	openLoopProbeSyncs   = 7
	openLoopProbeMaxSync = 6 * time.Millisecond
)

// openLoopSyncLatency is the median time of openLoopProbeSyncs write+fsync
// pairs in the temp directory, and false where the file cannot be written.
func openLoopSyncLatency() (time.Duration, bool) {
	file, err := os.CreateTemp("", "open-loop-probe-")
	if err != nil {
		return 0, false
	}
	defer os.Remove(file.Name())
	defer file.Close()
	block := make([]byte, 4096)
	took := make([]time.Duration, 0, openLoopProbeSyncs)
	for i := 0; i < openLoopProbeSyncs; i++ {
		start := time.Now()
		if _, err := file.WriteAt(block, int64(i)*int64(len(block))); err != nil {
			return 0, false
		}
		if err := file.Sync(); err != nil {
			return 0, false
		}
		took = append(took, time.Since(start))
	}
	sort.Slice(took, func(a, b int) bool { return took[a] < took[b] })
	return took[len(took)/2], true
}

// openLoopCPUPressure is the cumulative "some" CPU stall time of the box
// (Linux PSI), and false where the kernel does not report it.
func openLoopCPUPressure() (time.Duration, bool) {
	raw, err := os.ReadFile("/proc/pressure/cpu")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "some ") {
			continue
		}
		for _, field := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(field, "total="); ok {
				var us int64
				if _, err := fmt.Sscan(v, &us); err == nil {
					return time.Duration(us) * time.Microsecond, true
				}
			}
		}
	}
	return 0, false
}

// openLoopProbeSink keeps the probe's spin from being optimised away.
var openLoopProbeSink atomic.Uint64

// openLoopProbe is one reading of the box probe: the share of one core a spin
// on its own OS thread got over openLoopProbeSpin of wall time (thread CPU time
// over wall time), and the CPU pressure of the box over the same window (-1
// where the kernel does not report it).
type openLoopProbe struct {
	share, pressure float64
	// sync is the median write+fsync latency (0 where it cannot be read).
	sync time.Duration
}

// openLoopBoxProbe takes one reading, and false when the thread CPU clock
// cannot be read.
func openLoopBoxProbe() (openLoopProbe, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Timespec
	if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &before) != nil {
		return openLoopProbe{}, false
	}
	stallBefore, havePressure := openLoopCPUPressure()
	start := time.Now()
	x := uint64(1)
	for time.Since(start) < openLoopProbeSpin {
		for i := 0; i < 10000; i++ {
			x = x*6364136223846793005 + 1442695040888963407
		}
	}
	wall := time.Since(start)
	stallAfter, pressureAfter := openLoopCPUPressure()
	if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &after) != nil {
		return openLoopProbe{}, false
	}
	openLoopProbeSink.Add(x)
	reading := openLoopProbe{share: float64(after.Nano()-before.Nano()) / float64(wall.Nanoseconds()), pressure: -1}
	reading.sync, _ = openLoopSyncLatency()
	if havePressure && pressureAfter {
		reading.pressure = float64(stallAfter-stallBefore) / float64(wall)
	}
	return reading, true
}

// openLoopProbes is what the box probe measured around one stream.
type openLoopProbes []openLoopProbe

func (p *openLoopProbes) take() {
	if reading, ok := openLoopBoxProbe(); ok {
		*p = append(*p, reading)
	}
}

// starved reports whether any reading found the box short of CPU.
func (p openLoopProbes) starved() bool {
	for _, r := range p {
		if r.share < openLoopProbeMinShare || r.pressure >= openLoopProbeMaxPressure || r.sync >= openLoopProbeMaxSync {
			return true
		}
	}
	return false
}

func (p openLoopProbes) String() string {
	shares := make([]string, len(p))
	pressures := make([]string, len(p))
	syncs := make([]string, len(p))
	for i, r := range p {
		shares[i] = fmt.Sprintf("%.2f", r.share)
		syncs[i] = r.sync.Round(100 * time.Microsecond).String()
		pressures[i] = "n/a"
		if r.pressure >= 0 {
			pressures[i] = fmt.Sprintf("%.2f", r.pressure)
		}
	}
	return fmt.Sprintf("a spin on its own thread got [%s] of a core (limit %.2f), CPU pressure [%s] (limit %.2f), median write+fsync [%s] (limit %v)", strings.Join(shares, " "), openLoopProbeMinShare, strings.Join(pressures, " "), openLoopProbeMaxPressure, strings.Join(syncs, " "), openLoopProbeMaxSync)
}

// The disk-flush probe (substrate-1 GAP-1041). The serialised stage the stream
// queues on is the store's commits, and each ends in a flush of the
// write-ahead log to disk (synchronous=FULL), about 1.7 flushes a call. On a
// gate box the flush of a 4 KiB write takes 3 to 8 ms (p99 8 ms, max 20 ms over
// 700 to 800 flushes a run), and the stream keeps the stage about a third busy.
// While other jobs write to the same file system its flushes stall for seconds
// at 100 to 130 ms each (ext4 commits their data with the journal), with the
// CPU idle: the stage then needs several seconds a second, the calls queue
// past their window, and the CPU probe, finding the box quiet, blamed the
// gateway (TestGAP0490OpenLoop* failed at rel and on every fold in about half
// the runs on dc-sub-gates and dc-t6-timing). The probe writes and flushes
// 4 KiB beside the store every openLoopFlushEvery from the time the fixture is
// up, without touching the gateway. One slow flush happens on EBS and on CI
// runners with no disk pressure at all, and cannot explain a call unanswered
// for seconds (RV-T6A), so a stall counts only when it is sustained and
// explains the verdict: openLoopFlushStallRun slow flushes in a row, or
// openLoopFlushStallShare of a one-second window in slow flushes, and for an
// unanswered verdict a run of slow flushes at least openLoopWait long, since
// only that can keep a call from its answer for its whole window. A stall
// explains a timing verdict only when the stream passes once the calls it
// overlaps are set aside (RV-T6B): a real regression makes calls slow or
// unanswered across the whole run, and one burst somewhere in it must not
// turn that failure into a skip.
const (
	openLoopFlushEvery      = 100 * time.Millisecond
	openLoopFlushStall      = 50 * time.Millisecond
	openLoopFlushStallRun   = 3
	openLoopFlushStallShare = 0.25
	openLoopFlushWindow     = time.Second
	// openLoopFlushKeep bounds the flushes kept (the test deadline at
	// openLoopFlushEvery is 900).
	openLoopFlushKeep = 4096
)

// openLoopFlush is one probe flush: when it started and what it took.
type openLoopFlush struct {
	at   time.Time
	took time.Duration
}

// openLoopFlushProbe is the disk-flush probe of one test.
type openLoopFlushProbe struct {
	stopping, done chan struct{}
	mu             sync.Mutex
	flushes        []openLoopFlush
	max            time.Duration
	err            error
	// started and stopped bound the probe's time (the whole-run span of a
	// verdict with no calls of its own).
	started, stopped time.Time
}

// startOpenLoopFlushProbe starts the probe on a file in dir (the file system
// the store is on).
func startOpenLoopFlushProbe(dir string) *openLoopFlushProbe {
	p := &openLoopFlushProbe{stopping: make(chan struct{}), done: make(chan struct{}), started: time.Now()}
	f, err := os.OpenFile(filepath.Join(dir, "flush-probe"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		p.err = err
		close(p.done)
		return p
	}
	go func() {
		defer close(p.done)
		defer f.Close()
		block := make([]byte, 4096)
		tick := time.NewTicker(openLoopFlushEvery)
		defer tick.Stop()
		for {
			select {
			case <-p.stopping:
				return
			case <-tick.C:
			}
			started := time.Now()
			_, err := f.WriteAt(block, 0)
			if err == nil {
				err = f.Sync()
			}
			p.note(started, time.Since(started), err)
		}
	}()
	return p
}

// note records one flush.
func (p *openLoopFlushProbe) note(at time.Time, took time.Duration, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil && p.err == nil {
		p.err = err
	}
	if len(p.flushes) < openLoopFlushKeep {
		p.flushes = append(p.flushes, openLoopFlush{at, took})
	}
	p.max = max(p.max, took)
}

// stop ends the probe and waits for it.
func (p *openLoopFlushProbe) stop() {
	select {
	case <-p.stopping:
	default:
		close(p.stopping)
	}
	<-p.done
	p.mu.Lock()
	if p.stopped.IsZero() {
		p.stopped = time.Now()
	}
	p.mu.Unlock()
}

// openLoopStallRun is a run of slow flushes in a row.
type openLoopStallRun struct {
	span openLoopSpan
	n    int
}

// runsLocked is every run of slow flushes in a row.
func (p *openLoopFlushProbe) runsLocked() []openLoopStallRun {
	var out []openLoopStallRun
	var cur *openLoopStallRun
	for _, f := range p.flushes {
		if f.took < openLoopFlushStall {
			cur = nil
			continue
		}
		end := f.at.Add(f.took)
		if cur == nil {
			out = append(out, openLoopStallRun{span: openLoopSpan{f.at, end}})
			cur = &out[len(out)-1]
		}
		cur.span.to, cur.n = end, cur.n+1
	}
	return out
}

// windowShareLocked is the share of the one-second window starting at flush
// i spent in slow flushes.
func (p *openLoopFlushProbe) windowShareLocked(i int) float64 {
	w := openLoopSpan{p.flushes[i].at, p.flushes[i].at.Add(openLoopFlushWindow)}
	var slow time.Duration
	for _, g := range p.flushes[i:] {
		if !g.at.Before(w.to) {
			break
		}
		if g.took >= openLoopFlushStall {
			slow += min(g.took, w.to.Sub(g.at))
		}
	}
	return float64(slow) / float64(openLoopFlushWindow)
}

// busiestLocked is the largest share of a one-second window, starting at a
// slow flush, spent in slow flushes.
func (p *openLoopFlushProbe) busiestLocked() float64 {
	best := 0.0
	for i, f := range p.flushes {
		if f.took >= openLoopFlushStall {
			best = max(best, p.windowShareLocked(i))
		}
	}
	return best
}

func openLoopAnyOverlap(s openLoopSpan, spans []openLoopSpan) bool {
	for _, x := range spans {
		if s.overlaps(x) {
			return true
		}
	}
	return false
}

// stallSpansLocked is every stall that counts for a verdict of kind: a run
// of openLoopFlushStallRun slow flushes or more, or a one-second window
// openLoopFlushStallShare in slow flushes; for an unanswered verdict only a
// run at least openLoopWait long.
func (p *openLoopFlushProbe) stallSpansLocked(kind string) []openLoopSpan {
	var out []openLoopSpan
	for _, r := range p.runsLocked() {
		switch {
		case kind == "unanswered" && r.span.to.Sub(r.span.from) >= openLoopWait:
			out = append(out, r.span)
		case kind != "unanswered" && r.n >= openLoopFlushStallRun:
			out = append(out, r.span)
		}
	}
	if kind == "unanswered" {
		return out
	}
	for i, f := range p.flushes {
		if f.took >= openLoopFlushStall && p.windowShareLocked(i) >= openLoopFlushStallShare {
			out = append(out, openLoopSpan{f.at, f.at.Add(openLoopFlushWindow)})
		}
	}
	return out
}

// explains reports whether the disk flush stalled in a way that explains a
// verdict of kind, and for a timing verdict what the stream showed without
// the calls the stalls overlap. Any counted stall explains an inconclusive
// verdict (the baseline or a session start the box could not carry). A
// timing verdict (unanswered or slow, judged on timing) is explained only
// when the stream passes once the calls whose windows overlap a counted
// stall are set aside; with no timing to judge it is not explained.
func (p *openLoopFlushProbe) explains(kind string, timing *openLoopTiming) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	stalls := p.stallSpansLocked(kind)
	if len(stalls) == 0 {
		return false, ""
	}
	if kind != "unanswered" && kind != "slow" {
		return true, ""
	}
	if timing == nil {
		return false, ""
	}
	return timing.passesWithout(stalls)
}

func (p *openLoopFlushProbe) String() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	slow, longestN := 0, 0
	var longest time.Duration
	for _, f := range p.flushes {
		if f.took >= openLoopFlushStall {
			slow++
		}
	}
	for _, r := range p.runsLocked() {
		if d := r.span.to.Sub(r.span.from); d > longest {
			longest, longestN = d, r.n
		}
	}
	s := fmt.Sprintf("a 4 KiB write and flush beside the store every %v took up to %v (%d of %d at %v or more; longest run %d in a row over %v; busiest 1 s window %.0f%% slow; a stall counts at %d in a row or %.0f%% of 1 s, and for unanswered calls a run of %v)",
		openLoopFlushEvery, p.max.Round(time.Millisecond), slow, len(p.flushes), openLoopFlushStall, longestN, longest.Round(time.Millisecond),
		100*p.busiestLocked(), openLoopFlushStallRun, 100*openLoopFlushStallShare, openLoopWait)
	if p.err != nil {
		s += fmt.Sprintf(", probe error %v", p.err)
	}
	return s
}

// settleOpenLoop ends an open-loop test on its verdict. An INCONCLUSIVE verdict
// is a skip naming GAP-1456 and the numbers when the box probe found the box
// short of CPU or the flush probe found its disk flush stalled, and a failure
// when neither did (the box had CPU and disk to spare, so the real path that
// could not carry the stream is the gateway's own). The two timing verdicts,
// unanswered and slow, are measured on the same wall clock and are a skip on
// such a box as well; on a quiet box they fail. A disk stall explains a
// timing verdict only when the stream, judged again on timing without the
// calls the stall overlaps, passes (openLoopFlushProbe.explains). A refusal or
// an explicit failure is not a timing matter and fails on any box. Every
// verdict prints both probes, and a timing verdict what the stream showed
// without the stalled calls.
func settleOpenLoop(t *testing.T, verdict openLoopVerdict, probes openLoopProbes, flush *openLoopFlushProbe, deadline error, timing *openLoopTiming) {
	t.Helper()
	flush.stop()
	stalled, rest := flush.explains(verdict.kind, timing)
	short := probes.starved() || stalled
	if rest != "" {
		verdict.detail = fmt.Sprintf("%s; %s", verdict.detail, rest)
	}
	if verdict.kind == "inconclusive" && !short {
		// The baseline's own words blame the box; the probe says otherwise.
		verdict.detail = strings.TrimSuffix(strings.TrimPrefix(verdict.detail, "INCONCLUSIVE: "), "; the box is overloaded, so this run says nothing about the gateway")
	}
	if deadline != nil {
		verdict.detail = fmt.Sprintf("%s (the test deadline of %v ran out: %v)", verdict.detail, openLoopTestDeadline, deadline)
	}
	switch {
	case verdict.kind == "ok":
		t.Logf("%s; %s; %s", verdict.detail, probes, flush)
	case (verdict.kind == "inconclusive" || verdict.kind == "unanswered" || verdict.kind == "slow") && short:
		t.Skipf("GAP-1456 GAP-1041 INCONCLUSIVE, box short of CPU or of disk flush (%s; %s): %s", probes, flush, verdict.detail)
	case verdict.kind == "inconclusive":
		t.Fatalf("GAP-1456 FAIL, not a skip: the box was not short of CPU or disk flush (%s; %s), so this is the gateway: %s", probes, flush, verdict.detail)
	default:
		t.Fatalf("%s (%s; %s)", verdict.detail, probes, flush)
	}
}

// closeOpenLoopServer closes the ingress server, which waits for every request
// it still serves, inside openLoopTeardownDeadline. It reports whether they all
// ended.
func closeOpenLoopServer(srv *httptest.Server) bool {
	srv.CloseClientConnections()
	done := make(chan struct{})
	go func() {
		srv.Close()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(openLoopTeardownDeadline):
		return false
	}
}

// openLoopTmpfsMagic is the Linux statfs f_type of tmpfs (TMPFS_MAGIC).
const openLoopTmpfsMagic = 0x01021994

// openLoopDataOnRAM puts every t.TempDir of an open-loop test (the audit
// store, the journal, the sandbox bindings) on a RAM-backed folder when the
// box has one (Linux /dev/shm on tmpfs), as Go Throughput Test does with
// TMPDIR. The code path keeps its real fsync calls and the budgets are
// unchanged; what leaves the measurement is the disk the box shares with every
// other test process. In the parallel gate the fsyncs waited on other
// writers' flushes, which neither the CPU probe nor CPU or IO pressure sees:
// in every failing run CPU per call was normal (23.7-25.5 ms) while the
// baseline mean rose from 41-56 ms to 63-70 ms, and the stream then missed
// its window (rel-1-0-10 GAP-1456). Elsewhere the data stays in the default
// temp folder.
func openLoopDataOnRAM(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		return
	}
	var st unix.Statfs_t
	if unix.Statfs("/dev/shm", &st) != nil || int64(st.Type) != openLoopTmpfsMagic {
		t.Log("open-loop data on the default temp folder: no tmpfs /dev/shm")
		return
	}
	// The migrated audit template lives as long as the test process: it is
	// made in the default temp folder first, so this test's cleanup of its
	// RAM folder does not take it from the tests after it. Its copy into
	// the test's store is on RAM.
	if err := migrateAuditTemplate(); err != nil {
		t.Fatalf("migrate the template audit database: %v", err)
	}
	dir, err := os.MkdirTemp("/dev/shm", "dc-open-loop-")
	if err != nil {
		t.Logf("open-loop data on the default temp folder: %v", err)
		return
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	t.Setenv("TMPDIR", dir)
}

func runGAP0490OpenLoop(t *testing.T, sandboxes, perSecond int, duration time.Duration) {
	openLoopDataOnRAM(t)
	ctx, cancel := context.WithTimeout(t.Context(), openLoopTestDeadline)
	defer cancel()
	var probes openLoopProbes
	probes.take()
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
	// The flush probe starts once the fixture is up: a stall while the store
	// opened says nothing about the calls (GAP-1041).
	flush := startOpenLoopFlushProbe(t.TempDir())
	defer flush.stop()
	closed := false
	defer func() {
		// A test that ends early (a Fatal) still closes inside its bound.
		if !closed {
			closeOpenLoopServer(srv)
		}
	}()
	post := newOpenLoopPost(srv.URL)
	// Warm the sessions: the first call of an unseen session waits for its
	// start, which is not what this test measures. A session start left
	// unanswered on a starved box is the baseline's INCONCLUSIVE, not a hang.
	for i, token := range tokens {
		session := fmt.Sprintf("g490-open-%d", i)
		warm, cancel := context.WithTimeout(ctx, openLoopWait)
		status, out, err := post(warm, token, []byte(managedHookBody(session, "UserPromptSubmit")), false)
		cancel()
		if err == nil && status != http.StatusOK {
			t.Fatalf("session start %d %s", status, out)
		}
		if err != nil {
			probes.take()
			closed = true
			if !closeOpenLoopServer(srv) {
				t.Errorf("GAP-1456: the ingress still served requests %v after the session start of sandbox %d went unanswered", openLoopTeardownDeadline, i)
			}
			probes.take()
			settleOpenLoop(t, openLoopVerdict{"inconclusive", fmt.Sprintf("INCONCLUSIVE: the session start of sandbox %d was not answered inside %v (%v)", i, openLoopWait, err)}, probes, flush, ctx.Err(), nil)
			return
		}
	}
	// The baseline: the real path, one call after the other, right before the
	// stream, on the same box in the same state.
	plan := openLoopPlan{tokens: tokens, perSecond: perSecond, duration: duration, cores: runtime.GOMAXPROCS(0)}
	baseCtx, baseCancel := context.WithTimeout(ctx, openLoopBaselineDeadline)
	cpuBefore := openLoopProcessCPU(t)
	base := driveSingleStream(baseCtx, post, tokens[0], "g490-open-0", openLoopBaselineCalls)
	base.cpuPerCall = (openLoopProcessCPU(t) - cpuBefore) / openLoopBaselineCalls
	baseCancel()
	probes.take()
	var got openLoopResult
	if judgeOpenLoopBaseline(plan, base) == nil {
		// A baseline that already shows the box cannot carry the plan settles
		// the run; the stream would only spend the deadline.
		streamCtx, streamCancel := context.WithTimeout(ctx, duration+openLoopWait+openLoopStreamSlack)
		got = driveOpenLoop(streamCtx, post, plan)
		streamCancel()
	}
	closed = true
	drained := closeOpenLoopServer(srv)
	probes.take()
	if !drained {
		// Every client of the stream gave up inside its answer window; a
		// request the ingress still serves openLoopTeardownDeadline later is
		// a request that outlived its caller.
		t.Errorf("GAP-1456: the ingress still served requests %v after the stream ended (%s)", openLoopTeardownDeadline, probes)
	}
	verdict := judgeOpenLoop(plan, got, base)
	settleOpenLoop(t, verdict, probes, flush, ctx.Err(), &openLoopTiming{got, openLoopBudget(plan, base)})
}

// openLoopProcessCPU is the user and system CPU time this process has used.
func openLoopProcessCPU(t *testing.T) time.Duration {
	t.Helper()
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
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

// The CPU stage of the budget follows the cores. The slow-pool stream of run
// 43235986187 (2 x 22 calls/s, p95 550 ms over a baseline mean of 31 ms and
// p95 38 ms), with the 38 ms of CPU a call took in a profile of the same
// stream, passes on the 4 cores of a hosted runner (CPU utilisation 0.42)
// and is slow where 16 cores leave it no CPU wait (0.10) or where the CPU
// time is not known. A stream past the stretched budget is still slow, a box
// whose cores the stream would keep past openLoopMaxUtilisation is
// INCONCLUSIVE, and a refusal still fails on any box.
func TestGAP0490OpenLoopJudgementCPUStageFollowsTheCores(t *testing.T) {
	slowPool := openLoopRecorded(30, 30, 31*time.Millisecond, 38*time.Millisecond, 1)
	slowPool.cpuPerCall = 38 * time.Millisecond
	unmeasured := openLoopRecorded(30, 30, 31*time.Millisecond, 38*time.Millisecond, 1)
	cpuBound := openLoopRecorded(30, 30, 31*time.Millisecond, 38*time.Millisecond, 1)
	cpuBound.cpuPerCall = 80 * time.Millisecond
	stream := openLoopRecorded(440, 440, 266*time.Millisecond, 550*time.Millisecond, 44)
	refused := openLoopRecorded(440, 440, 266*time.Millisecond, 550*time.Millisecond, 44)
	refused.refused = 1
	plan := func(cores int) openLoopPlan {
		p := openLoopStubPlan(2, 22, 10*time.Second, 0)
		p.cores = cores
		return p
	}
	for _, tc := range []struct {
		name string
		plan openLoopPlan
		got  openLoopResult
		base openLoopResult
		kind string
	}{
		{"the slow-pool stream passes on 4 cores", plan(4), stream, slowPool, "ok"},
		{"the same stream is slow on 16 cores", plan(16), stream, slowPool, "slow"},
		{"the same stream is slow when the CPU time is not measured", plan(4), stream, unmeasured, "slow"},
		{"a stream past the stretched budget is slow", plan(4), openLoopRecorded(440, 440, 266*time.Millisecond, 900*time.Millisecond, 44), slowPool, "slow"},
		{"a stream that would keep 4 cores 88% busy is inconclusive", plan(4), stream, cpuBound, "inconclusive"},
		{"a refusal fails on 4 cores", plan(4), refused, slowPool, "refused"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if verdict := judgeOpenLoop(tc.plan, tc.got, tc.base); verdict.kind != tc.kind {
				t.Fatalf("judged %s, want %s: %s", verdict.kind, tc.kind, verdict.detail)
			}
		})
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
