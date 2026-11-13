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
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// The per-user open-loop tests drive the per-user Claude Code hook path the
// way the installed hook does (one PreToolUse per tool call, the answer
// within 3.5 s, a new connection per call) at 100 calls a second for 20 s:
// one session at 100/s, and ten sessions at 10/s each (S8 bar H1, rel-1-0-6
// GAP-0558 to GAP-0560, issue #1384). Each test first runs a serial leg in
// which every correlation occurrence has its own transaction (groups of one,
// the 1.0.9 shape: one baton turn and one COMMIT per hook) and logs it, then
// the grouped leg with the production limits, which is judged:
//   - the single-stream baseline of the real path and the measured cadence
//     are judged as in TestGAP0490OpenLoop* (judgeOpenLoopBaseline,
//     judgeOpenLoopStream): an overloaded box or a launcher that fell behind
//     is INCONCLUSIVE and fails, never a pass;
//   - at least 99.5% of the offered calls are answered with an allow inside
//     the 3.5 s window, no benign call is denied by that deadline, and the
//     p95 is at most 300 ms.
//
// They are opt-in (DC_GAP0490_OPEN_LOOP_BUDGET=1) like the 100 calls/s
// sandbox stream, and built without -race: they measure wall-clock time.
func TestHookPerUserOpenLoopOneSession100(t *testing.T) {
	runHookPerUserOpenLoop(t, 1, 100)
}

func TestHookPerUserOpenLoopTenSessions100(t *testing.T) {
	runHookPerUserOpenLoop(t, 10, 10)
}

const (
	perUserOpenLoopMinAnswered = 0.995
	perUserOpenLoopP95         = 300 * time.Millisecond
	perUserOpenLoopDuration    = 20 * time.Second
)

func runHookPerUserOpenLoop(t *testing.T, sessions, perSecond int) {
	if os.Getenv("DC_GAP0490_OPEN_LOOP_BUDGET") != "1" {
		t.Skip("set DC_GAP0490_OPEN_LOOP_BUDGET=1 to drive 100 per-user hook calls a second")
	}
	legs := []struct {
		name        string
		occurrences int
		judged      bool
		duration    time.Duration
	}{
		{"serial", 1, false, perUserOpenLoopDuration},
		{"grouped", 0, true, perUserOpenLoopDuration},
	}
	for _, leg := range legs {
		t.Run(leg.name, func(t *testing.T) {
			if leg.occurrences > 0 {
				setHookCorrelationGroupOccurrences(t, leg.occurrences)
			}
			if hold, err := time.ParseDuration(os.Getenv("S8_OPEN_LOOP_GROUP_HOLD")); err == nil && leg.occurrences == 0 {
				// Diagnosis only: another hold for the grouped leg.
				limits := hookCorrelationGroupLimits
				limits.Hold = hold
				setHookCorrelationGroupLimits(t, limits)
			}
			f := newAuditFailureHookFixture(t, "open")
			srv := httptest.NewServer(f.api.handleAgentHook("claudecode"))
			defer srv.Close()
			cwd := t.TempDir()
			names := make([]string, sessions)
			for i := range names {
				names[i] = fmt.Sprintf("s8-open-%d-%d", sessions, i)
				for _, event := range []string{"SessionStart", "UserPromptSubmit"} {
					status, out, err := postPerUserHook(t.Context(), srv.URL, perUserLifecycleBody(names[i], cwd, event))
					if err != nil || status != http.StatusOK {
						t.Fatalf("%s %s: %d %.200s %v", names[i], event, status, out, err)
					}
				}
			}
			cpuBefore := openLoopProcessCPU(t)
			base := openLoopResult{problems: map[string]int{}, offered: openLoopBaselineCalls}
			for n := 0; n < openLoopBaselineCalls; n++ {
				_, elapsed, status, out, err := performPerUserOpenLoopCall(t.Context(), srv.URL, cwd, names[0], 1000000+n)
				base.record(elapsed, status, out, err)
			}
			base.cpuPerCall = (openLoopProcessCPU(t) - cpuBefore) / openLoopBaselineCalls
			plan := openLoopPlan{tokens: names, perSecond: perSecond, duration: leg.duration, cores: runtime.GOMAXPROCS(0)}
			if path := os.Getenv("S8_GOROUTINE_DUMP"); path != "" {
				// A goroutine profile half way through the stream, for the
				// diagnosis of a slow run (not part of the judgement).
				timer := time.AfterFunc(leg.duration/2, func() {
					if out, err := os.Create(fmt.Sprintf("%s-%d-%s.txt", path, sessions, leg.name)); err == nil {
						_ = pprof.Lookup("goroutine").WriteTo(out, 1)
						_ = out.Close()
					}
				})
				defer timer.Stop()
			}
			got, denies := drivePerUserOpenLoop(t.Context(), srv.URL, cwd, plan)
			verdict := judgePerUserOpenLoop(plan, got, base, denies)
			t.Logf("PERUSER-OPENLOOP leg=%s sessions=%d rate=%d: %s: %s", leg.name, sessions, perSecond, verdict.kind, verdict.detail)
			if leg.judged && verdict.kind != "ok" {
				t.Fatal(verdict.detail)
			}
		})
	}
}

// perUserOpenLoopClient opens a new connection per call, as the hook does.
var perUserOpenLoopClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true, MaxIdleConnsPerHost: -1}}

func postPerUserHook(ctx context.Context, url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/api/v1/claudecode/hook", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookexec.HookAnswerWithinHeader, fmt.Sprint(openLoopWait.Milliseconds()))
	resp, err := perUserOpenLoopClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

func perUserLifecycleBody(session, cwd, event string) []byte {
	body := map[string]any{"hook_event_name": event, "session_id": session, "cwd": cwd}
	switch event {
	case "SessionStart":
		body["source"] = "startup"
	case "UserPromptSubmit":
		body["prompt"] = "list the files"
	}
	out, _ := json.Marshal(body)
	return out
}

// errPerUserDeadline is a call the hook would have denied because the
// gateway did not answer inside the hook window.
var errPerUserDeadline = errors.New("no answer inside the hook window")

func performPerUserOpenLoopCall(parent context.Context, url, cwd, session string, n int) (issued time.Time, elapsed time.Duration, status int, out []byte, err error) {
	body := fmt.Sprintf(`{"hook_event_name":"PreToolUse","session_id":%q,"cwd":%q,"tool_name":"Bash","tool_use_id":"toolu_%s_%d","tool_input":{"command":"git status"}}`, session, cwd, session, n)
	ctx, cancel := context.WithTimeout(parent, openLoopWait)
	defer cancel()
	issued = time.Now()
	status, out, err = postPerUserHook(ctx, url, []byte(body))
	elapsed = time.Since(issued)
	switch {
	case err != nil && (errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil):
		err = fmt.Errorf("%w: %v", errPerUserDeadline, err)
	case err == nil && status == http.StatusOK && elapsed > openLoopWait:
		err = fmt.Errorf("%w: answered after %v", errPerUserDeadline, elapsed)
	case err == nil && status == http.StatusOK && !perUserHookAllowed(out):
		err = fmt.Errorf("%w: %s", errOpenLoopProposal, out)
	}
	return issued, elapsed, status, out, err
}

// drivePerUserOpenLoop issues the plan on an absolute schedule (call n of a
// session at start + n ticks) without waiting for earlier answers, like
// driveOpenLoop, and also counts the calls the hook would have denied on its
// deadline.
func drivePerUserOpenLoop(parent context.Context, url, cwd string, plan openLoopPlan) (openLoopResult, int) {
	result := openLoopResult{problems: map[string]int{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	denies := 0
	total := int(plan.duration.Seconds()) * plan.perSecond
	result.offered = len(plan.tokens) * total
	interval := time.Second / time.Duration(plan.perSecond)
	start := time.Now()
	var first, last time.Time
	call := func(session string, n int) {
		defer wg.Done()
		issued, elapsed, status, out, err := performPerUserOpenLoopCall(parent, url, cwd, session, n)
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
		if errors.Is(err, errPerUserDeadline) {
			denies++
		}
		result.record(elapsed, status, out, err)
	}
	var launch sync.WaitGroup
	for i, session := range plan.tokens {
		launch.Add(1)
		go func() {
			defer launch.Done()
			// Sessions of one plan are spread over the tick, as independent
			// agents are.
			offset := interval * time.Duration(i) / time.Duration(len(plan.tokens))
			for n := 0; n < total; n++ {
				if d := time.Until(start.Add(time.Duration(n)*interval + offset)); d > 0 {
					time.Sleep(d)
				}
				wg.Add(1)
				go call(session, n)
			}
		}()
	}
	launch.Wait()
	wg.Wait()
	if !first.IsZero() {
		result.window = last.Sub(first) + interval
	}
	return result, denies
}

// judgePerUserOpenLoop is judgeOpenLoop with the bar H1 of a per-user hook:
// the baseline and cadence rules first (INCONCLUSIVE fails), then the answered
// share, the deadline denies and the p95.
func judgePerUserOpenLoop(plan openLoopPlan, got, base openLoopResult, denies int) openLoopVerdict {
	numbers := fmt.Sprintf("%d sessions at %d calls/s, issued %.1f calls/s on schedule: %d offered, answered in %v %.4f, deadline denies %d, p50 %v, p95 %v, max %v; baseline mean %v, p95 %v, CPU per call %v, %d cores",
		len(plan.tokens), plan.perSecond, got.achievedRate(), got.offered, openLoopWait, got.answeredShare(), denies,
		got.percentile(50).Round(time.Microsecond), got.percentile(95).Round(time.Microsecond), got.percentile(100).Round(time.Microsecond),
		base.mean().Round(time.Microsecond), base.percentile(95).Round(time.Microsecond), base.cpuPerCall.Round(time.Microsecond), plan.cores)
	if v := judgeOpenLoopBaseline(plan, base); v != nil {
		return openLoopVerdict{v.kind, v.detail + " (" + numbers + ")"}
	}
	if v := judgeOpenLoopStream(plan, got); v != nil {
		return openLoopVerdict{v.kind, v.detail + " (" + numbers + ")"}
	}
	switch {
	case denies != 0:
		return openLoopVerdict{"unanswered", fmt.Sprintf("%d benign calls denied on the hook deadline (%s): %v", denies, numbers, got.problems)}
	case got.answeredShare() < perUserOpenLoopMinAnswered:
		return openLoopVerdict{"unanswered", fmt.Sprintf("answered share below %.3f (%s): %v", perUserOpenLoopMinAnswered, numbers, got.problems)}
	case got.percentile(95) > perUserOpenLoopP95:
		return openLoopVerdict{"slow", fmt.Sprintf("p95 over %v (%s)", perUserOpenLoopP95, numbers)}
	}
	return openLoopVerdict{"ok", numbers}
}
