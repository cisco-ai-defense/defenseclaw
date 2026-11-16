// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// hookAnswerQueueBudget is the hook answer budget of the native hook
// (hookAnswerBudget, connector/hookexec/answer_deadline.go): a healthy
// gateway's answer must reach the hook inside it, queueing included.
const hookAnswerQueueBudget = 3500 * time.Millisecond

// hookAnswerQueueCeiling is the longest any single answer may take on any
// host, starved or not: three budgets, under the 11-13 s p95 of the queueing
// the group commit removed. A starved host can make the budget unjudgeable,
// but it cannot make an answer of this length a host effect: the starvation
// flag only says some busy thread waited, not how much of the answer it
// explains (GAP-0889).
const hookAnswerQueueCeiling = 3 * hookAnswerQueueBudget

// A late answer is told from a starved host by the answers around it. A host
// that keeps the process off the CPU slows every call in flight, so the calls
// beside a late one are slow too. A call that stalls alone is late while the
// process keeps answering quickly: at least hookAnswerStallPeers answers of at
// most hookAnswerQueueBudget/3 finish after the late one has been pending for a
// whole budget, and hookAnswerStallMargin or more before it finishes. The
// margin keeps the answers a paused process finishes together with the late one
// from counting as proof that the process was running (GAP-0889).
const (
	hookAnswerStallPeers  = 3
	hookAnswerStallMargin = 250 * time.Millisecond
	hookAnswerStallFast   = hookAnswerQueueBudget / 3
)

// hookAnswer is one answered hook call: when it ran, how long it took, and
// whether the host kept a busy thread of the process from the CPU for a
// quarter of exactly that call (testenv.Window). The calls are in flight
// together and a call's work moves between goroutines and threads, so no
// thread is the call's own: the window is never taken off a time, it only says
// whether the host let the measurement run (GAP-0889).
type hookAnswer struct {
	started, ended time.Time
	took           time.Duration
	starved        bool
}

// stalledAlone reports whether the late answer waited while the process was
// answering other calls quickly, which no host effect on the whole process
// explains.
func (late hookAnswer) stalledAlone(all []hookAnswer) bool {
	from, to := late.started.Add(hookAnswerQueueBudget), late.ended.Add(-hookAnswerStallMargin)
	peers := 0
	for _, other := range all {
		if other.took <= hookAnswerStallFast && !other.ended.Before(from) && !other.ended.After(to) {
			peers++
		}
	}
	return peers >= hookAnswerStallPeers
}

// TestHookAnswersStayInsideTheBudgetUnderCPULoad drives the real hook
// handler, audit store and v8 runtime at 10 benign Claude Code PreToolUse
// calls a second from ten sessions on two CPUs with six busy goroutines (the
// GAP-1790 overload shape of the GAP-1489/1211/1243 rows). At the 1.0.5 base
// every audit append committed alone on the store's one connection and the
// answers queued behind them: p95 11.4-13.6 s. Concurrent appends now share
// a transaction (group commit): p95 under 1 s. Every answer must be inside
// the budget, the slowest included. A host that does not let the process run
// cannot be measured (see below), and then the test says so and stops.
func TestHookAnswersStayInsideTheBudgetUnderCPULoad(t *testing.T) {
	if testing.Short() || hookAnswerRaceBuild {
		t.Skip("load measurement: not under -short or the race detector")
	}
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	cwd := t.TempDir()
	call := func(session string, index int) (hookAnswer, int) {
		body, err := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
			"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%s_%06d", session, index),
			"tool_input":  map[string]any{"command": "echo ok", "description": "Print ok"},
		})
		if err != nil {
			t.Error(err)
			return hookAnswer{}, 0
		}
		window := testenv.StartWindow()
		started := time.Now()
		rec := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(rec,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		ended := time.Now()
		took := ended.Sub(started)
		return hookAnswer{started: started, ended: ended, took: took, starved: took > hookAnswerQueueBudget && window.Starved()}, rec.Code
	}
	for index := range 20 {
		call("warm", index)
	}

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	var stopped atomic.Bool
	var hogs sync.WaitGroup
	for range 6 {
		hogs.Add(1)
		go func() {
			defer hogs.Done()
			spins := 0
			for !stopped.Load() {
				spins++
			}
			_ = spins
		}()
	}
	const sessions = 10
	const duration = 20 * time.Second
	var mu sync.Mutex
	var answers []hookAnswer
	var calls sync.WaitGroup
	deadline := time.Now().Add(duration)
	for session := range sessions {
		calls.Add(1)
		go func() {
			defer calls.Done()
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			var inflight sync.WaitGroup
			for index := 0; time.Now().Before(deadline); index++ {
				<-tick.C
				inflight.Add(1)
				go func() {
					defer inflight.Done()
					result, code := call(fmt.Sprintf("load-%d", session), index)
					if code != http.StatusOK {
						t.Errorf("call %d of session %d: HTTP %d", index, session, code)
					}
					mu.Lock()
					answers = append(answers, result)
					mu.Unlock()
				}()
			}
			inflight.Wait()
		}()
	}
	calls.Wait()
	stopped.Store(true)
	hogs.Wait()
	sort.Slice(answers, func(i, j int) bool { return answers[i].took < answers[j].took })
	if len(answers) < sessions*int(duration/time.Second)/2 {
		t.Fatalf("only %d calls ran", len(answers))
	}
	over, overOnAFreeHost, beyondCeiling, stalls := 0, 0, 0, 0
	for _, a := range answers {
		if a.took > hookAnswerQueueCeiling {
			beyondCeiling++
		}
		if a.took > hookAnswerQueueBudget {
			over++
			if !a.starved {
				overOnAFreeHost++
			} else if a.stalledAlone(answers) {
				stalls++
			}
		}
	}
	p95 := answers[len(answers)*95/100].took
	t.Logf("%d calls at 10/s on 2 CPUs with 6 busy goroutines: p50 %v p95 %v max %v",
		len(answers), answers[len(answers)/2].took, p95, answers[len(answers)-1].took)
	// Every answer, not a percentile: a call over the budget is a benign call
	// refused as a gateway no-answer (GAP-1981). The budget is the wall time
	// of the call, and nothing is subtracted from it: no call is excused by
	// time the host kept some thread of the process waiting, which a call
	// blocked on anything else also overlaps. A call over it fails; the
	// queueing the group commit removed took 11-13 s at p95 and fails the
	// same way. The one thing the host changes is whether the measurement is
	// valid: when every call that missed the budget did so while the host
	// kept a busy thread of the process off the CPU for a quarter of the
	// call, the process was not given the two CPUs the load is shaped for,
	// and the run says so and is not judged. A call that missed it on a host
	// that left the process three quarters of its CPU is never in that case:
	// the answers take under 1 s there. No answer is excused beyond the
	// ceiling (three budgets): that fails whatever the host did. A starved
	// host does not excuse a late answer that stalled alone either (see
	// stalledAlone): the flag only says some busy thread waited, not that the
	// late call lost that CPU time.
	if beyondCeiling > 0 {
		t.Fatalf("%d of %d answers over the %v answer ceiling, starved host or not (max %v, p95 %v)", beyondCeiling, len(answers), hookAnswerQueueCeiling, answers[len(answers)-1].took, p95)
	}
	if stalls > 0 {
		t.Fatalf("%d of %d answers over the %v answer budget while the process kept answering other calls quickly (max %v, p95 %v)", stalls, len(answers), hookAnswerQueueBudget, answers[len(answers)-1].took, p95)
	}
	if overOnAFreeHost > 0 {
		t.Fatalf("%d of %d answers over the %v answer budget (%d on a free host; max %v, p95 %v)", over, len(answers), hookAnswerQueueBudget, overOnAFreeHost, answers[len(answers)-1].took, p95)
	}
	if over > 0 {
		t.Skipf("host starved the process: %d of %d answers over the %v answer budget, each while a busy thread of the process was off the CPU for %.0f%% or more of the call; max %v, p95 %v. The budget was not judged",
			over, len(answers), hookAnswerQueueBudget, testenv.StarvedShare*100, answers[len(answers)-1].took, p95)
	}
}

// TestLateHookAnswerStalledAloneIsToldFromAStarvedHost: a late answer that
// waited while the process answered other calls quickly is a stall of its own
// and is never excused by a starved host; a late answer beside slow calls, or
// beside the calls a paused process finishes together with it, still is
// (GAP-0889).
func TestLateHookAnswerStalledAloneIsToldFromAStarvedHost(t *testing.T) {
	t.Parallel()
	origin := time.Unix(1000, 0)
	at := func(started, took time.Duration) hookAnswer {
		return hookAnswer{started: origin.Add(started), ended: origin.Add(started + took), took: took, starved: true}
	}
	peersEvery := func(from, to, took time.Duration) []hookAnswer {
		var out []hookAnswer
		for start := from; start < to; start += 100 * time.Millisecond {
			out = append(out, at(start, took))
		}
		return out
	}
	cases := []struct {
		name    string
		late    hookAnswer
		peers   []hookAnswer
		stalled bool
	}{
		{"blocked for 8 s while calls answer in half a second", at(0, 8*time.Second), peersEvery(0, 8*time.Second, 500*time.Millisecond), true},
		{"late beside calls that are slow too", at(0, 6*time.Second), peersEvery(0, 6*time.Second, 2500*time.Millisecond), false},
		{"late across a pause the process resumed from", at(0, 5200*time.Millisecond), peersEvery(5*time.Second, 5200*time.Millisecond, 100*time.Millisecond), false},
		{"late with no call to compare to", at(0, 4*time.Second), nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			all := append([]hookAnswer{c.late}, c.peers...)
			if got := c.late.stalledAlone(all); got != c.stalled {
				t.Fatalf("stalledAlone = %v, want %v", got, c.stalled)
			}
		})
	}
}
