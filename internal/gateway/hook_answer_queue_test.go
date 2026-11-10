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

// TestHookAnswersStayInsideTheBudgetUnderCPULoad drives the real hook
// handler, audit store and v8 runtime at 10 benign Claude Code PreToolUse
// calls a second from ten sessions on two CPUs with six busy goroutines (the
// GAP-1790 overload shape of the GAP-1489/1211/1243 rows). At the 1.0.5 base
// every audit append committed alone on the store's one connection and the
// answers queued behind them: p95 11.4-13.6 s. Concurrent appends now share
// a transaction (group commit): p95 under 1 s. Every answer must be inside
// the budget, the slowest included.
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
	// answer is one call: how long it took, and whether it stayed inside the
	// budget once the time the host kept this process from the CPU during
	// exactly that call is taken off (GAP-0889).
	type answer struct {
		took   time.Duration
		within bool
	}
	call := func(session string, index int) (answer, int) {
		body, err := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
			"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%s_%06d", session, index),
			"tool_input":  map[string]any{"command": "echo ok", "description": "Print ok"},
		})
		if err != nil {
			t.Error(err)
			return answer{}, 0
		}
		meter := testenv.StartMeter()
		started := time.Now()
		rec := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(rec,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		took := time.Since(started)
		return answer{took: took, within: meter.Within(took, hookAnswerQueueBudget)}, rec.Code
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
	var answers []answer
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
	over := 0
	for _, a := range answers {
		if !a.within {
			over++
		}
	}
	p95 := answers[len(answers)*95/100].took
	t.Logf("%d calls at 10/s on 2 CPUs with 6 busy goroutines: p50 %v p95 %v max %v",
		len(answers), answers[len(answers)/2].took, p95, answers[len(answers)-1].took)
	// Every answer, not a percentile: a call over the budget is a benign call
	// refused as a gateway no-answer (GAP-1981). The budget is the wall time
	// of the call. Only a call that missed it is given the host, and only the
	// time its own process was ready to run and had no CPU during that call
	// (testenv.Meter, started just before it): a call that waited on anything
	// else keeps the miss, and none passes beyond testenv.MaxStretch budgets,
	// which stays under the 11-13 s the queueing the group commit removed took.
	if over > 0 {
		t.Fatalf("%d of %d answers over the %v answer budget (max %v, p95 %v)", over, len(answers), hookAnswerQueueBudget, answers[len(answers)-1].took, p95)
	}
}
