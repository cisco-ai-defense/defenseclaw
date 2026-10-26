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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
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
// a transaction (group commit): p95 under 1 s.
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
	call := func(session string, index int) (time.Duration, int) {
		body, err := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"),
			"cwd": cwd, "permission_mode": "default", "hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%s_%06d", session, index),
			"tool_input":  map[string]any{"command": "echo ok", "description": "Print ok"},
		})
		if err != nil {
			t.Error(err)
			return 0, 0
		}
		started := time.Now()
		rec := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(rec,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		return time.Since(started), rec.Code
	}
	for index := range 20 {
		call("warm", index)
	}

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(2))
	stop := make(chan struct{})
	var hogs sync.WaitGroup
	for range 6 {
		hogs.Add(1)
		go func() {
			defer hogs.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	const sessions = 10
	const duration = 20 * time.Second
	var mu sync.Mutex
	var latencies []time.Duration
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
					latency, code := call(fmt.Sprintf("load-%d", session), index)
					if code != http.StatusOK {
						t.Errorf("call %d of session %d: HTTP %d", index, session, code)
					}
					mu.Lock()
					latencies = append(latencies, latency)
					mu.Unlock()
				}()
			}
			inflight.Wait()
		}()
	}
	calls.Wait()
	close(stop)
	hogs.Wait()
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	if len(latencies) < sessions*int(duration/time.Second)/2 {
		t.Fatalf("only %d calls ran", len(latencies))
	}
	p95 := latencies[len(latencies)*95/100]
	t.Logf("%d calls at 10/s on 2 CPUs with 6 busy goroutines: p50 %v p95 %v max %v",
		len(latencies), latencies[len(latencies)/2], p95, latencies[len(latencies)-1])
	if p95 > hookAnswerQueueBudget {
		t.Fatalf("answer p95 %v is over the %v answer budget", p95, hookAnswerQueueBudget)
	}
}
