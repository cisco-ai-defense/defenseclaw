// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"runtime/pprof"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestHookBurstProbe is the burst shape of the managed Mac relay cell
// (rel-1-0-4 GAP-0367): WORKERS concurrent callers of one account send CALLS
// PreToolUse calls, each in its own session as the cell's producer does,
// through the per-caller admission and run slots (admitHookCaller) into the
// real Claude Code hook handler, audit store and v8 runtime, with the WAL
// guard running. Warm first fills the store with that many calls (sessions
// of 1000) and takes the planner statistics, as a long-lived gateway has.
// It logs the latency of every call split into the wait for a run slot and
// the time served, and fails when the slowest call reaches the 5 s hook
// budget. It is skipped unless DEFENSECLAW_HOOK_BURST_PROBE=1, so a lane
// can run the test binary on the host that saturated. Settings:
//
//	DEFENSECLAW_HOOK_BURST_WARM    calls written before the burst (default 0)
//	DEFENSECLAW_HOOK_BURST_CALLS   calls in the burst (default 200)
//	DEFENSECLAW_HOOK_BURST_WORKERS concurrent callers (default 32)
//	DEFENSECLAW_HOOK_BURST_OUT     directory for cpu, block and mutex profiles
func TestHookBurstProbe(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_BURST_PROBE") != "1" {
		t.Skip("set DEFENSECLAW_HOOK_BURST_PROBE=1 to run the hook burst probe")
	}
	setting := func(name string, value int) int {
		if raw := os.Getenv(name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil {
				t.Fatal(err)
			}
			return parsed
		}
		return value
	}
	warm, calls, workers := setting("DEFENSECLAW_HOOK_BURST_WARM", 0), setting("DEFENSECLAW_HOOK_BURST_CALLS", 200), setting("DEFENSECLAW_HOOK_BURST_WORKERS", 32)
	out := os.Getenv("DEFENSECLAW_HOOK_BURST_OUT")
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
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)
	// The budget of the relayed sandbox hook class, which the cell's calls
	// took.
	hookClass := sandboxBudgetLimits[sandboxBudgetHook]
	api.hookCallerLimits.rate, api.hookCallerLimits.burst, api.hookCallerLimits.inFlight = hookClass.Rate, hookClass.Burst, hookClass.InFlight
	cwd := t.TempDir()
	hook := api.handleAgentHook("claudecode")
	var mu sync.Mutex
	var queued, served []time.Duration
	refused := 0
	admitted := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		began := time.Now()
		r, release := api.admitHookCaller(w, r, "1532183418", "/api/v1/claudecode/hook")
		if release == nil {
			mu.Lock()
			refused++
			mu.Unlock()
			return
		}
		defer release()
		inSlot := time.Now()
		hook.ServeHTTP(w, r)
		mu.Lock()
		queued = append(queued, inSlot.Sub(began))
		served = append(served, time.Since(inSlot))
		mu.Unlock()
	})
	call := func(h http.Handler, session string, index int) time.Duration {
		if session == "burst" {
			session = fmt.Sprintf("burst-%06d", index)
		}
		body, _ := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
			"hook_event_name": "PreToolUse", "tool_name": "Bash",
			"tool_use_id": fmt.Sprintf("toolu_%s_%06d", session, index),
			"tool_input":  map[string]any{"command": "echo ok"},
		})
		began := time.Now()
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		return time.Since(began)
	}
	run := func(h http.Handler, session string, n, w int) []time.Duration {
		latencies := make([]time.Duration, n)
		next := make(chan int)
		var wg sync.WaitGroup
		for range w {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for index := range next {
					latencies[index] = call(h, session, index)
				}
			}()
		}
		for index := range n {
			next <- index
		}
		close(next)
		wg.Wait()
		return latencies
	}
	size := func(path string) int64 {
		info, err := os.Stat(path)
		if err != nil {
			return 0
		}
		return info.Size()
	}
	if warm > 0 {
		began := time.Now()
		for done := 0; done < warm; done += 1000 {
			run(hook, fmt.Sprintf("warm-%d", done/1000), min(1000, warm-done), 4)
			_, _ = fixture.store.CheckpointWALIfLarge(t.Context(), auditWALLimitBytes, auditWALWriterBudget)
		}
		analyzed, err := fixture.store.RefreshPlannerStatistics(t.Context())
		t.Logf("planner statistics analyzed=%v err=%v", analyzed, err)
		t.Logf("warm %d calls in %v audit.db=%d wal=%d", warm, time.Since(began).Round(time.Millisecond), size(fixture.path), size(fixture.path+"-wal"))
	}
	if out != "" {
		_ = os.MkdirAll(out, 0o700)
		runtime.SetBlockProfileRate(int(100 * time.Microsecond))
		runtime.SetMutexProfileFraction(5)
		file, _ := os.Create(filepath.Join(out, "cpu.prof"))
		_ = pprof.StartCPUProfile(file)
		defer func() {
			pprof.StopCPUProfile()
			file.Close()
			for _, name := range []string{"block", "mutex"} {
				f, _ := os.Create(filepath.Join(out, name+".prof"))
				_ = pprof.Lookup(name).WriteTo(f, 0)
				f.Close()
			}
		}()
	}
	cpuSample := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	cpu := func() float64 {
		metrics.Read(cpuSample)
		return cpuSample[0].Value.Float64() - cpuSample[1].Value.Float64()
	}
	pct := func(s []time.Duration, p int) time.Duration {
		if len(s) == 0 {
			return 0
		}
		return s[min(len(s)-1, len(s)*p/100)].Round(time.Millisecond)
	}
	single := run(admitted, "single", 20, 1)
	slices.Sort(single)
	t.Logf("GOMAXPROCS=%d single p50=%v max=%v", runtime.GOMAXPROCS(0), pct(single, 50), pct(single, 100))
	// The sidecar's WAL guard every auditWALGuardInterval, as in the gateway;
	// each pass that synced the database file or held the writer is logged.
	guardCtx, guardStop := context.WithCancel(t.Context())
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		tick := time.NewTicker(auditWALGuardInterval)
		defer tick.Stop()
		for {
			select {
			case <-guardCtx.Done():
				return
			case <-tick.C:
			}
			began := time.Now()
			pass, passCancel := context.WithTimeout(guardCtx, auditWALCopyTimeout)
			result, err := fixture.store.CheckpointWALIfLarge(pass, auditWALLimitBytes, auditWALWriterBudget)
			passCancel()
			if result.WriterHeld > 0 || result.Syncs > 0 {
				t.Logf("guard pass %v log=%d writer_held=%v syncs=%d sync_longest=%v restarted=%v err=%v",
					time.Since(began).Round(time.Millisecond), result.LogBytes, result.WriterHeld.Round(time.Millisecond),
					result.Syncs, result.SyncLongest.Round(time.Millisecond), result.Restarted, err)
			}
		}
	}()
	mu.Lock()
	queued, served = nil, nil
	mu.Unlock()
	cpu0, began := cpu(), time.Now()
	latencies := run(admitted, "burst", calls, workers)
	elapsed := time.Since(began)
	cpuUsed := cpu() - cpu0
	guardStop()
	<-guardDone
	slices.Sort(latencies)
	slices.Sort(queued)
	slices.Sort(served)
	t.Logf("burst calls=%d workers=%d refused=%d elapsed=%v cpu=%.2fs p50=%v p99=%v max=%v queue p50=%v p99=%v served p50=%v p99=%v audit.db=%d wal=%d",
		calls, workers, refused, elapsed.Round(time.Millisecond), cpuUsed,
		pct(latencies, 50), pct(latencies, 99), pct(latencies, 100), pct(queued, 50), pct(queued, 99), pct(served, 50), pct(served, 99),
		size(fixture.path), size(fixture.path+"-wal"))
	if refused > 0 {
		t.Errorf("%d of %d burst calls were refused (429): a refused call denies its tool call", refused, calls)
	}
	if slowest := pct(latencies, 100); slowest >= hookBurstBudget {
		t.Errorf("the slowest burst call took %v, at or over the %v hook budget", slowest, hookBurstBudget)
	}
}

// hookBurstBudget is the most a burst call may take: the agent's 5 s wait
// for DefenseClaw.
const hookBurstBudget = 5 * time.Second
