// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// A provider's tool ID is unique within its session, not necessarily across
// sessions. Offer three overlapping hook calls every 300 ms (10/s) and keep
// each session's ten calls distinct. Every benign call must get a decision,
// and every session/tool pair must retain its own pending audit operation.
func TestHookFloodKeepsPendingIdentityPerCall(t *testing.T) {
	const calls = 60
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
	cwd := t.TempDir()
	failures := make(chan string, calls)
	var pending sync.WaitGroup
	start := time.Now()
	for group := range calls / 3 {
		if wait := time.Until(start.Add(time.Duration(group) * 300 * time.Millisecond)); wait > 0 {
			time.Sleep(wait)
		}
		for slot := range 3 {
			index := group*3 + slot
			pending.Add(1)
			go func() {
				defer pending.Done()
				body, _ := json.Marshal(map[string]any{
					"session_id":      fmt.Sprintf("flood-session-%02d", index/10),
					"transcript_path": filepath.Join(cwd, "transcript.jsonl"),
					"cwd":             cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash",
					"tool_use_id": fmt.Sprintf("toolu_%02d", index%10),
					"tool_input":  map[string]any{"command": "echo ok"},
				})
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				var answer struct {
					Action string `json:"action"`
				}
				if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &answer) != nil || answer.Action != "allow" {
					failures <- fmt.Sprintf("call %d: status=%d answer=%s", index, recorder.Code, recorder.Body.String())
				}
			}()
		}
	}
	pending.Wait()
	close(failures)
	for failure := range failures {
		t.Error(failure)
	}
	database, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var operations int
	if err := database.QueryRow(`SELECT COUNT(*) FROM correlation_pending_operations WHERE operation_type='tool'`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if operations != calls {
		t.Fatalf("pending operations=%d, want one unique session/tool key for each of %d decisions", operations, calls)
	}
	terminal := func(session, toolID string) {
		t.Helper()
		payload := map[string]any{"hook_event_name": "PostToolUse", "tool_name": "Bash",
			"tool_use_id": toolID, "tool_response": "ok"}
		if session != "" {
			payload["session_id"] = session
		}
		body, _ := json.Marshal(payload)
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("terminal status=%d answer=%s", recorder.Code, recorder.Body.String())
		}
	}
	status := func(session, toolID string) audit.CorrelationOperationStatus {
		t.Helper()
		var got string
		if err := database.QueryRow(`SELECT status FROM correlation_pending_operations WHERE session_id=? AND operation_id=?`,
			session, toolID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		return audit.CorrelationOperationStatus(got)
	}
	terminal("flood-session-01", "toolu_00")
	if got := status("flood-session-01", "toolu_00"); got != audit.CorrelationOperationCompleted {
		t.Fatalf("exact session terminal left status %s, want completed", got)
	}
	if got := status("flood-session-00", "toolu_00"); got != audit.CorrelationOperationActive {
		t.Fatalf("another session's operation changed to %s", got)
	}
	terminal("unrelated-session", "toolu_00")
	for session := range calls / 10 {
		if session == 1 {
			continue
		}
		if got := status(fmt.Sprintf("flood-session-%02d", session), "toolu_00"); got != audit.CorrelationOperationActive {
			t.Fatalf("mismatched session terminal changed session %d to %s", session, got)
		}
	}
	terminal("", "toolu_01")
	for session := range calls / 10 {
		if got := status(fmt.Sprintf("flood-session-%02d", session), "toolu_01"); got != audit.CorrelationOperationActive {
			t.Fatalf("ambiguous terminal changed session %d to %s", session, got)
		}
	}
	// A provider can omit the session on the start and report it on the
	// terminal. The exact ID still names the connector-scoped start uniquely.
	startBody, _ := json.Marshal(map[string]any{
		"transcript_path": filepath.Join(cwd, "transcript.jsonl"),
		"cwd":             cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_use_id": "sessionless-tool", "tool_input": map[string]any{"command": "echo ok"},
	})
	startRecorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(startRecorder,
		httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(startBody)))
	if startRecorder.Code != http.StatusOK {
		t.Fatalf("sessionless start status=%d answer=%s", startRecorder.Code, startRecorder.Body.String())
	}
	terminal("reported-session", "sessionless-tool")
	var sessionlessStatus string
	if err := database.QueryRow(`SELECT status FROM correlation_pending_operations WHERE session_id IS NULL AND operation_id='sessionless-tool'`).Scan(&sessionlessStatus); err != nil {
		t.Fatal(err)
	}
	if sessionlessStatus != string(audit.CorrelationOperationCompleted) {
		t.Fatalf("sessionless start with reported-session terminal status=%s, want completed", sessionlessStatus)
	}
}

// hookFloodMinute is one minute of a flood: the latencies of the calls
// launched in it, summarized.
type hookFloodMinute struct {
	average, p50, p99, max time.Duration
}

// The flatness rule of the B-26 flood cells (rel-1-0-3 GAP-0247, GAP-0186):
// minute 1 is warm-up, minutes 2-5 are the baseline, and each of the last
// five minutes has its average and p99 within 1.25x of the baseline's mean
// average and mean p99. No call takes 5 s or more.
const (
	hookFloodBaselineFirst = 1 // zero-based: minutes 2-5
	hookFloodBaselineLast  = 4
	hookFloodCheckedTail   = 5
	hookFloodFlatRatio     = 1.25
	hookFloodMaxCall       = 5 * time.Second
	// hookFloodWALBound is the published sampled WAL file ceiling of the
	// registered 10 Hz flood cells (GAP-0952).
	hookFloodWALBound = auditWALLimitBytes
	// hookFloodWALSample is how often the probe samples the WAL file size.
	hookFloodWALSample = 250 * time.Millisecond
)

// hookFloodFlatnessViolations applies the flatness rule to a flood's minutes
// and returns one line per violation.
func hookFloodFlatnessViolations(minutes []hookFloodMinute) []string {
	if len(minutes) < hookFloodBaselineLast+1+hookFloodCheckedTail {
		return []string{fmt.Sprintf("the flood has %d minutes; the flatness rule needs at least %d",
			len(minutes), hookFloodBaselineLast+1+hookFloodCheckedTail)}
	}
	var averages, p99s time.Duration
	for _, minute := range minutes[hookFloodBaselineFirst : hookFloodBaselineLast+1] {
		averages += minute.average
		p99s += minute.p99
	}
	count := time.Duration(hookFloodBaselineLast - hookFloodBaselineFirst + 1)
	baseAverage, baseP99 := averages/count, p99s/count
	limit := func(base time.Duration) time.Duration { return time.Duration(float64(base) * hookFloodFlatRatio) }
	var violations []string
	for index := len(minutes) - hookFloodCheckedTail; index < len(minutes); index++ {
		minute := minutes[index]
		if minute.average > limit(baseAverage) {
			violations = append(violations, fmt.Sprintf("minute %d average %v is over %v (1.25x the minutes 2-5 mean %v)",
				index+1, minute.average, limit(baseAverage), baseAverage))
		}
		if minute.p99 > limit(baseP99) {
			violations = append(violations, fmt.Sprintf("minute %d p99 %v is over %v (1.25x the minutes 2-5 mean %v)",
				index+1, minute.p99, limit(baseP99), baseP99))
		}
	}
	for index, minute := range minutes {
		if minute.max >= hookFloodMaxCall {
			violations = append(violations, fmt.Sprintf("minute %d has a call of %v", index+1, minute.max))
		}
	}
	return violations
}

func TestHookFloodFlatnessRule(t *testing.T) {
	flat := func(average, p99 time.Duration) hookFloodMinute {
		return hookFloodMinute{average: average, p50: average, p99: p99, max: p99}
	}
	minutes := func(tail hookFloodMinute) []hookFloodMinute {
		out := []hookFloodMinute{flat(400*time.Millisecond, 900*time.Millisecond)} // warm-up is ignored
		for range 4 {
			out = append(out, flat(100*time.Millisecond, 200*time.Millisecond))
		}
		for range 20 {
			out = append(out, flat(110*time.Millisecond, 220*time.Millisecond))
		}
		for range 5 {
			out = append(out, tail)
		}
		return out
	}
	if got := hookFloodFlatnessViolations(minutes(flat(125*time.Millisecond, 250*time.Millisecond))); len(got) != 0 {
		t.Fatalf("a flood at 1.25x is flat: %v", got)
	}
	if got := hookFloodFlatnessViolations(minutes(flat(126*time.Millisecond, 200*time.Millisecond))); len(got) != 5 {
		t.Fatalf("an average over 1.25x in the last five minutes: %v, want five violations", got)
	}
	if got := hookFloodFlatnessViolations(minutes(flat(100*time.Millisecond, 251*time.Millisecond))); len(got) != 5 {
		t.Fatalf("a p99 over 1.25x in the last five minutes: %v, want five violations", got)
	}
	slow := minutes(flat(100*time.Millisecond, 200*time.Millisecond))
	slow[12].max = hookFloodMaxCall
	if got := hookFloodFlatnessViolations(slow); len(got) != 1 {
		t.Fatalf("a 5 s call: %v, want one violation", got)
	}
	if got := hookFloodFlatnessViolations(minutes(flat(0, 0))[:9]); len(got) != 1 {
		t.Fatalf("a nine-minute flood: %v, want the length violation", got)
	}
}

// hookFloodGuardMinute sums the WAL guard passes that ended in one minute and
// the largest WAL file sampled in it.
type hookFloodGuardMinute struct {
	passes, writer, deferred, restarted, truncated, failed, syncs int
	held, heldMax, passMax, syncMax                               time.Duration
	walMax                                                        int64
}

// TestHookFloodProbe drives the real Claude Code hook handler, audit store and
// v8 runtime in process with one session at a fixed rate, the shape of the
// B-26 flood cells (rel-1-0-3 GAP-0247, GAP-0186, GAP-0244), and fails unless
// every flood meets the flatness rule (hookFloodFlatnessViolations). It is
// skipped unless DEFENSECLAW_HOOK_FLOOD_PROBE=1 and runs on Linux, macOS and
// Windows, so a lane can run the test binary on the host that saturated; it
// needs no source tree there. Settings:
//
//	DEFENSECLAW_HOOK_FLOOD_CALLS  calls per flood (default 6000; at least ten minutes of calls)
//	DEFENSECLAW_HOOK_FLOOD_RATE   calls per second (default 10)
//	DEFENSECLAW_HOOK_FLOOD_FLOODS back-to-back floods in one process (default 1)
//	DEFENSECLAW_HOOK_FLOOD_IDLE   idle seconds after each flood (default 0)
//	DEFENSECLAW_HOOK_FLOOD_OUT    directory for cpu, block, mutex and heap profiles
//
// Each minute's line has the latencies of the calls launched in it, the WAL
// guard passes that ended in it (how often and how long a pass held the audit
// writer connection, and how often and how long it synced the database file
// off the writer) and the largest WAL file sampled every 250 ms. The probe
// also fails when a sample is over 256 MiB (hookFloodWALBound).
func TestHookFloodProbe(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_FLOOD_PROBE") != "1" {
		t.Skip("set DEFENSECLAW_HOOK_FLOOD_PROBE=1 to run the hook flood probe")
	}
	setting := func(name string, value int) int {
		if raw := os.Getenv(name); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 0 {
				t.Fatalf("%s=%q is not a count", name, raw)
			}
			return parsed
		}
		return value
	}
	calls, rate := setting("DEFENSECLAW_HOOK_FLOOD_CALLS", 6000), setting("DEFENSECLAW_HOOK_FLOOD_RATE", 10)
	floods, idle := setting("DEFENSECLAW_HOOK_FLOOD_FLOODS", 1), setting("DEFENSECLAW_HOOK_FLOOD_IDLE", 0)
	if rate < 1 || floods < 1 {
		t.Fatal("the probe needs a rate and one flood")
	}
	segment := rate * 60
	if minutes := hookFloodBaselineLast + 1 + hookFloodCheckedTail; calls < minutes*segment {
		t.Fatalf("the flatness rule needs at least %d minutes: %d calls at %d/s", minutes, minutes*segment, rate)
	}
	out := os.Getenv("DEFENSECLAW_HOOK_FLOOD_OUT")

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
	cwd := t.TempDir()

	// The sidecar's background audit loops: the WAL guard every
	// auditWALGuardInterval with the sidecar's limits, and the planner
	// statistics every auditPlannerStatsInterval.
	var guardMu sync.Mutex
	var guardStart time.Time
	guardMinutes := map[int]*hookFloodGuardMinute{}
	ctx, cancel := context.WithCancel(t.Context())
	var loops sync.WaitGroup
	defer func() { cancel(); loops.Wait() }()
	loops.Add(3)
	var walPeak int64
	go func() {
		defer loops.Done()
		tick := time.NewTicker(hookFloodWALSample)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			info, err := os.Stat(fixture.path + "-wal")
			if err != nil {
				continue
			}
			guardMu.Lock()
			if !guardStart.IsZero() {
				index := int(time.Since(guardStart) / time.Minute)
				minute := guardMinutes[index]
				if minute == nil {
					minute = &hookFloodGuardMinute{}
					guardMinutes[index] = minute
				}
				minute.walMax = max(minute.walMax, info.Size())
				walPeak = max(walPeak, info.Size())
			}
			guardMu.Unlock()
		}
	}()
	go func() {
		defer loops.Done()
		tick := time.NewTicker(auditWALGuardInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			began := time.Now()
			pass, passCancel := context.WithTimeout(ctx, auditWALCopyTimeout)
			result, err := fixture.store.CheckpointWALIfLarge(pass, auditWALGuardTriggerBytes, auditWALWriterBudget)
			passCancel()
			guardMu.Lock()
			if !guardStart.IsZero() {
				minute := guardMinutes[int(time.Since(guardStart)/time.Minute)]
				if minute == nil {
					minute = &hookFloodGuardMinute{}
					guardMinutes[int(time.Since(guardStart)/time.Minute)] = minute
				}
				minute.passes++
				if err != nil {
					minute.failed++
				}
				if result.WriterHeld > 0 {
					minute.writer++
					minute.held += result.WriterHeld
					minute.heldMax = max(minute.heldMax, result.WriterHeld)
				}
				if result.WriterDeferred {
					minute.deferred++
				}
				if result.Restarted {
					minute.restarted++
				}
				if result.Truncated {
					minute.truncated++
				}
				minute.syncs += result.Syncs
				minute.syncMax = max(minute.syncMax, result.SyncLongest)
				minute.passMax = max(minute.passMax, time.Since(began))
			}
			guardMu.Unlock()
		}
	}()
	go func() {
		defer loops.Done()
		tick := time.NewTicker(auditPlannerStatsInterval)
		defer tick.Stop()
		for {
			_, _ = fixture.store.RefreshPlannerStatistics(ctx)
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()

	// The runtime's estimate of the CPU time it used: every CPU class but idle.
	cpuSample := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	cpuSeconds := func() float64 {
		metrics.Read(cpuSample)
		if cpuSample[0].Value.Kind() != metrics.KindFloat64 || cpuSample[1].Value.Kind() != metrics.KindFloat64 {
			return 0
		}
		return cpuSample[0].Value.Float64() - cpuSample[1].Value.Float64()
	}
	fileSize := func(path string) int64 {
		info, err := os.Stat(path)
		if err != nil {
			return 0
		}
		return info.Size()
	}
	memory := func(label string) {
		runtime.GC()
		var stats runtime.MemStats
		runtime.ReadMemStats(&stats)
		t.Logf("memory %s heap_inuse=%dKiB heap_sys=%dKiB heap_released=%dKiB sys=%dKiB goroutines=%d",
			label, stats.HeapInuse>>10, stats.HeapSys>>10, stats.HeapReleased>>10, stats.Sys>>10, runtime.NumGoroutine())
	}
	writeProfile := func(name string, write func(*os.File) error) {
		if out == "" {
			return
		}
		file, err := os.Create(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := write(file); err != nil {
			t.Fatal(err)
		}
	}
	heapProfile := func(name string) {
		runtime.GC()
		writeProfile(name, func(file *os.File) error { return pprof.WriteHeapProfile(file) })
	}
	if out != "" {
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		runtime.SetBlockProfileRate(int(100 * time.Microsecond))
		runtime.SetMutexProfileFraction(5)
		defer runtime.SetBlockProfileRate(0)
		defer runtime.SetMutexProfileFraction(0)
	}
	memory("start")
	heapProfile("heap-start.prof")

	for flood := 1; flood <= floods; flood++ {
		session := fmt.Sprintf("hook-flood-probe-%d", flood)
		latencies := make([]time.Duration, calls)
		// An `echo ok` call is allowed; a block here is a failed check (an
		// audit row the store could not write fails closed).
		var blocked atomic.Int64
		var cpuFile *os.File
		startCPU := func(name string) {
			if out == "" {
				return
			}
			cpuFile, err = os.Create(filepath.Join(out, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := pprof.StartCPUProfile(cpuFile); err != nil {
				t.Fatal(err)
			}
		}
		stopCPU := func() {
			if cpuFile != nil {
				pprof.StopCPUProfile()
				_ = cpuFile.Close()
				cpuFile = nil
			}
		}
		startCPU(fmt.Sprintf("cpu-flood%d-first.prof", flood))
		var wg sync.WaitGroup
		start := time.Now()
		guardMu.Lock()
		guardStart = start
		clear(guardMinutes)
		walPeak = 0
		guardMu.Unlock()
		segmentCPU := cpuSeconds()
		for index := range calls {
			if wait := time.Until(start.Add(time.Duration(index) * time.Second / time.Duration(rate))); wait > 0 {
				time.Sleep(wait)
			}
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				body, _ := json.Marshal(map[string]any{
					"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
					"hook_event_name": "PreToolUse", "tool_name": "Bash",
					"tool_use_id": fmt.Sprintf("toolu_%d_%06d", flood, index),
					"tool_input":  map[string]any{"command": "echo ok"},
				})
				began := time.Now()
				recorder := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
				latencies[index] = time.Since(began)
				var answer struct {
					Action string `json:"action"`
				}
				if json.Unmarshal(recorder.Body.Bytes(), &answer) != nil || answer.Action != "allow" {
					blocked.Add(1)
				}
			}(index)
			if index == calls/6 {
				stopCPU()
			}
			if index == calls-calls/6 {
				startCPU(fmt.Sprintf("cpu-flood%d-last.prof", flood))
			}
			if (index+1)%segment == 0 {
				now := cpuSeconds()
				t.Logf("flood %d sent %d audit.db=%d wal=%d cpu_per_call=%.1fms", flood, index+1,
					fileSize(fixture.path), fileSize(fixture.path+"-wal"), (now-segmentCPU)*1000/float64(segment))
				segmentCPU = now
			}
		}
		wg.Wait()
		stopCPU()
		t.Logf("flood %d drained %v after the first call", flood, time.Since(start).Round(time.Millisecond))
		guardMu.Lock()
		guardStart = time.Time{}
		guards := map[int]hookFloodGuardMinute{}
		for minute, stats := range guardMinutes {
			guards[minute] = *stats
		}
		floodWALPeak := walPeak
		guardMu.Unlock()
		var minutes []hookFloodMinute
		for first := 0; first+segment <= calls; first += segment {
			part := slices.Clone(latencies[first : first+segment])
			slices.Sort(part)
			var sum time.Duration
			for _, latency := range part {
				sum += latency
			}
			minute := hookFloodMinute{
				average: sum / time.Duration(segment), p50: part[segment/2],
				p99: part[segment*99/100], max: part[segment-1],
			}
			minutes = append(minutes, minute)
			guard := guards[len(minutes)-1]
			t.Logf("flood %d minute %d calls %d-%d average=%v p50=%v p99=%v max=%v guard passes=%d writer=%d deferred=%d restarted=%d truncated=%d failed=%d writer_held=%v writer_held_max=%v pass_max=%v wal_max=%d syncs=%d sync_max=%v",
				flood, len(minutes), first, first+segment,
				minute.average.Round(time.Microsecond), minute.p50.Round(time.Microsecond),
				minute.p99.Round(time.Microsecond), minute.max.Round(time.Microsecond),
				guard.passes, guard.writer, guard.deferred, guard.restarted, guard.truncated, guard.failed,
				guard.held.Round(time.Millisecond), guard.heldMax.Round(time.Millisecond), guard.passMax.Round(time.Millisecond),
				guard.walMax, guard.syncs, guard.syncMax.Round(time.Millisecond))
		}
		all := slices.Clone(latencies)
		slices.Sort(all)
		t.Logf("flood %d all %d calls p50=%v p99=%v p999=%v max=%v not_allowed=%d", flood, calls,
			all[calls/2].Round(time.Microsecond), all[calls*99/100].Round(time.Microsecond),
			all[calls*999/1000].Round(time.Microsecond), all[calls-1].Round(time.Microsecond), blocked.Load())
		if blocked.Load() > int64(calls/1000) {
			t.Errorf("flood %d: %d of %d calls were not allowed, over 0.1%%", flood, blocked.Load(), calls)
		}
		for _, violation := range hookFloodFlatnessViolations(minutes) {
			t.Errorf("flood %d is not flat: %s", flood, violation)
		}
		t.Logf("flood %d sampled WAL peak %d bytes (bound %d)", flood, floodWALPeak, int64(hookFloodWALBound))
		if floodWALPeak > hookFloodWALBound {
			t.Errorf("flood %d: the WAL file reached %d bytes, over the %d-byte sampled bound", flood, floodWALPeak, int64(hookFloodWALBound))
		}
		memory(fmt.Sprintf("flood%d-end", flood))
		for waited := 0; waited < idle; waited += 60 {
			pause := min(60, idle-waited)
			time.Sleep(time.Duration(pause) * time.Second)
			memory(fmt.Sprintf("flood%d-idle+%ds", flood, waited+pause))
		}
		heapProfile(fmt.Sprintf("heap-flood%d.prof", flood))
	}
	writeProfile("block.prof", func(file *os.File) error { return pprof.Lookup("block").WriteTo(file, 0) })
	writeProfile("mutex.prof", func(file *os.File) error { return pprof.Lookup("mutex").WriteTo(file, 0) })
}
