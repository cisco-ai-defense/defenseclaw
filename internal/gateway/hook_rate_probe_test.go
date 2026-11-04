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
	"reflect"
	"runtime"
	"runtime/pprof"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// hookRateProbeDeadline is the native hook's local answer deadline: a call
// the gateway answers later than this is a deadline denial at the agent.
const hookRateProbeDeadline = 3500 * time.Millisecond

// TestHookRateProbe is the open-loop form of the SWEEP-100 acceptance cell
// (r108 SWEEP-100.md): the real Claude Code hook handler, audit store, v8
// runtime and WAL guard in process, one session, benign Bash calls offered
// at a fixed rate for a fixed window whether or not earlier calls have been
// answered. It is skipped unless DEFENSECLAW_HOOK_RATE_PROBE=1. Settings:
//
//	DEFENSECLAW_HOOK_RATE          offered calls per second (default 100)
//	DEFENSECLAW_HOOK_RATE_SECONDS  window in seconds (default 120)
//	DEFENSECLAW_HOOK_RATE_GROW_MIB grow audit.db to at least this size first (default 0)
//	DEFENSECLAW_HOOK_RATE_OUT      directory for cpu, block and mutex profiles
//
// It fails unless every call is allowed, p95 is under 1 s, no call misses
// the hook's 3.5 s deadline, the sampled WAL stays within its 256 MiB bound
// and no WAL guard pass holds the audit writer 50 ms or more.
func TestHookRateProbe(t *testing.T) {
	if os.Getenv("DEFENSECLAW_HOOK_RATE_PROBE") != "1" {
		t.Skip("set DEFENSECLAW_HOOK_RATE_PROBE=1 to run the hook rate probe")
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
	rate, seconds := setting("DEFENSECLAW_HOOK_RATE", 100), setting("DEFENSECLAW_HOOK_RATE_SECONDS", 120)
	growMiB := setting("DEFENSECLAW_HOOK_RATE_GROW_MIB", 0)
	if rate < 1 || seconds < 1 {
		t.Fatal("the probe needs a rate and a window")
	}
	out := os.Getenv("DEFENSECLAW_HOOK_RATE_OUT")

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

	call := func(session, toolID string) (time.Duration, bool) {
		body, _ := json.Marshal(map[string]any{
			"session_id": session, "transcript_path": filepath.Join(cwd, "transcript.jsonl"), "cwd": cwd,
			"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": toolID,
			"tool_input": map[string]any{"command": "echo ok"},
		})
		began := time.Now()
		recorder := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(recorder,
			httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)))
		elapsed := time.Since(began)
		var answer struct {
			Action string `json:"action"`
		}
		allowed := recorder.Code == http.StatusOK && json.Unmarshal(recorder.Body.Bytes(), &answer) == nil && answer.Action == "allow"
		return elapsed, allowed
	}
	if growMiB > 0 {
		// Real rows first, so the copies below carry the shape of a call.
		for index := range 300 {
			if _, allowed := call("hook-rate-probe-seed", fmt.Sprintf("seed_%04d", index)); !allowed {
				t.Fatalf("seed call %d was not allowed", index)
			}
		}
		began := time.Now()
		growHookRateProbeAuditDB(t, fixture.path, int64(growMiB)<<20)
		t.Logf("RATEPROBE grown audit.db=%dMiB in %v", hookRateProbeFileSize(fixture.path)>>20, time.Since(began).Round(time.Second))
	}

	var queueSnapshot func() (int64, time.Duration)
	if method := reflect.ValueOf(fixture.store).MethodByName("CallWriteQueueSnapshot"); method.IsValid() {
		queueSnapshot = func() (int64, time.Duration) {
			value := method.Call(nil)[0]
			return value.FieldByName("Depth").Int(), time.Duration(value.FieldByName("OldestAge").Int())
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	var loops sync.WaitGroup
	defer func() { cancel(); loops.Wait() }()
	var statsMu sync.Mutex
	var walPeak, queuePeak int64
	var queueOldest, heldMax, heldSum, passMax time.Duration
	var passes, writerPasses, bounded, deferred, restarted, failed int
	loops.Add(2)
	go func() {
		defer loops.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
			wal := hookRateProbeFileSize(fixture.path + "-wal")
			var depth int64
			var oldest time.Duration
			if queueSnapshot != nil {
				depth, oldest = queueSnapshot()
			}
			statsMu.Lock()
			walPeak = max(walPeak, wal)
			queuePeak = max(queuePeak, depth)
			queueOldest = max(queueOldest, oldest)
			statsMu.Unlock()
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
			if ctx.Err() != nil {
				return
			}
			statsMu.Lock()
			passes++
			if err != nil {
				failed++
			}
			if result.WriterHeld > 0 {
				writerPasses++
				heldSum += result.WriterHeld
				heldMax = max(heldMax, result.WriterHeld)
			}
			if result.Bounded {
				bounded++
			}
			if result.WriterDeferred {
				deferred++
			}
			if result.Restarted {
				restarted++
			}
			passMax = max(passMax, time.Since(began))
			statsMu.Unlock()
		}
	}()

	if out != "" {
		if err := os.MkdirAll(out, 0o700); err != nil {
			t.Fatal(err)
		}
		cpuFile, err := os.Create(filepath.Join(out, "cpu.prof"))
		if err != nil {
			t.Fatal(err)
		}
		if err := pprof.StartCPUProfile(cpuFile); err != nil {
			t.Fatal(err)
		}
		defer func() { pprof.StopCPUProfile(); _ = cpuFile.Close() }()
		runtimeSetProfileRates(true)
		defer runtimeSetProfileRates(false)
		defer func() {
			for _, name := range []string{"block", "mutex"} {
				file, err := os.Create(filepath.Join(out, name+".prof"))
				if err == nil {
					_ = pprof.Lookup(name).WriteTo(file, 0)
					_ = file.Close()
				}
			}
		}()
	}

	calls := rate * seconds
	latencies := make([]time.Duration, calls)
	answered := make([]time.Time, calls)
	var notAllowed atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for index := range calls {
		if wait := time.Until(start.Add(time.Duration(index) * time.Second / time.Duration(rate))); wait > 0 {
			time.Sleep(wait)
		}
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			elapsed, allowed := call("hook-rate-probe", fmt.Sprintf("toolu_%06d", index))
			latencies[index], answered[index] = elapsed, time.Now()
			if !allowed {
				notAllowed.Add(1)
			}
		}(index)
		if (index+1)%(rate*10) == 0 {
			statsMu.Lock()
			t.Logf("RATEPROBE sent %d audit.db=%dMiB wal=%dMiB wal_peak=%dMiB queue_peak=%d queue_oldest=%v held_max=%v",
				index+1, hookRateProbeFileSize(fixture.path)>>20, hookRateProbeFileSize(fixture.path+"-wal")>>20, walPeak>>20,
				queuePeak, queueOldest.Round(time.Millisecond), heldMax.Round(time.Millisecond))
			statsMu.Unlock()
		}
	}
	wg.Wait()
	window := start.Add(time.Duration(seconds) * time.Second)
	sorted := slices.Clone(latencies)
	slices.Sort(sorted)
	var late, inWindow int
	for index, latency := range latencies {
		if latency >= hookRateProbeDeadline {
			late++
		}
		if !answered[index].After(window) {
			inWindow++
		}
	}
	quantile := func(q float64) time.Duration {
		return sorted[min(int(float64(calls)*q), calls-1)].Round(time.Microsecond)
	}
	statsMu.Lock()
	t.Logf("RATEPROBE rate=%d seconds=%d calls=%d grown=%dMiB p50=%v p95=%v p99=%v max=%v not_allowed=%d over_deadline=%d answered_in_window_per_s=%.2f "+
		"queue_peak=%d queue_oldest_max=%v guard_passes=%d writer_passes=%d held_max=%v held_sum=%v pass_max=%v bounded=%d deferred=%d restarted=%d failed=%d wal_peak=%dMiB audit.db=%dMiB",
		rate, seconds, calls, int64(growMiB), quantile(0.50), quantile(0.95), quantile(0.99), sorted[calls-1].Round(time.Microsecond),
		notAllowed.Load(), late, float64(inWindow)/float64(seconds),
		queuePeak, queueOldest.Round(time.Millisecond), passes, writerPasses, heldMax.Round(time.Microsecond), heldSum.Round(time.Millisecond),
		passMax.Round(time.Millisecond), bounded, deferred, restarted, failed, walPeak>>20, hookRateProbeFileSize(fixture.path)>>20)
	if notAllowed.Load() != 0 {
		t.Errorf("%d of %d benign calls were not allowed", notAllowed.Load(), calls)
	}
	if p95 := quantile(0.95); p95 >= time.Second {
		t.Errorf("p95 %v is not under 1 s", p95)
	}
	if late != 0 {
		t.Errorf("%d calls missed the hook's %v deadline", late, hookRateProbeDeadline)
	}
	if walPeak > auditWALLimitBytes {
		t.Errorf("the sampled WAL reached %d bytes, over its %d-byte bound", walPeak, int64(auditWALLimitBytes))
	}
	if heldMax >= 50*time.Millisecond {
		t.Errorf("a WAL guard pass held the audit writer for %v, not under 50 ms", heldMax)
	}
	statsMu.Unlock()
}

func runtimeSetProfileRates(on bool) {
	if on {
		runtime.SetBlockProfileRate(int(100 * time.Microsecond))
		runtime.SetMutexProfileFraction(5)
		return
	}
	runtime.SetBlockProfileRate(0)
	runtime.SetMutexProfileFraction(0)
}

func hookRateProbeFileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

// growHookRateProbeAuditDB copies the audit rows already in path, with fresh
// identifiers, until the database file is at least target bytes, so the
// audit_events table and its indexes have the depth of a grown per-user
// history (SWEEP-100: a 2+ GiB audit DB).
func growHookRateProbeAuditDB(t *testing.T, path string, target int64) {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	rows, err := db.Query(`SELECT name FROM pragma_table_info('audit_events')`)
	if err != nil {
		t.Fatal(err)
	}
	var columns, values []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
		switch name {
		case "id":
			values = append(values, "id || '.g' || k.n || '.' || lower(hex(randomblob(4)))")
		case "session_id", "trace_id", "request_id", "run_id", "tool_id", "agent_instance_id":
			values = append(values, "lower(hex(randomblob(16)))")
		case "timestamp":
			values = append(values, "datetime(timestamp, '-' || (k.n * 37 % 86400) || ' minutes')")
		default:
			values = append(values, name)
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TEMP TABLE hook_rate_probe_seed AS SELECT * FROM audit_events`); err != nil {
		t.Fatal(err)
	}
	statement := fmt.Sprintf(`WITH RECURSIVE k(n) AS (SELECT ? UNION ALL SELECT n+1 FROM k WHERE n < ?)
		INSERT INTO audit_events (%s) SELECT %s FROM hook_rate_probe_seed, k`,
		strings.Join(columns, ", "), strings.Join(values, ", "))
	for round := 0; hookRateProbeFileSize(path)+hookRateProbeFileSize(path+"-wal") < target; round++ {
		if _, err := db.Exec(statement, round*20+1, round*20+20); err != nil {
			t.Fatalf("grow audit_events: %v", err)
		}
		if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			t.Fatalf("checkpoint the grown audit.db: %v", err)
		}
	}
	if _, err := db.Exec(`DROP TABLE hook_rate_probe_seed`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		t.Fatal(err)
	}
}
