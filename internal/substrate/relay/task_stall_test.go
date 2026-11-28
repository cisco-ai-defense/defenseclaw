// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0273: an unattended task whose agent waits on a connection that never
// answers (the J46 gateway outage) printed nothing and ran forever. The
// relay now bounds it.

func stallConfig(mode string, args ...string) kit.Config {
	cfg := kit.DefaultConfig()
	cfg.Relay.Connector = "claudecode"
	cfg.Relay.Headless = agentArgv(mode, args...)
	return cfg
}

type eventLog struct {
	mu sync.Mutex
	ev []TaskEvent
}

func (l *eventLog) emit(e TaskEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, e)
}

func (l *eventLog) text(kind string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, e := range l.ev {
		if e.Type == kind {
			b.WriteString(e.Data + "\n")
		}
	}
	return b.String()
}

// flat is a process group that uses nothing.
func flat(int) (Usage, bool) { return Usage{}, true }

func runWithin(t *testing.T, limit time.Duration, f func() TaskEnd) TaskEnd {
	t.Helper()
	done := make(chan TaskEnd, 1)
	go func() { done <- f() }()
	select {
	case end := <-done:
		return end
	case <-time.After(limit):
		t.Fatalf("the task did not end within %s: an unattended run hangs (GAP-0273)", limit)
		return TaskEnd{}
	}
}

func TestSilentTaskIsEndedWithAReason(t *testing.T) {
	var log eventLog
	warmed := 0
	o := HeadlessOptions{
		Warm: func(context.Context, string) error {
			warmed++
			if warmed > 1 {
				return errors.New("connection refused")
			}
			return nil
		},
		Stall: 1500 * time.Millisecond, Tick: 100 * time.Millisecond, Usage: flat,
	}
	start := time.Now()
	end := runWithin(t, 20*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("silent"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.ExitCode != ExitStalled || !end.Stalled {
		t.Fatalf("end %+v, want exit %d stalled", end, ExitStalled)
	}
	if !strings.Contains(end.Cause, "made no progress for 2s") || !strings.Contains(end.Cause, "does not answer (connection refused)") {
		t.Fatalf("cause %q does not say why", end.Cause)
	}
	if !strings.Contains(log.text("error"), end.Cause) {
		t.Fatalf("the task log does not carry the cause: %+v", log.ev)
	}
	if d := time.Since(start); d > stopGrace {
		t.Fatalf("a TERM-able agent took %s to end", d)
	}
}

func TestStalledAgentThatIgnoresTermIsKilled(t *testing.T) {
	if testing.Short() {
		t.Skip("waits the stop grace")
	}
	var log eventLog
	o := HeadlessOptions{Stall: 500 * time.Millisecond, Tick: 100 * time.Millisecond, Usage: flat}
	end := runWithin(t, stopGrace+15*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("ignore-term"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.ExitCode != ExitStalled || !strings.Contains(end.Cause, "the gateway was not checked") {
		t.Fatalf("end %+v", end)
	}
}

func TestRetryNoticesAreNotProgress(t *testing.T) {
	var log eventLog
	o := HeadlessOptions{Stall: time.Second, Tick: 100 * time.Millisecond, Usage: flat}
	end := runWithin(t, 20*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("retry-loop"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if !end.Stalled {
		t.Fatalf("an agent that only retries was not ended: %+v", end)
	}
}

func TestOutputAndUsageAreProgress(t *testing.T) {
	// Output every 200 ms for 5 s, then exit 0: never 4 s without output. The
	// stand-in agent is the test binary, which under -race and load needs
	// over a second to start, so the stall window is wider than a shell's.
	var log eventLog
	o := HeadlessOptions{Stall: 4 * time.Second, Tick: 100 * time.Millisecond, Usage: flat}
	end := runWithin(t, 20*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("talk", "25"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.Stalled || end.ExitCode != 0 {
		t.Fatalf("a talking agent was ended: %+v", end)
	}
	// Silent for 2.5 s but busy (CPU grows every sample): not a stall.
	var n atomic.Int64
	busy := func(int) (Usage, bool) { return Usage{CPU: time.Duration(n.Add(1)) * time.Second}, true }
	o = HeadlessOptions{Stall: time.Second, Tick: 100 * time.Millisecond, Usage: busy}
	end = runWithin(t, 20*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("sleep", "2500ms"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.Stalled || end.ExitCode != 0 {
		t.Fatalf("a busy silent agent was ended: %+v", end)
	}
	// I/O alone counts too (a model stream).
	var io atomic.Uint64
	reading := func(int) (Usage, bool) { return Usage{IO: io.Add(stallIO)}, true }
	o = HeadlessOptions{Stall: time.Second, Tick: 100 * time.Millisecond, Usage: reading}
	end = runWithin(t, 20*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("sleep", "2500ms"), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.Stalled || end.ExitCode != 0 {
		t.Fatalf("a streaming silent agent was ended: %+v", end)
	}
}

// stopAfter returns a file a test script writes a background child's PID
// to (the child-holds-output agent writes it); the child is stopped by that exact PID when the test
// ends. A task that ends normally leaves its background children running,
// and the tests left them behind (GAP-0246).
func stopAfter(t *testing.T) string {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	t.Cleanup(func() {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return
		}
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
			if p, err := os.FindProcess(pid); err == nil {
				_ = p.Kill()
			}
		}
	})
	return pidFile
}

func TestTaskEndsWhenAChildKeepsItsOutputOpen(t *testing.T) {
	// The agent exits; a background child holds stdout. The old relay
	// waited for the pipe to close, so the task never reported its exit.
	var log eventLog
	o := HeadlessOptions{Usage: flat}
	pidFile := stopAfter(t)
	end := runWithin(t, drainBudget+10*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig("child-holds-output", pidFile), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if end.ExitCode != 4 || !strings.Contains(log.text("stdout"), "bye") {
		t.Fatalf("end %+v events %+v", end, log.ev)
	}
}

func TestTaskStallConfig(t *testing.T) {
	cfg := kit.DefaultConfig()
	if got := cfg.Relay.TaskStall(); got != kit.DefaultTaskStall || kit.DefaultTaskStall != 10*time.Minute {
		t.Fatalf("default stall %s", got)
	}
	cfg.Relay.TaskStallMS = 120000
	if cfg.Relay.TaskStall() != 2*time.Minute {
		t.Fatal("task_stall_ms ignored")
	}
}

func TestReportTaskEndRetriesThenStops(t *testing.T) {
	calls := 0
	err := ReportTaskEnd(context.Background(), func(context.Context, TaskEnd) error {
		calls++
		if calls < 2 {
			return kit.ErrUnreachable
		}
		return nil
	}, TaskEnd{ExitCode: 1})
	if err != nil || calls != 2 {
		t.Fatalf("calls %d err %v: an unanswered report is retried", calls, err)
	}
	calls = 0
	err = ReportTaskEnd(context.Background(), func(context.Context, TaskEnd) error {
		calls++
		return errReportRefused
	}, TaskEnd{})
	if !errors.Is(err, errReportRefused) || calls != 1 {
		t.Fatalf("calls %d err %v: a refusal is final", calls, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = ReportTaskEnd(ctx, func(context.Context, TaskEnd) error { return kit.ErrUnreachable }, TaskEnd{})
	if err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("err %v after %s: the report is bounded", err, time.Since(start))
	}
}

func TestGatewayReport(t *testing.T) {
	status := http.StatusNoContent
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 512)
		n, _ := r.Body.Read(buf)
		got = r.URL.Path + " " + string(buf[:n])
		w.WriteHeader(status)
	}))
	defer srv.Close()
	cfg := kit.DefaultConfig()
	cfg.GatewayURL = srv.URL
	cfg.MaxTimeMS, cfg.RetryMaxTimeMS = 2000, 2000
	tr, err := kit.NewTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	report := GatewayReport(tr)
	if err := report(context.Background(), TaskEnd{ExitCode: ExitStalled, Stalled: true, Cause: "c"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got, TaskReportPath+" ") || !strings.Contains(got, `"exit_code":124`) || !strings.Contains(got, `"stalled":true`) {
		t.Fatalf("posted %q", got)
	}
	status = http.StatusNotFound
	if err := report(context.Background(), TaskEnd{}); !errors.Is(err, errReportRefused) {
		t.Fatalf("404: %v", err)
	}
	status = http.StatusServiceUnavailable
	if err := report(context.Background(), TaskEnd{}); err == nil || errors.Is(err, errReportRefused) {
		t.Fatalf("503 must be retryable: %v", err)
	}
}

func TestGatewayVerifierHasADeadline(t *testing.T) {
	hold := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-hold }))
	defer srv.Close()
	defer close(hold)
	g := &GatewayVerifier{URL: srv.URL, Client: srv.Client(), Budget: 300 * time.Millisecond}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer x.y.z")
	start := time.Now()
	if _, err := g.Verify(context.Background(), r); err == nil {
		t.Fatal("a gateway that never answers verified a token")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the token check waited %s on a gateway that never answers", d)
	}
}
