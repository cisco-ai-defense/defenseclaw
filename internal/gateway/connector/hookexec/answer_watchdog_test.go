// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
)

const cpuBurnHelperEnv = "DEFENSECLAW_HOOKEXEC_TEST_CPU_BURN"

// TestCPUBurnHelper is a child process of startCPUContention: it keeps one
// CPU busy until it is killed (at most 30 seconds).
func TestCPUBurnHelper(t *testing.T) {
	if os.Getenv(cpuBurnHelperEnv) != "1" {
		t.Skip("helper process of the CPU contention tests")
	}
	for until := time.Now().Add(30 * time.Second); time.Now().Before(until); {
	}
}

// startCPUContention fills every CPU of the host with busy processes of the
// same priority as the test, the way an attestation repair filled the CPU of
// the Windows twin in GAP-0155, until the test ends.
func startCPUContention(t *testing.T) {
	t.Helper()
	burners := runtime.NumCPU() + 2
	for range burners {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCPUBurnHelper$")
		cmd.Env = append(os.Environ(), cpuBurnHelperEnv+"=1", "GOMAXPROCS=1")
		if err := cmd.Start(); err != nil {
			t.Fatalf("start a CPU burner: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
	}
	time.Sleep(200 * time.Millisecond)
}

// firstWriteRecorder keeps what the agent reads and when the first byte came.
type firstWriteRecorder struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	first time.Time
}

func (r *firstWriteRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.first.IsZero() && len(p) > 0 {
		r.first = time.Now()
	}
	return r.buf.Write(p)
}

func (r *firstWriteRecorder) read() (string, time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String(), r.first
}

// ignoringContextRT is a transport held in work no context ends (a service
// query the busy system does not answer) until release closes.
type ignoringContextRT struct{ release chan struct{} }

func (rt ignoringContextRT) RoundTrip(*http.Request) (*http.Response, error) {
	<-rt.release
	return nil, io.EOF
}

// managedWindowsStandalone is a managed Windows standalone hook (the
// profile of the B2W and BW twins).
func managedWindowsStandalone(opts *Options) {
	managedCodex(opts)
	opts.ExplainUnenrolledAccount = true
}

// GAP-0155, GAP-0167: the 4 s answer budget holds on a host whose CPU is
// full: a managed tool call whose own work is held up (a transport in a
// service query no context ends, or per-call work before the request) is
// still answered, blocked, by its answer deadline, and the process ends
// then. Before the watchdog the deny came only when the held-up work ended.
func TestToolCallAnswerBudgetHoldsUnderCPUContention(t *testing.T) {
	startCPUContention(t)
	const budget = time.Second
	for _, test := range []struct {
		name   string
		mutate func(opts *Options, release chan struct{})
	}{
		{"transport held in a service query", func(opts *Options, release chan struct{}) {
			opts.HTTPClient = &http.Client{Transport: ignoringContextRT{release: release}}
		}},
		{"per-call work held before the request", func(opts *Options, release chan struct{}) {
			opts.AssetFacts = func(string, []byte) string {
				<-release
				return ""
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			shortAnswerBudget(t, budget)
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			stdout := &firstWriteRecorder{}
			exited := make(chan int, 1)
			started := time.Now()
			returned := make(chan runResult, 1)
			go func() {
				returned <- run(t, "claudecode", &stubRT{status: http.StatusOK, body: `{"action":"allow"}`}, func(opts *Options) {
					managedWindowsStandalone(opts)
					opts.StartedAt = started
					opts.Stdout = stdout
					opts.Exit = func(code int) { exited <- code }
					test.mutate(opts, release)
				})
			}()
			var code int
			select {
			case code = <-exited:
			case <-time.After(10 * time.Second):
				t.Fatal("no answer 10 s after the call started")
			}
			out, first := stdout.read()
			if late := first.Sub(started); late > budget+750*time.Millisecond {
				t.Fatalf("the answer came %s after the call started, want by the %s budget", late, budget)
			}
			if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) ||
				!strings.Contains(out, managedGatewayNoAnswerReason) {
				t.Fatalf("exit %d stdout %q, want the managed deny naming %s", code, out, managedGatewayNoAnswerReason)
			}
			unblock()
			select {
			case result := <-returned:
				if result.code != 0 {
					t.Fatalf("Run returned %d after the watchdog answered with 0", result.code)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return once the held-up work ended")
			}
			if out, _ := stdout.read(); strings.Count(out, `"permissionDecision":"`) != 1 {
				t.Fatalf("stdout %q, want exactly one answer", out)
			}
		})
	}
}

// The watchdog stands down when the call is answered in time: it neither
// writes a second answer nor ends the process.
func TestAnswerWatchdogStandsDownWhenTheCallIsAnsweredInTime(t *testing.T) {
	// The budget leaves room for the request itself: a Claude Code or Codex
	// request holds its delivery body up to hookDeliveryCapabilityWait
	// (250 ms) for the gateway's 103, which the stub never sends, and a
	// hosted macOS runner adds its own latency (300 ms failed there).
	const budget = 1500 * time.Millisecond
	shortAnswerBudget(t, budget)
	for _, body := range []string{`{"action":"allow"}`, `{"action":"block","reason":"policy rule"}`} {
		exited := make(chan int, 1)
		result := run(t, "claudecode", &stubRT{status: http.StatusOK, body: body}, func(opts *Options) {
			managedWindowsStandalone(opts)
			opts.Exit = func(code int) { exited <- code }
		})
		// Past the deadline: a watchdog that did not stand down has fired.
		time.Sleep(budget + 500*time.Millisecond)
		select {
		case code := <-exited:
			t.Fatalf("%s: the watchdog ended the process (%d) after the call was answered", body, code)
		default:
		}
		if strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) || strings.Count(result.stdout, "\n") > 1 {
			t.Fatalf("%s: stdout %q stderr %q, want the gateway's answer alone", body, result.stdout, result.stderr)
		}
		if strings.Contains(body, "block") != blocked(result) {
			t.Fatalf("%s: code %d stdout %q stderr %q does not carry the gateway's decision", body, result.code, result.stdout, result.stderr)
		}
	}
}

// GAP-0155: the account, its session and the asset facts are computed once
// for a call, not again for every try while the gateway restarts.
func TestRequestFactsAreComputedOncePerCall(t *testing.T) {
	fastRestartRetries(t)
	var computed atomic.Int32
	rt := failingThen(3, syscall.ECONNREFUSED, `{"action":"allow"}`)
	result := run(t, "claudecode", rt, func(opts *Options) {
		managedWindowsStandalone(opts)
		opts.AssetFacts = func(string, []byte) string {
			computed.Add(1)
			return "facts-v1"
		}
	})
	if rt.requests != 4 || result.code != 0 || strings.Contains(result.stdout, "deny") {
		t.Fatalf("requests=%d code=%d stdout=%q, want the restarted gateway's allow on the 4th try", rt.requests, result.code, result.stdout)
	}
	if got := computed.Load(); got != 1 {
		t.Fatalf("asset facts computed %d times for one call, want once", got)
	}
	if got := rt.gotReq.Header.Get(assetfacts.Header); got != "facts-v1" {
		t.Fatalf("the last try carried asset facts %q, want them copied", got)
	}
}

// GAP-0155, GAP-0167: a managed try after the gateway was seen not running
// must have its connection within the restart budget. A try that began just
// before the budget ended and met a slow service manager ends there, with
// the not-running deny, instead of at the answer deadline or later.
func TestManagedRetryEndsAtTheRestartBudgetWhenItCannotConnect(t *testing.T) {
	fastRestartRetries(t)
	shortAnswerBudget(t, 6*time.Second)
	notRunning := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	rt := &stubRT{onRequest: func(rt *stubRT, req *http.Request) (*http.Response, error) {
		if rt.requests == 1 {
			return nil, notRunning
		}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}}
	started := time.Now()
	result := run(t, "claudecode", rt, func(opts *Options) {
		managedWindowsStandalone(opts)
		opts.StartedAt = started
	})
	elapsed := time.Since(started)
	if elapsed < gatewayRestartBudget-500*time.Millisecond || elapsed > gatewayRestartBudget+600*time.Millisecond {
		t.Fatalf("the call ended after %s, want at the %s restart budget", elapsed, gatewayRestartBudget)
	}
	if !strings.Contains(result.stdout, `"permissionDecision":"deny"`) || !strings.Contains(result.stdout, managedGatewayNotRunningReason) {
		t.Fatalf("stdout %q, want the not-running deny", result.stdout)
	}
}
