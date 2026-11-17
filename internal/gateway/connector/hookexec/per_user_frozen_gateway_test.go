// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// frozenProbeForTest turns the frozen-gateway probe on for the test's
// injected clients (production probes only the Windows loopback client) with
// a short window.
func frozenProbeForTest(t *testing.T, window time.Duration) {
	t.Helper()
	previousOn, previousWindow, previousGap := perUserFrozenProbeOn, perUserFrozenProbeWindow, perUserFrozenConfirmGap
	perUserFrozenProbeOn = func(Options) bool { return true }
	perUserFrozenProbeWindow = window
	perUserFrozenConfirmGap = 50 * time.Millisecond
	t.Cleanup(func() {
		perUserFrozenProbeOn, perUserFrozenProbeWindow, perUserFrozenConfirmGap = previousOn, previousWindow, previousGap
	})
}

func frozenGAP1107Payload(event string) string {
	switch event {
	case "UserPromptSubmit":
		return `{"hook_event_name":"UserPromptSubmit","session_id":"s-1107","prompt":"list the files"}`
	case "Stop":
		return `{"hook_event_name":"Stop","session_id":"s-1107","stop_hook_active":false}`
	}
	return `{"hook_event_name":"` + event + `","session_id":"s-1107","tool_name":"Bash","tool_input":{"command":"ls -la"},"tool_response":{"stdout":"a b"}}`
}

// rel-1-0-10 GAP-1107: a per-user gateway that is frozen (suspended) takes
// the connection on Windows and answers nothing. A Claude Code prompt, tool
// result or stop event has no answer deadline: it waited its whole hook
// timeout and was blocked with "fail mode closed" in the open tier. A probe
// of the same listener that also gets no status proves the outage, so the
// open tier lets the event run with the warning at once, and the strict
// tier blocks it at once, as the structured block (exit 0), never the exit 2
// that makes Claude Code print the registered command line.
func TestGAP1107FrozenGatewayPromptToolResultAndStopFollowTheOutageMode(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	frozenProbeForTest(t, 300*time.Millisecond)
	for _, event := range []string{"UserPromptSubmit", "PostToolUse", "PostToolBatch", "Stop"} {
		for _, tier := range []string{"open", "closed"} {
			t.Run(event+"/"+tier, func(t *testing.T) {
				var home string
				result, elapsed := runAgainstGateway(t, "claudecode", hungGateway(t), func(opts *Options) {
					home = opts.Home
					opts.Event = event
					opts.FailMode = "closed"
					opts.OutageFailModeNow = func() string { return tier }
					opts.Stdin = strings.NewReader(frozenGAP1107Payload(event))
					// Without the probe the call waits for this timeout.
					opts.HTTPClient.Timeout = 6 * time.Second
				})
				if elapsed > 3*time.Second {
					t.Fatalf("answered after %s, want the bounded frozen-gateway answer", elapsed)
				}
				if result.code != 0 {
					t.Fatalf("exit %d stdout=%q stderr=%q: an exit-2 block shows Claude Code's registered command line",
						result.code, result.stdout, result.stderr)
				}
				out := result.stdout + result.stderr
				if tier == "open" && strings.Contains(out, "fail mode closed") {
					t.Fatalf("frozen gateway answered as a fail-closed no-answer: %q", out)
				}
				entry := lastHookFailure(t, home)
				if entry["reason"] != perUserGatewayNoAnswerReason || entry["category"] != "transport" {
					t.Fatalf("failure = %v, want the transport no-answer record", entry)
				}
				wantBlock := tier == "closed" && event != "Stop"
				if got := strings.Contains(result.stdout, `"decision":"block"`); got != wantBlock {
					t.Fatalf("block=%v, want %v: stdout=%q stderr=%q", got, wantBlock, result.stdout, result.stderr)
				}
				wantOutcome := "fail_open"
				if wantBlock {
					wantOutcome = "fail_closed"
				}
				if event == "Stop" && tier == "closed" {
					wantOutcome = entry["outcome"] // a closed stop is a deliberate allow
				}
				if entry["outcome"] != wantOutcome {
					t.Fatalf("outcome %q, want %q: %v", entry["outcome"], wantOutcome, entry)
				}
			})
		}
	}
}

// A gateway that is up answers the probe while it is still evaluating the
// call (an LLM judge of a prompt can take longer than the tool-gate budget):
// the call keeps waiting for the decision and takes it.
func TestGAP1107BusyGatewayKeepsItsLateDecision(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	frozenProbeForTest(t, 300*time.Millisecond)
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		time.Sleep(900 * time.Millisecond)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	})
	var home string
	result, elapsed := runAgainstGateway(t, "claudecode", addr, func(opts *Options) {
		home = opts.Home
		opts.Event = "UserPromptSubmit"
		opts.FailMode = "closed"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(frozenGAP1107Payload("UserPromptSubmit"))
		opts.HTTPClient.Timeout = 6 * time.Second
	})
	if result.code != 0 || elapsed < 900*time.Millisecond || strings.Contains(result.stdout+result.stderr, "did not answer") {
		t.Fatalf("after %s exit %d stdout=%q stderr=%q, want the late gateway allow", elapsed, result.code, result.stdout, result.stderr)
	}
	if data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl")); err == nil && len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("a busy gateway wrote a failure row: %s", data)
	}
}

// A tool-gate event keeps its answer budget and the ordinary-call rule; the
// probe never runs for it.
func TestGAP1107ToolGateIsNotProbed(t *testing.T) {
	for _, event := range []string{"PreToolUse", "PermissionRequest"} {
		opts := Options{Connector: "claudecode", Event: event, HTTPClient: &http.Client{}, StartedAt: time.Now()}
		previous := perUserFrozenProbeOn
		perUserFrozenProbeOn = func(Options) bool { return true }
		if perUserFrozenProbeCall(opts) {
			t.Errorf("%s is probed", event)
		}
		perUserFrozenProbeOn = previous
	}
	for _, opts := range []Options{
		{Connector: "claudecode", Event: "UserPromptSubmit", HTTPClient: &http.Client{}, StartedAt: time.Now(), ManagedEnterprise: true},
		{Connector: "claudecode", Event: "UserPromptSubmit", HTTPClient: &http.Client{}, StartedAt: time.Now(), SecureClient: true},
		{Connector: "kiro", Event: "UserPromptSubmit", HTTPClient: &http.Client{}, StartedAt: time.Now()},
	} {
		previous := perUserFrozenProbeOn
		perUserFrozenProbeOn = func(Options) bool { return true }
		if perUserFrozenProbeCall(opts) {
			t.Errorf("%+v is probed", opts.Connector)
		}
		perUserFrozenProbeOn = previous
	}
	if perUserFrozenProbeOn(Options{perUserLoopbackDial: false}) {
		t.Error("an injected client is probed in production")
	}
}

// The closed answer of a Claude Code tool-result event is the structured
// block a policy verdict gives, with exit 0: an exit-2 block made Claude Code
// print the whole registered cmd.exe hook-guard command line (GAP-1107).
func TestGAP1107ClaudeToolResultBlockIsStructured(t *testing.T) {
	for _, event := range []string{"PostToolUse", "PostToolUseFailure", "PostToolBatch"} {
		var stdout, stderr bytes.Buffer
		code := emitManagedClaudeBlock(Options{Event: event, eventBound: true, Stdout: &stdout, Stderr: &stderr}, "DefenseClaw blocked this tool result: x")
		var out map[string]string
		if code != 0 || stderr.Len() != 0 || json.Unmarshal(stdout.Bytes(), &out) != nil ||
			out["decision"] != "block" || out["reason"] == "" || out["systemMessage"] != out["reason"] {
			t.Errorf("%s: exit %d stdout=%q stderr=%q", event, code, stdout.String(), stderr.String())
		}
		// An event read from the payload keeps the exit 2 that blocks every
		// event Claude Code may run it as.
		stdout.Reset()
		stderr.Reset()
		if code := emitManagedClaudeBlock(Options{Event: event, Stdout: &stdout, Stderr: &stderr}, "x"); code != blockExit || stdout.Len() != 0 {
			t.Errorf("%s from the payload: exit %d stdout=%q", event, code, stdout.String())
		}
	}
}

// healthHangsFirst serves /health with no status for its first `hang`
// requests (until the probe gives up) and 200 after them; every other path
// answers allow after callDelay.
func healthHangsFirst(t *testing.T, hang int32, callDelay time.Duration) string {
	t.Helper()
	var probes atomic.Int32
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if probes.Add(1) <= hang {
				select {
				case <-r.Context().Done():
				case <-release:
				}
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		select {
		case <-time.After(callDelay):
			_, _ = w.Write([]byte(`{"action":"allow"}`))
		case <-r.Context().Done():
		}
	})
}

// GAP-1122: the probe window starts at the verified connection. A dial and
// owner check that take longer than the whole window (a loaded host) are not
// a miss when the gateway then answers /health.
func TestGAP1122SlowVerifiedDialIsNotAMiss(t *testing.T) {
	frozenProbeForTest(t, 200*time.Millisecond)
	addr := healthHangsFirst(t, 0, 0)
	dialer := &net.Dialer{}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			time.Sleep(600 * time.Millisecond) // the dial and the owner-tuple check
			return dialer.DialContext(ctx, network, address)
		}}}
	if got := perUserProbeGateway(context.Background(), Options{APIAddr: addr, HTTPClient: client}); got != probeNotFrozen {
		t.Fatalf("slow verified dial = %v, want not frozen", got)
	}
}

// GAP-1122: one missed probe is not a frozen gateway. A live gateway that
// misses one probe and answers the next keeps the call waiting for its
// decision; the call never turns into an outage allow.
func TestGAP1122OneMissedProbeIsNotFrozen(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	frozenProbeForTest(t, 300*time.Millisecond)
	var home string
	result, elapsed := runAgainstGateway(t, "claudecode", healthHangsFirst(t, 1, 1500*time.Millisecond), func(opts *Options) {
		home = opts.Home
		opts.Event = "UserPromptSubmit"
		opts.FailMode = "closed"
		opts.OutageFailModeNow = func() string { return "open" }
		opts.Stdin = strings.NewReader(frozenGAP1107Payload("UserPromptSubmit"))
		opts.HTTPClient.Timeout = 6 * time.Second
	})
	if result.code != 0 || elapsed < 1500*time.Millisecond || strings.Contains(result.stdout+result.stderr, "did not answer") {
		t.Fatalf("after %s exit %d stdout=%q stderr=%q, want the gateway's own late allow", elapsed, result.code, result.stdout, result.stderr)
	}
	if data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl")); err == nil && len(bytes.TrimSpace(data)) != 0 {
		t.Fatalf("one missed probe wrote a failure row: %s", data)
	}
}

// GAP-1122: the watch calls the gateway frozen only after two consecutive
// misses; an answer or an inconclusive probe between them restarts the count.
func TestGAP1122TwoConsecutiveMissesAreFrozen(t *testing.T) {
	shortAnswerBudget(t, 10*time.Millisecond)
	frozenProbeForTest(t, 10*time.Millisecond)
	for _, tc := range []struct {
		name   string
		seq    []frozenProbeResult
		frozen bool
	}{
		{"two misses", []frozenProbeResult{probeMissed, probeMissed}, true},
		{"one miss", []frozenProbeResult{probeMissed}, false},
		{"miss, answer, miss", []frozenProbeResult{probeMissed, probeNotFrozen, probeMissed}, false},
		{"miss, clock jump, miss", []frozenProbeResult{probeMissed, probeInconclusive, probeMissed}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			previous := perUserFrozenProbe
			perUserFrozenProbe = func(context.Context, Options) frozenProbeResult {
				n := int(calls.Add(1))
				if n > len(tc.seq) {
					return probeNotFrozen
				}
				return tc.seq[n-1]
			}
			t.Cleanup(func() { perUserFrozenProbe = previous })
			ctx, _, release := watchPerUserFrozenGateway(context.Background(), Options{
				Connector: "claudecode", Event: "UserPromptSubmit", HTTPClient: &http.Client{}, StartedAt: time.Now(),
			})
			defer release()
			deadline := time.Now().Add(2 * time.Second)
			for int(calls.Load()) <= len(tc.seq) && !perUserGatewayFrozen(ctx) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if got := perUserGatewayFrozen(ctx); got != tc.frozen {
				t.Fatalf("frozen = %v after %d probes, want %v", got, calls.Load(), tc.frozen)
			}
		})
	}
}

// GAP-1122: a window whose wall clock jumped (the host slept and resumed
// mid-call) proves nothing; the same window without the jump is a miss.
func TestGAP1122ClockJumpMakesTheMissInconclusive(t *testing.T) {
	frozenProbeForTest(t, 200*time.Millisecond)
	addr := hungGateway(t)
	opts := Options{APIAddr: addr, HTTPClient: &http.Client{}}
	if got := perUserProbeGateway(context.Background(), opts); got != probeMissed {
		t.Fatalf("plain silent window = %v, want a miss", got)
	}
	previous := frozenProbeWall
	var reads atomic.Int32
	frozenProbeWall = func() time.Time {
		if reads.Add(1) > 1 {
			return time.Now().Round(0).Add(30 * time.Second)
		}
		return time.Now().Round(0)
	}
	t.Cleanup(func() { frozenProbeWall = previous })
	if got := perUserProbeGateway(context.Background(), opts); got != probeInconclusive {
		t.Fatalf("window with a 30 s wall-clock jump = %v, want inconclusive", got)
	}
}
