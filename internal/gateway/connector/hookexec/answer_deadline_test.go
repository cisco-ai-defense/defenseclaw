// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func shortAnswerBudget(t *testing.T, budget time.Duration) {
	t.Helper()
	previous := hookAnswerBudget
	hookAnswerBudget = budget
	t.Cleanup(func() { hookAnswerBudget = previous })
}

// gatewayAt serves every hook call with handle on a real loopback listener,
// so informational responses travel as they do in production.
func gatewayAt(t *testing.T, handle http.HandlerFunc) string {
	t.Helper()
	server := httptest.NewServer(handle)
	t.Cleanup(server.Close)
	return server.Listener.Addr().String()
}

// hungGateway accepts every call and never answers it while the test runs.
func hungGateway(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	addr := gatewayAt(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Cleanups run last in, first out: the handlers return before the
	// server closes.
	t.Cleanup(func() { close(release) })
	return addr
}

func runAgainstGateway(t *testing.T, connector, addr string, mutate func(*Options)) (runResult, time.Duration) {
	t.Helper()
	started := time.Now()
	result := run(t, connector, nil, func(opts *Options) {
		opts.APIAddr = addr
		opts.HTTPClient = &http.Client{}
		opts.StartedAt = started
		if mutate != nil {
			mutate(opts)
		}
	})
	return result, time.Since(started)
}

func blocked(result runResult) bool {
	return result.code != 0 || strings.Contains(result.stdout, "deny") || strings.Contains(result.stdout, `"block"`)
}

// GAP-0155, GAP-0167, GAP-0139, GAP-0160: a managed gateway that accepted a
// tool call but gives no decision (it is stopping, starting, repairing or
// too busy) holds the call no longer than the answer budget, and the call is
// blocked then, whatever the hook's fail mode: never allowed.
func TestManagedToolCallFailsClosedWhenTheGatewayDoesNotAnswerInTime(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	shortAnswerFloor(t)
	for _, event := range []string{"PreToolUse", "PermissionRequest", "PostToolUse", "UserPromptSubmit"} {
		for _, open := range []bool{false, true} {
			if open && toolGateEvent("codex", event) {
				continue // Existing tool-gate outage policy is tested separately.
			}
			t.Run(event+"/open="+strconv.FormatBool(open), func(t *testing.T) {
				home := t.TempDir()
				result, elapsed := runAgainstGateway(t, "codex", hungGateway(t), func(opts *Options) {
					managedWindowsStandalone(opts)
					opts.FailureLogHome = userLogHome(home)
					opts.Event = event
					if open {
						opts.FailMode = "open"
					}
					opts.Stdin = strings.NewReader(`{"hook_event_name":"` + event + `","tool_name":"shell","prompt":"echo ok"}`)
					// Keep the regression fast even when the answer budget is missing.
					opts.HTTPClient.Timeout = 1200 * time.Millisecond
				})
				if elapsed > time.Second || !blocked(result) {
					t.Errorf("after %s code=%d stdout=%q stderr=%q, want a bounded block", elapsed, result.code, result.stdout, result.stderr)
				}
				entry := lastHookFailure(t, home)
				if entry["reason"] != managedGatewayNoAnswerReason || entry["hook"] != "codex-hook" ||
					entry["category"] != "transport" || entry["fail_mode"] != "closed" || entry["outcome"] != "fail_closed" {
					t.Errorf("failure = %v, want the event's managed no-answer refusal", entry)
				}
				data, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
				if err != nil || strings.Count(string(data), "\n") != 1 {
					t.Fatalf("failure log = %q, err=%v, want exactly one row", data, err)
				}
			})
		}
	}
}

// A decision that comes after the budget is not used: the gateway's late
// allow does not turn into an allow of the tool call.
func TestALateAllowIsNotTakenAfterTheAnswerBudget(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(700 * time.Millisecond)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	})
	result, elapsed := runAgainstGateway(t, "codex", addr, managedCodex)
	if elapsed > 650*time.Millisecond {
		t.Fatalf("the call waited %s, want it ended at the 300ms budget", elapsed)
	}
	if !blocked(result) {
		t.Fatalf("a late allow was taken: code=%d stdout=%q stderr=%q", result.code, result.stdout, result.stderr)
	}
}

// A gateway that waits on a remote scanner (the LLM judge, Cisco AI
// Defense) reports it with 102 Processing, and the call waits past the
// answer budget for the scanner's answer, up to the progress ceiling
// (TestProgressReportWaitsNoLongerThanTheCeiling).
func TestToolCallKeepsItsBudgetWhileTheGatewayWaitsOnARemoteScanner(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	var asked atomic.Bool
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		asked.Store(r.Header.Get(HookProgressHeader) == "1")
		w.WriteHeader(HookProgressStatus)
		time.Sleep(700 * time.Millisecond)
		_, _ = w.Write([]byte(`{"action":"block","reason":"judge rule"}`))
	})
	result, _ := runAgainstGateway(t, "codex", addr, managedCodex)
	if !asked.Load() {
		t.Fatal("the hook did not ask for progress reports")
	}
	if !strings.Contains(result.stdout+result.stderr, "judge rule") {
		t.Fatalf("stdout=%q stderr=%q, want the scanner's decision after the budget", result.stdout, result.stderr)
	}
	allowed := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(HookProgressStatus)
		time.Sleep(700 * time.Millisecond)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	})
	result, _ = runAgainstGateway(t, "codex", allowed, managedCodex)
	if result.code != 0 || strings.Contains(result.stdout, "deny") {
		t.Fatalf("code=%d stdout=%q stderr=%q, want the scanner's allow", result.code, result.stdout, result.stderr)
	}
}

// A per-user hook applies its fail mode at the end of the answer budget:
// closed blocks and names the cause; open is the account's own choice.
func TestPerUserToolCallAppliesItsFailModeWhenTheGatewayDoesNotAnswer(t *testing.T) {
	shortAnswerBudget(t, 300*time.Millisecond)
	closed, elapsed := runAgainstGateway(t, "codex", hungGateway(t), func(opts *Options) { opts.FailMode = "closed" })
	if elapsed > time.Second || !blocked(closed) || !strings.Contains(closed.stderr, "did not answer in time") {
		t.Fatalf("closed: after %s code=%d stdout=%q stderr=%q, want a block naming the slow gateway",
			elapsed, closed.code, closed.stdout, closed.stderr)
	}
	open, elapsed := runAgainstGateway(t, "claudecode", hungGateway(t), func(opts *Options) { opts.FailMode = "open" })
	if elapsed > time.Second || open.code != 0 || !strings.Contains(open.stdout, "did not answer in time") {
		t.Fatalf("open: after %s code=%d stdout=%q stderr=%q, want the notice", elapsed, open.code, open.stdout, open.stderr)
	}
}

// Prompts, session and stop events, and Secure Client hooks, keep their
// whole budget and send no progress request.
func TestOnlyToolCallsOfNativeHooksHaveTheAnswerBudget(t *testing.T) {
	shortAnswerBudget(t, 200*time.Millisecond)
	slowAllow := func(asked *atomic.Bool) string {
		return gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(HookProgressHeader) != "" {
				asked.Store(true)
			}
			time.Sleep(500 * time.Millisecond)
			_, _ = w.Write([]byte(`{"action":"allow"}`))
		})
	}
	for _, test := range []struct {
		name      string
		connector string
		mutate    func(*Options)
	}{
		{"a prompt", "claudecode", func(opts *Options) { opts.Event = "UserPromptSubmit"; opts.FailMode = "closed" }},
		{"a stop event", "claudecode", func(opts *Options) { opts.Event = "Stop"; opts.FailMode = "closed" }},
		{"Secure Client", "codex", func(opts *Options) { managedCodex(opts); opts.SecureClient = true }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var asked atomic.Bool
			result, _ := runAgainstGateway(t, test.connector, slowAllow(&asked), test.mutate)
			if result.code != 0 || strings.Contains(result.stdout, "deny") {
				t.Fatalf("code=%d stdout=%q stderr=%q, want the slow allow", result.code, result.stdout, result.stderr)
			}
			if asked.Load() {
				t.Fatal("the hook asked for progress reports")
			}
		})
	}
}

// A gateway that answers 429 (too busy) is sent the call again only while
// a resend can still be answered within the budget (GAP-0205 kept within
// GAP-0155): the call is blocked within the budget, not after four resends.
func TestBusyResendsEndWithinTheAnswerBudget(t *testing.T) {
	shortAnswerBudget(t, 1500*time.Millisecond)
	var calls atomic.Int32
	addr := gatewayAt(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	result, elapsed := runAgainstGateway(t, "codex", addr, managedCodex)
	if elapsed > 2*time.Second {
		t.Fatalf("busy resends took %s, want them ended within the 1.5s budget", elapsed)
	}
	if got := calls.Load(); got < 1 || got > 2 {
		t.Fatalf("the gateway saw %d calls, want the resends that fit the budget (1 or 2)", got)
	}
	if !blocked(result) || !strings.Contains(result.stdout+result.stderr, managedGatewayNoAnswerReason) {
		t.Fatalf("code=%d stdout=%q stderr=%q, want a block naming the slow gateway", result.code, result.stdout, result.stderr)
	}
}

func TestToolGateEvents(t *testing.T) {
	for _, test := range []struct {
		connector, event string
		want             bool
	}{
		{"claudecode", "PreToolUse", true},
		{"claudecode", "PermissionRequest", true},
		{"claudecode", "UserPromptSubmit", false},
		{"claudecode", "Stop", false},
		{"codex", "PreToolUse", true},
		{"codex", "SessionStart", false},
		{"copilot", "preToolUse", true},
		{"copilot", "userPromptSubmitted", false},
		{"cursor", "beforeShellExecution", true},
		{"cursor", "beforeSubmitPrompt", false},
		{"hermes", "pre_tool_call", true},
		{"opencode", "tool.execute.before", true},
		{"amp", "tool.call", true},
		{"unknown", "PreToolUse", false},
	} {
		if got := toolGateEvent(test.connector, test.event); got != test.want {
			t.Errorf("toolGateEvent(%q, %q) = %v, want %v", test.connector, test.event, got, test.want)
		}
	}
}

// The hook's budgets count from the process's creation, which comes before
// this package's initialization.
func TestProcessStartTimeIsTheCreationOfTheProcess(t *testing.T) {
	now := time.Now()
	started, ok := processStartTime(now)
	if !ok {
		if processStartTimeKnown {
			t.Fatal("the system did not report the process start")
		}
		return
	}
	if started.After(hookProcessInit.Add(20 * time.Millisecond)) {
		t.Fatalf("process start %s is after the package init %s", started, hookProcessInit)
	}
	if hookProcessInit.Sub(started) > maxProcessStartAge {
		t.Fatalf("process start %s is %s before the package init", started, hookProcessInit.Sub(started))
	}
	if got := ProcessStartTime(); got.After(time.Now()) {
		t.Fatalf("ProcessStartTime() = %s is in the future", got)
	}
}

// GAP-0527: a managed Codex Stop hook has no answer budget, so a stalled
// gateway ends it at the client timeout. Stop still may not block, and its
// row names the event and the stall, not an unreachable gateway.
func TestManagedCodexStopDuringAGatewayStallNamesTheEventAndTheStall(t *testing.T) {
	for _, failMode := range []string{"closed", "open"} {
		t.Run(failMode, func(t *testing.T) {
			logHome := filepath.Join(t.TempDir(), ".defenseclaw")
			result, _ := runAgainstGateway(t, "codex", hungGateway(t), func(opts *Options) {
				managedCodex(opts)
				opts.ManagedStandalone = true
				opts.ManagedUnixSocket = "/not-used-by-the-test-client/hook.sock"
				opts.FailMode = failMode
				opts.FailureLogHome = func() string { return logHome }
				opts.HTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
				opts.Event = "Stop"
				opts.Stdin = strings.NewReader(`{"hook_event_name":"Stop"}`)
			})
			if blocked(result) {
				t.Fatalf("code=%d stdout=%q stderr=%q, want the neutral Stop allow", result.code, result.stdout, result.stderr)
			}
			data, err := os.ReadFile(filepath.Join(logHome, "logs", "hook-failures.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			var row map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(data), &row); err != nil {
				t.Fatalf("row %q: %v", data, err)
			}
			if row["event"] != "Stop" || row["reason"] != managedGatewayNoAnswerReason {
				t.Fatalf("row %v, want event Stop and reason %s", row, managedGatewayNoAnswerReason)
			}
		})
	}
}
