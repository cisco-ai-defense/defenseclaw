// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// W6 review loop 1: a standalone managed hook whose administrator chose fail
// mode open lets a call through only on an outage (the gateway service is not
// running, is restarting or gives no answer in time). A gateway that answered
// the call with an error status is up: a 429 whose resend cannot be answered
// within the answer budget, a resend after a 429 that is not answered, and a
// 4xx or 5xx whose body is cut off or dropped are blocked, as the fail-modes
// table says. Before, all of them took the no-answer path, which open allows.

// standaloneOpenProfiles are the standalone managed hooks whose administrator
// chose fail mode open: Unix, and Windows (which resends a 401).
var standaloneOpenProfiles = map[string]func(*Options){
	"unix": func(o *Options) {
		managedCodex(o)
		o.FailMode = "open"
	},
	"windows": standaloneOpenCodex,
}

// errorStatusConnectors are connectors whose managed hook has its own open
// answer (Copilot, OpenCode) or block body (Claude Code, Cursor), with the
// payload each reads.
var errorStatusConnectors = []struct {
	connector, event, payload string
}{
	{"codex", "PreToolUse", `{"hook_event_name":"PreToolUse"}`},
	{"claudecode", "PreToolUse", `{"hook_event_name":"PreToolUse","tool_name":"Bash"}`},
	{"copilot", "preToolUse", `{"toolName":"bash","toolArgs":"{\"command\":\"echo ok\"}"}`},
	{"cursor", "beforeShellExecution", `{"hook_event_name":"beforeShellExecution","command":"echo ok"}`},
	{"opencode", "tool.execute.before", `{"event":"tool.execute.before","tool":"bash"}`},
}

// cutOffStatusGateway answers every hook call with status and headers that
// declare a longer body than it sends, then stalls (drop false) or drops the
// connection (drop true).
func cutOffStatusGateway(t *testing.T, status int, drop bool) string {
	t.Helper()
	release := make(chan struct{})
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		const partial = `{"error":"unavailable"}`
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(partial)+64))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, partial)
		w.(http.Flusher).Flush()
		if drop {
			panic(http.ErrAbortHandler)
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	return addr
}

// busyGateway answers the first call 429 with Retry-After: 1 (every call when
// then is nil and hang false), then each later one with then, or not at all
// (hang).
func busyGateway(t *testing.T, hang bool, then http.HandlerFunc) string {
	t.Helper()
	release := make(chan struct{})
	var calls atomic.Int32
	addr := gatewayAt(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 || (then == nil && !hang) {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if then != nil {
			then(w, r)
			return
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	return addr
}

func cutOff503(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Length", "128")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, `{"error":"unavailable"`)
	w.(http.Flusher).Flush()
	<-r.Context().Done()
}

func withConnector(mutate func(*Options), event, payload string) func(*Options) {
	return func(o *Options) {
		mutate(o)
		o.Event = event
		o.Stdin = strings.NewReader(payload)
	}
}

func TestStandaloneOpenBlocksAGatewayThatAnsweredAnErrorStatus(t *testing.T) {
	shortAnswerFloor(t)
	type gatewayCase struct {
		name   string
		budget time.Duration
		addr   func(t *testing.T) string
	}
	cases := []gatewayCase{
		{"429 whose Retry-After outlasts the budget", 400 * time.Millisecond,
			func(t *testing.T) string { return busyGateway(t, false, nil) }},
		{"429, then a resend the gateway never answers", 1500 * time.Millisecond,
			func(t *testing.T) string { return busyGateway(t, true, nil) }},
		{"429, then a 503 whose body is cut off", 1500 * time.Millisecond,
			func(t *testing.T) string { return busyGateway(t, false, cutOff503) }},
	}
	// Codex gets every status; the other connectors, whose answers differ
	// only in their output, one 5xx and one 4xx each way.
	var codexOnly []gatewayCase
	for _, status := range []int{500, 502, 503, 400, 401, 403, 404, 409} {
		for _, drop := range []bool{false, true} {
			how := "stalls"
			if drop {
				how = "drops"
			}
			gc := gatewayCase{"HTTP " + strconv.Itoa(status) + " whose body " + how, 400 * time.Millisecond,
				func(t *testing.T) string { return cutOffStatusGateway(t, status, drop) }}
			if status == 503 || status == 404 {
				cases = append(cases, gc)
			} else {
				codexOnly = append(codexOnly, gc)
			}
		}
	}
	for profile, standaloneOpen := range standaloneOpenProfiles {
		for _, c := range errorStatusConnectors {
			mutate := withConnector(standaloneOpen, c.event, c.payload)
			t.Run(profile+"/"+c.connector, func(t *testing.T) {
				// The control: a verified gateway that took the call and gave
				// no answer in the whole budget is the outage the administrator's
				// open covers (managedNoAnswerOutage, benign defaults loop round
				// 3), so every case below blocks for its error status alone.
				shortAnswerBudget(t, 400*time.Millisecond)
				if hung, _ := runAgainstGateway(t, c.connector, hungGateway(t), mutate); blocked(hung) {
					t.Fatalf("a gateway that took the call and gave no answer was blocked in fail mode open: code=%d stdout=%q stderr=%q",
						hung.code, hung.stdout, hung.stderr)
				}
				all := cases
				if c.connector == "codex" {
					all = append(append([]gatewayCase{}, cases...), codexOnly...)
				}
				for _, gc := range all {
					shortAnswerBudget(t, gc.budget)
					result, elapsed := runAgainstGateway(t, c.connector, gc.addr(t), mutate)
					if !blocked(result) {
						t.Errorf("%s: allowed in fail mode open: code=%d stdout=%q stderr=%q", gc.name, result.code, result.stdout, result.stderr)
					}
					if elapsed > gc.budget+time.Second {
						t.Errorf("%s: answered after %s, want within the %s budget", gc.name, elapsed, gc.budget)
					}
				}
			})
		}
	}
	// A gateway that answered and then cut off its body cannot use open mode.
	shortAnswerBudget(t, 400*time.Millisecond)
	for mode, want := range map[string]bool{"open": true, "closed": true} {
		result, _ := runAgainstGateway(t, "claudecode", cutOffStatusGateway(t, http.StatusServiceUnavailable, false), func(o *Options) {
			o.FailMode = mode
		})
		if blocked(result) != want {
			t.Fatalf("per-user %s: blocked = %v, want %v: code=%d stdout=%q stderr=%q", mode, blocked(result), want, result.code, result.stdout, result.stderr)
		}
	}
}

// heldBody is a response body whose Read ignores every context until release
// closes, as a process the host does not schedule in time.
type heldBody struct{ release chan struct{} }

func (b heldBody) Read([]byte) (int, error) {
	<-b.release
	return 0, io.ErrUnexpectedEOF
}

func (heldBody) Close() error { return nil }

// The watchdog answers a call whose own work is held past the deadline. Once
// the gateway answered the call with an error status, that answer is closed
// too, not the fail-open answer of a gateway that gave none.
func TestWatchdogAnswerIsClosedOnceTheGatewayAnsweredAnErrorStatus(t *testing.T) {
	shortAnswerFloor(t)
	for _, tc := range []struct {
		name   string
		budget time.Duration
		answer func(rt *stubRT, release chan struct{}) (*http.Response, error)
	}{
		{"503 whose body is held", 400 * time.Millisecond, func(_ *stubRT, release chan struct{}) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: heldBody{release}, Header: make(http.Header)}, nil
		}},
		{"404 whose body is held", 400 * time.Millisecond, func(_ *stubRT, release chan struct{}) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusNotFound, Body: heldBody{release}, Header: make(http.Header)}, nil
		}},
		{"429, then a resend that is held", 1500 * time.Millisecond, func(rt *stubRT, release chan struct{}) (*http.Response, error) {
			if rt.requests == 1 {
				header := make(http.Header)
				header.Set("Retry-After", "1")
				return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader("{}")), Header: header}, nil
			}
			<-release
			return nil, io.EOF
		}},
	} {
		for profile, standaloneOpen := range standaloneOpenProfiles {
			t.Run(tc.name+"/"+profile, func(t *testing.T) {
				shortAnswerBudget(t, tc.budget)
				release := make(chan struct{})
				var releaseOnce sync.Once
				unblock := func() { releaseOnce.Do(func() { close(release) }) }
				t.Cleanup(unblock)
				rt := &stubRT{onRequest: func(rt *stubRT, _ *http.Request) (*http.Response, error) { return tc.answer(rt, release) }}
				stdout := &firstWriteRecorder{}
				exited := make(chan int, 1)
				returned := make(chan runResult, 1)
				go func() {
					returned <- run(t, "codex", rt, func(o *Options) {
						standaloneOpen(o)
						o.StartedAt = time.Now()
						o.Stdout = stdout
						o.Exit = func(code int) { exited <- code }
						o.FailureLogHome = userLogHome(t.TempDir())
					})
				}()
				select {
				case code := <-exited:
					if out, _ := stdout.read(); !blocked(runResult{code: code, stdout: out}) {
						t.Fatalf("the watchdog answered exit %d stdout %q, want the closed answer", code, out)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("the watchdog did not answer the held call")
				}
				unblock()
				select {
				case result := <-returned:
					if out, _ := stdout.read(); !blocked(runResult{code: result.code, stdout: out}) {
						t.Fatalf("Run returned %d stdout %q, want the closed answer", result.code, out)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("Run did not return once the call was released")
				}
			})
		}
	}
}
