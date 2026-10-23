// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// shortAnswerFloor lets a short test budget leave the gateway its answer
// window, so a missing answer is the gateway's outage (gatewayAnswerWindowShort).
func shortAnswerFloor(t *testing.T) {
	t.Helper()
	previous := hookGatewayAnswerFloor
	hookGatewayAnswerFloor = 50 * time.Millisecond
	t.Cleanup(func() { hookGatewayAnswerFloor = previous })
}

// standaloneOpenCodex is a managed Windows standalone Codex hook whose
// administrator chose fail mode open (outages only).
func standaloneOpenCodex(opts *Options) {
	managedWindowsStandalone(opts)
	opts.FailMode = "open"
}

// G-small loop 2, finding 1: a managed hook whose administrator chose fail
// mode open still refuses a failure that is not an outage. When the account
// lookup of its failure row stalls before the refusal is out, the watchdog
// answers at the deadline, and that answer is the call's closed one, not the
// fail-open answer of a gateway that gave none.
func TestWatchdogKeepsAKnownRefusalClosedWhileItsRowWaits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		rt     *stubRT
		mutate func(*Options)
	}{
		{name: "unverified gateway peer", rt: &stubRT{err: errManagedGatewayPeerUnverified}},
		{name: "standalone hook without its socket", rt: ok(`{"action":"allow"}`),
			mutate: func(o *Options) { o.ManagedStandalone = true }},
		{name: "unverified peer, strict availability", rt: &stubRT{err: errManagedGatewayPeerUnverified},
			mutate: func(o *Options) { o.StrictAvailability = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortAnswerBudget(t, 400*time.Millisecond)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			stdout := &firstWriteRecorder{}
			exited := make(chan int, 1)
			returned := make(chan runResult, 1)
			go func() {
				returned <- run(t, "codex", tc.rt, func(o *Options) {
					standaloneOpenCodex(o)
					o.StartedAt = time.Now()
					o.Stdout = stdout
					o.Exit = func(code int) { exited <- code }
					o.FailureLogHome = func() string {
						<-release
						return logHome
					}
					if tc.mutate != nil {
						tc.mutate(o)
					}
				})
			}()
			select {
			case code := <-exited:
				out, _ := stdout.read()
				if !blocked(runResult{code: code, stdout: out}) {
					t.Fatalf("the watchdog answered exit %d stdout %q while the refusal's row waited, want the closed answer", code, out)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the watchdog did not answer while the refusal's row waited on the account lookup")
			}
			unblock()
			select {
			case result := <-returned:
				out, _ := stdout.read()
				if !blocked(runResult{code: result.code, stdout: out}) {
					t.Fatalf("Run returned %d stdout %q, want the closed answer", result.code, out)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return once the lookup ended")
			}
		})
	}
	// No answer is not proof of a stopped service, so the deadline keeps the
	// managed call closed even when the administrator chose open.
	shortAnswerBudget(t, 400*time.Millisecond)
	shortAnswerFloor(t)
	hung := make(chan struct{})
	stdout := &firstWriteRecorder{}
	exited := make(chan int, 1)
	logHome := t.TempDir()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		run(t, "codex", nil, func(o *Options) {
			standaloneOpenCodex(o)
			o.StartedAt = time.Now()
			o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
			o.Stdout = stdout
			o.Exit = func(code int) { exited <- code }
			o.FailureLogHome = userLogHome(logHome)
		})
	}()
	// Run ends before the budget is restored.
	t.Cleanup(func() { close(hung); <-returned })
	select {
	case code := <-exited:
		if out, _ := stdout.read(); !blocked(runResult{code: code, stdout: out}) {
			t.Fatalf("no answer in fail mode open: exit %d stdout %q, want a closed answer", code, out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog did not answer a gateway that gave no answer")
	}
}

// G-small loop 2, finding 2: the account lookup of a managed row can take
// longer than the watchdog's log wait (an NSS or a Windows profile lookup).
// The watchdog that answers a call still leaves its hook-failures row before
// the process ends, with one lookup for the call, both when Run starts the
// watchdog and when the hook command armed it before Run.
func TestWatchdogRowSurvivesASlowAccountLookup(t *testing.T) {
	const lookup = 250 * time.Millisecond
	if lookup <= answerWatchdogLogWait {
		t.Fatalf("the lookup (%s) must outlast the watchdog's log wait (%s)", lookup, answerWatchdogLogWait)
	}
	for _, tc := range []struct {
		name     string
		failMode string
		prearm   bool
		event    string
	}{
		{"watchdog started by Run, fail mode closed", "closed", false, "PreToolUse"},
		{"watchdog started by Run, fail mode open", "open", false, "PreToolUse"},
		{"watchdog armed before Run, fail mode closed", "closed", true, "PreToolUse"},
		{"watchdog armed before Run, fail mode open", "open", true, "PreToolUse"},
		{"prompt watchdog retains closed in outage mode open", "open", false, "UserPromptSubmit"},
		{"result watchdog retains closed in outage mode open", "open", true, "PostToolUse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shortAnswerBudget(t, 800*time.Millisecond)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			var lookups atomic.Int32
			resolve := func() string {
				lookups.Add(1)
				time.Sleep(lookup)
				return logHome
			}
			hung := make(chan struct{})
			rowAtExit := make(chan string, 1)
			exit := func(int) {
				row, _ := os.ReadFile(filepath.Join(logHome, "logs", "hook-failures.jsonl"))
				rowAtExit <- string(row)
			}
			started := time.Now()
			returned := make(chan struct{})
			// Run ends before the budget is restored.
			t.Cleanup(func() { close(hung); <-returned })
			go func() {
				defer close(returned)
				run(t, "codex", nil, func(o *Options) {
					managedWindowsStandalone(o)
					o.Event = tc.event
					o.Stdin = strings.NewReader(`{"hook_event_name":"` + tc.event + `","tool_name":"shell","prompt":"echo ok"}`)
					o.FailMode = tc.failMode
					o.StartedAt = started
					o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
					o.FailureLogHome = resolve
					if !tc.prearm {
						o.Exit = exit
						return
					}
					watchdog := ArmAnswerWatchdog(Options{
						Connector: "codex", Event: tc.event, ManagedEnterprise: true,
						StartedAt: started, Exit: exit, Stdout: &strings.Builder{}, Stderr: &strings.Builder{},
						FailureLogHome: resolve,
					}, []byte(`{"hook_event_name":"`+tc.event+`"}`))
					if watchdog == nil {
						t.Error("the managed tool call armed no watchdog")
						return
					}
					o.AnswerWatchdog = watchdog
				})
			}()
			select {
			case row := <-rowAtExit:
				if strings.Count(row, "\n") != 1 || !strings.Contains(row, managedGatewayNoAnswerReason) {
					t.Fatalf("hook-failures.jsonl when the process ended = %q, want one %s row", row, managedGatewayNoAnswerReason)
				}
				if tc.event != "PreToolUse" && (!strings.Contains(row, `"fail_mode":"closed"`) ||
					!strings.Contains(row, `"outcome":"fail_closed"`)) {
					t.Fatalf("prompt/result watchdog row = %q, want fail_closed", row)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the watchdog did not answer")
			}
			if n := lookups.Load(); n != 1 {
				t.Fatalf("the call looked the account up %d times, want once", n)
			}
		})
	}
}

// G-small loop 4, finding 1: the hook command arms a managed tool call's
// watchdog before it resolves the runtime, and Run adopts it only later. A
// deadline that passes before Run begins (a stalled descriptor, sidecar or
// account read) is answered by the armed watchdog alone, and that answer
// still leaves the call exactly one hook-failures row, also when the account
// lookup outlasts the watchdog's log wait and whatever fail mode the command
// line names. A call the hook command ends itself before the deadline
// (Finish) gets no watchdog answer and no row.
func TestWatchdogArmedBeforeRunLogsItsAnswer(t *testing.T) {
	const budget = 600 * time.Millisecond
	for _, tc := range []struct {
		name     string
		lookup   time.Duration
		failMode string
		finish   bool
	}{
		{name: "fast account lookup"},
		{name: "account lookup slower than the log wait", lookup: 250 * time.Millisecond},
		{name: "fail mode open on the command line", failMode: "open"},
		{name: "ended by the hook command before the deadline", finish: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.lookup > 0 && tc.lookup <= answerWatchdogLogWait {
				t.Fatalf("the lookup (%s) must outlast the watchdog's log wait (%s)", tc.lookup, answerWatchdogLogWait)
			}
			shortAnswerBudget(t, budget)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			rows := filepath.Join(logHome, "logs", "hook-failures.jsonl")
			var lookups atomic.Int32
			type exited struct {
				code int
				row  string
			}
			done := make(chan exited, 1)
			stdout := &firstWriteRecorder{}
			watchdog := ArmAnswerWatchdog(Options{
				Connector: "codex", Event: "PreToolUse", FailMode: tc.failMode, ManagedEnterprise: true,
				StartedAt: time.Now(), Stdout: stdout, Stderr: &strings.Builder{},
				FailureLogHome: func() string {
					lookups.Add(1)
					time.Sleep(tc.lookup)
					return logHome
				},
				Exit: func(code int) {
					row, _ := os.ReadFile(rows)
					done <- exited{code: code, row: string(row)}
				},
			}, []byte(`{"hook_event_name":"PreToolUse"}`))
			if watchdog == nil {
				t.Fatal("the managed tool call armed no watchdog")
			}
			if tc.finish {
				if code := watchdog.Finish(0); code != 0 {
					t.Fatalf("Finish before the deadline returned %d, want the call's own 0", code)
				}
				select {
				case got := <-done:
					t.Fatalf("the watchdog answered (exit %d) a call the hook command had ended", got.code)
				case <-time.After(2 * budget):
				}
				if row, _ := os.ReadFile(rows); len(row) != 0 {
					t.Fatalf("a call ended before its deadline left a row: %q", row)
				}
				return
			}
			select {
			case got := <-done:
				out, _ := stdout.read()
				if !blocked(runResult{code: got.code, stdout: out}) {
					t.Fatalf("the armed watchdog answered exit %d stdout %q, want the managed closed answer", got.code, out)
				}
				if strings.Count(got.row, "\n") != 1 || !strings.Contains(got.row, managedGatewayNoAnswerReason) {
					t.Fatalf("hook-failures.jsonl when the process ended = %q, want one %s row", got.row, managedGatewayNoAnswerReason)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the armed watchdog did not answer before Run began")
			}
			if n := lookups.Load(); n != 1 {
				t.Fatalf("the call looked the account up %d times, want once", n)
			}
		})
	}
}

// G-small loop round 3: a call whose watchdog the hook command armed before
// Run can fail inside Run before Run adopts that watchdog (an invalid
// managed runtime, a missing or disabled home, an unknown account, a
// foreign hook, an oversized payload, a broken Codex binding). Its row uses
// the watchdog's one account lookup, which started when the watchdog was
// armed: a second lookup that stalls past the deadline left the watchdog
// waiting on a row that never came, and the call ended with no row at all.
func TestEarlyFailureOfAPrearmedCallReusesTheWatchdogLookup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Options)
	}{
		{"invalid managed runtime", func(o *Options) {
			o.ManagedRuntimeFailure = "enterprise_managed_runtime_untrusted"
		}},
		{"unregistered account", func(o *Options) {
			o.ManagedRuntimeFailure = managedSIDUnregisteredReason
		}},
		{"foreign hook blocked", func(o *Options) {
			o.ManagedRuntimeFailure = ForeignHookBlockedReasonPrefix + "codex"
		}},
		{"managed home missing", func(o *Options) {
			o.Home = filepath.Join(o.Home, "missing")
		}},
		{"managed home disabled", func(o *Options) {
			if err := os.WriteFile(filepath.Join(o.Home, ".disabled"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized payload", func(o *Options) {
			o.MaxBody = 8
		}},
		{"broken Codex binding", func(o *Options) {
			o.HookContractID = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const budget = 600 * time.Millisecond
			shortAnswerBudget(t, budget)
			shortAnswerFloor(t)
			logHome := t.TempDir()
			rows := filepath.Join(logHome, "logs", "hook-failures.jsonl")
			stall := make(chan struct{})
			var lookups atomic.Int32
			resolve := func() string {
				if lookups.Add(1) > 1 {
					<-stall
				}
				return logHome
			}
			exited := make(chan string, 1)
			stdout := &firstWriteRecorder{}
			started := time.Now()
			watchdog := ArmAnswerWatchdog(Options{
				Connector: "codex", Event: "PreToolUse", ManagedEnterprise: true,
				StartedAt: started, Stdout: stdout, Stderr: &strings.Builder{},
				FailureLogHome: resolve,
				Exit: func(int) {
					row, _ := os.ReadFile(rows)
					exited <- string(row)
				},
			}, []byte(`{"hook_event_name":"PreToolUse"}`))
			if watchdog == nil {
				t.Fatal("the managed tool call armed no watchdog")
			}
			// The armed watchdog's lookup is done before Run begins.
			<-watchdog.logHome.done
			returned := make(chan runResult, 1)
			// Run ends before the budget is restored.
			t.Cleanup(func() { close(stall); <-returned })
			go func() {
				returned <- run(t, "codex", ok(`{"action":"allow"}`), func(o *Options) {
					managedWindowsStandalone(o)
					o.StartedAt = started
					o.FailureLogHome = resolve
					o.AnswerWatchdog = watchdog
					o.Stdin = strings.NewReader(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
					tc.mutate(o)
				})
			}()
			var row string
			select {
			case result := <-returned:
				returned <- result
				out, _ := stdout.read()
				if !blocked(runResult{code: result.code, stdout: out}) {
					t.Fatalf("the early failure answered exit %d stdout %q, want the managed closed answer", result.code, out)
				}
				raw, _ := os.ReadFile(rows)
				row = string(raw)
			case row = <-exited:
				if row == "" {
					t.Fatalf("the watchdog ended the call with no hook-failures row (%d account lookups)", lookups.Load())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the call did not end")
			}
			if strings.Count(row, "\n") != 1 {
				t.Fatalf("hook-failures.jsonl = %q, want one row", row)
			}
			if n := lookups.Load(); n != 1 {
				t.Fatalf("the call looked the account up %d times, want once", n)
			}
		})
	}
}
