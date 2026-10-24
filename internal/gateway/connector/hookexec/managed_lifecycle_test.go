// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubManagedLifecycle replaces this computer's lifecycle marker read for
// one test.
func stubManagedLifecycle(t *testing.T, held func() bool) {
	t.Helper()
	previous := managedLifecycleHeld
	managedLifecycleHeld = func(Options) bool { return held() }
	t.Cleanup(func() { managedLifecycleHeld = previous })
}

// managedOutages are the gateway failures a managed hook meets, each as the
// hook answers it. idleRuns: the administrator's open lets the call through
// while no lifecycle runs (ManagedOutageFailsOpen): a proven stopped
// service, and a tool call that a verified gateway took and did not answer
// in time. A restart, and a missing answer of a call no verified gateway
// took, stay closed (the managed standalone outage guard, TGT-0040).
var managedOutages = []struct {
	name     string
	idleRuns bool
	answer   func(opts Options, sp spec) int
}{
	{"service stopped", true, func(opts Options, sp spec) int {
		err := fmt.Errorf("%w: %w (state=1 pid=0)", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
		return failUnreachable(withManagedOutage(opts, err), sp, managedPeerFailMode(opts, opts.FailMode, err), managedPeerFailureReason(opts, err))
	}},
	{"service started, nothing listens yet", true, func(opts Options, sp spec) int {
		err := fmt.Errorf("%w: %w: nothing listens on 127.0.0.1:18970 yet", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
		return failUnreachable(withManagedOutage(opts, err), sp, managedPeerFailMode(opts, opts.FailMode, err), managedPeerFailureReason(opts, err))
	}},
	{"still restarting after the restart wait", false, func(opts Options, sp spec) int {
		return failUnreachable(withManagedOutage(opts, errGatewayRestarting), sp, opts.FailMode, managedGatewayRestartingReason)
	}},
	{"no answer in time", true, func(opts Options, sp spec) int {
		opts.gatewayTookCall = true
		return failNoAnswer(opts, sp, opts.FailMode)
	}},
	{"no answer, no verified gateway took the call", false, func(opts Options, sp spec) int {
		return failNoAnswer(opts, sp, opts.FailMode)
	}},
}

func managedOutageOptions(t *testing.T, form nativeHookForm, failMode string, stdout, stderr *bytes.Buffer) Options {
	t.Helper()
	return withDefaults(Options{
		Connector:         form.connector,
		Event:             form.event,
		HookSurface:       form.surface,
		ManagedEnterprise: true,
		ManagedStandalone: true,
		FailMode:          failMode,
		Home:              t.TempDir(),
		Stdin:             strings.NewReader(""),
		Stdout:            stdout,
		Stderr:            stderr,
	})
}

// GAP-1074, GAP-1075, GAP-0993: an administrator's open on a managed
// standalone host covers a gateway outage, but a call met the gateway that
// the lifecycle had stopped or was restarting (an upgrade, a repair, a
// configuration change), or that it had started but not yet proven ready,
// and was allowed. While the lifecycle runs (managedLifecycleActive: its run
// marker on Linux and macOS, a gateway service that is not automatic on
// Windows) every managed tool hook form answers every outage as fail mode
// closed does. When it does not, the administrator's open still applies
// (control), and a Secure Client or per-user hook never reads the marker.
func TestManagedHookAnswersClosedWhileTheLifecycleRuns(t *testing.T) {
	var held atomic.Bool
	stubManagedLifecycle(t, held.Load)
	for _, form := range nativeToolHookForms {
		sp, ok := specFor(form.connector)
		if !ok {
			t.Fatalf("no spec for %s", form.connector)
		}
		for _, outage := range managedOutages {
			t.Run(form.String()+"/"+outage.name, func(t *testing.T) {
				answer := func(failMode string) (bool, string) {
					var stdout, stderr bytes.Buffer
					code := outage.answer(managedOutageOptions(t, form, failMode, &stdout, &stderr), sp)
					return nativeAnswerBlocks(code, stdout.String()), fmt.Sprintf("exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
				}
				held.Store(false)
				if blocks, got := answer("open"); blocks == outage.idleRuns {
					t.Fatalf("lifecycle idle, administrator open: %s, blocks=%v, want %v (control)", got, blocks, !outage.idleRuns)
				}
				held.Store(true)
				if blocks, got := answer("open"); !blocks {
					t.Fatalf("lifecycle running, administrator open: %s, want the closed answer", got)
				}
				if blocks, got := answer("closed"); !blocks {
					t.Fatalf("lifecycle running, administrator closed: %s, want the closed answer", got)
				}
			})
		}
	}
	held.Store(true)
	outage := fmt.Errorf("%w: %w", errManagedGatewayPeerUnverified, errManagedGatewayNotRunning)
	if ManagedOutageFailsOpen(Options{ManagedEnterprise: true, FailMode: "open"}, outage) {
		t.Fatal("a lifecycle transition counts as an outage")
	}
	held.Store(false)
	if !ManagedOutageFailsOpen(Options{ManagedEnterprise: true, FailMode: "open"}, outage) {
		t.Fatal("an outage outside a lifecycle run does not count (control)")
	}
	held.Store(true)
	for _, opts := range []Options{
		{ManagedEnterprise: true, SecureClient: true, FailMode: "open"},
		{FailMode: "open", Home: t.TempDir()},
	} {
		if managedLifecycleActive(opts) {
			t.Fatalf("%+v reads the managed lifecycle marker", opts)
		}
		if got := closeDuringInstall(&opts, "open"); got != "open" {
			t.Fatalf("%+v: closeDuringInstall = %q, want open", opts, got)
		}
	}
}

// A call whose gateway has not answered when the lifecycle starts is closed
// too: the answer watchdog Run adopted with the administrator's open looks
// at the lifecycle again at its deadline (GAP-1074), as it looks at a
// per-user install lock (GAP-0862). A look that does not end in time counts
// as held.
func TestAdoptedManagedAnswerWatchdogAnswersClosedWhenTheLifecycleStartsMidCall(t *testing.T) {
	const budget = 200 * time.Millisecond
	shortAnswerBudget(t, budget)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cases := []struct {
		name   string
		blocks bool
		took   bool
		held   func() bool
	}{
		// The administrator's open covers a gateway that took the call and
		// did not answer it (loop round 3), never one no verified gateway
		// took, and never a lifecycle run.
		{"lifecycle idle, the gateway took the call (control)", false, true, func() bool { return false }},
		{"lifecycle idle, no verified gateway took the call", true, false, func() bool { return false }},
		{"lifecycle starts mid-call", true, true, func() bool { return true }},
		{"lifecycle look stalls", true, true, func() bool { <-release; return false }},
	}
	for _, form := range nativeToolHookForms {
		sp, ok := specFor(form.connector)
		if !ok {
			t.Fatalf("no spec for %s", form.connector)
		}
		for _, tc := range cases {
			t.Run(form.String()+"/"+tc.name, func(t *testing.T) {
				var running atomic.Bool
				stubManagedLifecycle(t, func() bool {
					if !running.Load() {
						return false
					}
					return tc.held()
				})
				stdout, stderr := &firstWriteRecorder{}, &firstWriteRecorder{}
				exited := make(chan int, 1)
				started := time.Now()
				opts := Options{
					Connector:         form.connector,
					Event:             form.event,
					HookSurface:       form.surface,
					ManagedEnterprise: true,
					ManagedStandalone: true,
					FailMode:          "open",
					StartedAt:         started,
					Stdout:            stdout,
					Stderr:            stderr,
					Exit:              func(code int) { exited <- code },
				}
				watchdog := ArmAnswerWatchdog(opts, []byte(`{"tool_name":"Bash","tool_input":{"command":"echo ok"}}`))
				if watchdog == nil {
					t.Fatalf("no watchdog for %s", form)
				}
				// Run adopts it with the administrator's open, before the
				// lifecycle starts.
				adopted := withDefaults(opts)
				adopted.Event = resolveHookEvent(adopted.Event, nil)
				watchdog.hold(&adopted)
				watchdog.adopt(&adopted, sp, "open")
				if tc.took {
					watchdog.markGatewayTookCall()
				}
				running.Store(true)
				var code int
				select {
				case code = <-exited:
				case <-time.After(5 * time.Second):
					t.Fatal("no answer at the deadline")
				}
				out, _ := stdout.read()
				errOut, _ := stderr.read()
				if got := nativeAnswerBlocks(code, out); got != tc.blocks {
					t.Fatalf("%s: exit %d stdout %q stderr %q blocks=%v, want blocks=%v", form, code, out, errOut, got, tc.blocks)
				}
			})
		}
	}
}
