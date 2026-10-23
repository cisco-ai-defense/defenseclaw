// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// attached is a second terminal's attach: its lease's release, or why it
// was refused.
type attached struct {
	release func()
	err     error
}

// attachSession attaches a second terminal's session to name as connect
// does: its lease, then the check, under the gate, that the sandbox still
// runs.
func attachSession(ta *testApp, name string) attached {
	s := &session{app: ta.App, api: ta.daemon.client(), sb: &sandboxapi.Sandbox{Name: name}}
	release, err := ta.holdSession(bg, name, s.stillRunning)
	return attached{release: release, err: err}
}

// attachAfterStopCount starts a second terminal's attach right after the
// next stop's or delete's count under the gate, and waits long enough for
// it to reach the gate before that stop goes on. The returned func waits
// for its outcome.
func attachAfterStopCount(t *testing.T, ta *testApp, name string) func() attached {
	t.Helper()
	prev := afterStopCount
	t.Cleanup(func() { afterStopCount = prev })
	done := make(chan attached, 1)
	var once sync.Once
	afterStopCount = func(string) {
		once.Do(func() {
			go func() { done <- attachSession(ta, name) }()
			time.Sleep(150 * time.Millisecond)
		})
	}
	return func() attached {
		select {
		case a := <-done:
			if a.release != nil {
				t.Cleanup(a.release)
			}
			return a
		case <-time.After(10 * time.Second):
			t.Fatal("the second terminal's attach never ended")
			return attached{}
		}
	}
}

// readyMount is a ready mounted sandbox the session started.
func readyMount(ta *testApp, name string, rm bool) *session {
	sb := sampleSandbox(name)
	ta.daemon.add(sb)
	return &session{app: ta.App, api: ta.daemon.client(), sb: &sb, started: true, rm: rm}
}

func shortGateWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := sandboxGateWait
	sandboxGateWait = d
	t.Cleanup(func() { sandboxGateWait = prev })
}

// A second terminal's attach racing the first's end: the end's count and
// its stop (or --rm delete) are one step under the sandbox's exclusive
// gate, and the attach records its lease and checks that the sandbox runs
// under the same gate, shared. Whatever the order, the sandbox is never
// stopped or deleted under an attached session: either the end sees the
// session and keeps the sandbox, or the attach comes after the stop and is
// refused with the way to start it again.
func TestSandboxGateAttachRacingAStop(t *testing.T) {
	for _, rm := range []bool{false, true} {
		end := map[bool]string{false: "stop", true: "rm"}[rm]
		t.Run(end+": attach right after the final count", func(t *testing.T) {
			ta := newTestApp(t, "")
			s := readyMount(ta, "box", rm)
			second := attachAfterStopCount(t, ta, "box")
			ta.ok(t, s.finish(bg, false))
			got := second()
			if got.err == nil {
				t.Fatalf("the second terminal attached to a sandbox the first then ended: stop %d, delete %d", ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"))
			}
			if rm {
				wantErr(t, got.err, "cannot confirm that box still runs", "defenseclaw sandbox status box")
				ta.wantCalls(t, 1, "DELETE", "box")
			} else {
				wantErr(t, got.err, "box is stopped now: it was stopped while this session attached", "start it again: defenseclaw sandbox connect box")
				ta.wantCalls(t, 1, "POST", "box/stop")
			}
			if n := countSessions(t, ta, "box"); n != 0 {
				t.Fatalf("a refused attach left %d leases", n)
			}
		})
		t.Run(end+": attach while the stop waits for the gate", func(t *testing.T) {
			ta := newTestApp(t, "")
			s := readyMount(ta, "box", rm)
			registering, proceed := make(chan struct{}), make(chan struct{})
			attachDone := make(chan attached, 1)
			go func() {
				release, err := ta.holdSession(bg, "box", func(context.Context) error {
					close(registering)
					<-proceed
					return nil
				})
				attachDone <- attached{release: release, err: err}
			}()
			<-registering
			finished := make(chan error, 1)
			go func() { finished <- s.finish(bg, false) }()
			select {
			case err := <-finished:
				t.Fatalf("the end crossed an attach that held the gate: %v", err)
			case <-time.After(150 * time.Millisecond):
			}
			close(proceed)
			a := <-attachDone
			if a.err != nil {
				t.Fatal(a.err)
			}
			defer a.release()
			ta.ok(t, <-finished)
			if stop, del := ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"); stop+del != 0 {
				t.Fatalf("stop %d, delete %d under the session that attached first", stop, del)
			}
			has(t, ta.output(), "1 other session is attached to it")
		})
		t.Run(end+": stop while an attach holds its lease", func(t *testing.T) {
			ta := newTestApp(t, "")
			s := readyMount(ta, "box", rm)
			a := attachSession(ta, "box")
			if a.err != nil {
				t.Fatal(a.err)
			}
			defer a.release()
			ta.ok(t, s.finish(bg, false))
			if stop, del := ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"); stop+del != 0 {
				t.Fatalf("stop %d, delete %d under an attached session", stop, del)
			}
			has(t, ta.output(), "1 other session is attached to it")
		})
	}
}

// A gate another command keeps past the bounded wait is not zero sessions:
// a session's end, `sandbox stop`, `sandbox delete` and a pull's stop again
// leave the sandbox as it is and say what to run; an attach is refused.
func TestSandboxGateWaitExpiryLeavesTheSandbox(t *testing.T) {
	const why = "another DefenseClaw command is attaching to, stopping or deleting it"
	ta := newTestApp(t, "y\ny\n", sampleSandbox("box"), copySandbox("copybox"))
	runAnswers(ta, "run=none\n", "")
	shortGateWait(t, 150*time.Millisecond)
	for _, name := range []string{"box", "copybox"} {
		release, err := ta.lockSandbox(bg, name, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(release)
	}
	s := &session{app: ta.App, api: ta.daemon.client(), sb: &sandboxapi.Sandbox{Name: "box"}, started: true}
	wantErr(t, s.finish(bg, false), "cannot confirm whether another session uses box", why, "defenseclaw sandbox status box")
	wantErr(t, ta.Stop(bg, StopOptions{Name: "box", Yes: true}), "cannot confirm whether another session uses box", why)
	wantErr(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}, Yes: true}), "cannot confirm whether another session uses box", why)
	if a := attachSession(ta, "box"); a.err == nil {
		a.release()
		t.Fatal("an attach got past a gate held for the whole wait")
	} else {
		wantErr(t, a.err, "cannot record the session with box", why)
	}
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	has(t, ta.output(), "copybox keeps running: cannot confirm whether another session uses copybox")
	if stop, del := ta.calls("POST", "box/stop")+ta.calls("POST", "copybox/stop"), ta.calls("DELETE", "box"); stop+del != 0 {
		t.Fatalf("stop %d, delete %d past an expired gate wait", stop, del)
	}
}

// A gateway restart or rollback holds the account's lifecycle lock
// exclusively: that is the exclusive lock of every sandbox of the account.
// A session's end waits for it before it counts and stops, and an attach
// waits before it records its lease.
func TestGatewayRollbackHoldsEverySandboxGate(t *testing.T) {
	ta := newTestApp(t, "")
	if err := os.MkdirAll(ta.LifecycleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	s := readyMount(ta, "box", false)
	readyMount(ta, "other", false)
	unlock, err := openshell.LockGatewayLifecycle(bg, ta.LifecycleDir)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	attachDone := make(chan attached, 1)
	go func() { finished <- s.finish(bg, false) }()
	go func() { attachDone <- attachSession(ta, "other") }()
	select {
	case err := <-finished:
		t.Fatalf("a session's end crossed the gateway rollback: %v", err)
	case a := <-attachDone:
		t.Fatalf("an attach crossed the gateway rollback: %v", a.err)
	case <-time.After(200 * time.Millisecond):
	}
	if ta.calls("POST", "box/stop") != 0 {
		t.Fatal("a stop during the gateway rollback")
	}
	unlock()
	ta.ok(t, <-finished)
	a := <-attachDone
	if a.err != nil {
		t.Fatal(a.err)
	}
	a.release()
	ta.wantCalls(t, 1, "POST", "box/stop")
}

// GAP-0455 (and the W4b2 review's "mounted session end can stop a
// connection made after its count"): a second terminal connects right
// after the first terminal's end counted no session, before its stop (or
// --rm delete). The stop no longer runs under the new session: the connect
// waits for the gate, then finds the sandbox stopped and says how to start
// it again.
func TestGAP0455MountedEndDoesNotStopAConnectAfterItsCount(t *testing.T) {
	for _, rm := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "rm"}[rm], func(t *testing.T) {
			ta := newTestApp(t, "u\n")
			second := attachAfterStopCount(t, ta, sbName)
			ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: rm}))
			got := second()
			ended := ta.calls("POST", sbName+"/stop") + ta.calls("DELETE", sbName)
			if got.err == nil && ended > 0 {
				t.Fatalf("the connect made after the end's count kept a session in a sandbox the end then ended: stop %d, delete %d",
					ta.calls("POST", sbName+"/stop"), ta.calls("DELETE", sbName))
			}
			if got.err != nil && ended == 0 {
				t.Fatalf("the connect was refused, yet the sandbox runs: %v", got.err)
			}
		})
	}
}

// GAP-0398: copy mode, terminal 2 connects right after terminal 1's
// finish counted no session (the copy's question was answered), before its
// stop or --rm delete: no stop or delete under terminal 2.
func TestGAP0398CopyFinishDoesNotEndAConnectAfterItsCount(t *testing.T) {
	for _, rm := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "rm"}[rm], func(t *testing.T) {
			ta := newTestApp(t, "a\n")
			second := attachAfterStopCount(t, ta, "fix-tests")
			ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Copy: true, Name: "fix-tests", Rm: rm}))
			got := second()
			ended := ta.calls("POST", "fix-tests/stop") + ta.calls("DELETE", "fix-tests")
			if got.err == nil && ended > 0 {
				t.Fatalf("terminal 2 attached to a copy sandbox terminal 1 then ended: stop %d, delete %d",
					ta.calls("POST", "fix-tests/stop"), ta.calls("DELETE", "fix-tests"))
			}
			if got.err != nil && ended == 0 {
				t.Fatalf("terminal 2 was refused, yet the sandbox runs: %v", got.err)
			}
		})
	}
}

// GAP-0466: a pull starts a stopped copy sandbox to read it, and another
// terminal connects while it reads. The pull's stop again, decided under
// the sandbox's exclusive gate, leaves it running for that session.
func TestGAP0466PullLeavesACopyRunningForANewSession(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	var release func()
	ta.copy.onPull = func() { release = holdTestSession(t, ta, "copybox") }
	t.Cleanup(func() {
		if release != nil {
			release()
		}
	})
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 0, "POST", "copybox/stop")
	has(t, ta.output(), "copybox keeps running: 1 terminal is attached to copybox", "stop it once it ends: defenseclaw sandbox stop copybox")
}

// The W4b2 review's "a vanished lease hides other live sessions", the
// other half: a count that holds no gate (status, a resume offer) made
// while an attach has created its lease file but not locked it yet would
// remove that lease as dead, and the session would be invisible to every
// later stop. The lease is locked before it takes its name, so the count
// does not see it, and it survives.
func TestLeaseNotYetLockedSurvivesAnUngatedCount(t *testing.T) {
	ta := newTestApp(t, "")
	prev := afterLeaseCreate
	t.Cleanup(func() { afterLeaseCreate = prev })
	during := -1
	afterLeaseCreate = func(name string) { during = countSessions(t, ta, name) }
	defer holdTestSession(t, ta, "box")()
	if during != 0 {
		t.Fatalf("an ungated count during the attach saw %d sessions", during)
	}
	if n := countSessions(t, ta, "box"); n != 1 {
		t.Fatalf("attached = %d after the attach, want 1: its lease was removed as dead", n)
	}
	dir, _ := ta.sessionsDir("box")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".new") {
			t.Fatalf("an unrenamed lease %s is left", e.Name())
		}
	}
}

// A `sandbox stop` the user confirmed with one session attached asks again
// when another attached while the question was open (the count under the
// gate), defaulting to no; so does `sandbox delete`.
func TestStopAndDeleteAskAgainForASessionThatAttachedSinceTheQuestion(t *testing.T) {
	for _, del := range []bool{false, true} {
		ta := newTestApp(t, "", sampleSandbox("box"))
		runAnswers(ta, "run=none\n", "")
		defer holdTestSession(t, ta, "box")()
		var second func()
		ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("y\nn\n"), attach: func() { second = holdTestSession(t, ta, "box") }}
		if del {
			ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}}))
			has(t, ta.output(), "2 terminals are attached to box (a harness session or `defenseclaw sandbox connect --shell`) now; deleting it ends them. Delete anyway? [y/N]", "box is kept")
		} else {
			ta.ok(t, ta.Stop(bg, StopOptions{Name: "box"}))
			has(t, ta.output(), "2 terminals are attached to box (a harness session or `defenseclaw sandbox connect --shell`) now; stopping the sandbox ends them. Stop anyway? [y/N]", "box keeps running")
		}
		second()
		if stop, d := ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"); stop+d != 0 {
			t.Fatalf("delete=%v: stop %d, delete %d under a session that attached after the question", del, stop, d)
		}
	}
}

// A setup whose gateway restart OpenShell's account of a raw sandbox
// refused names the stop (the refusal's) and then the setup to rerun.
func TestSetupNamesTheRetryAfterARefusedRestart(t *testing.T) {
	err := retryAfterStop(fmt.Errorf("%w; OpenShell has not reported these stopped: raw-box (ready): `openshell sandbox stop raw-box`", openshell.ErrUnflushed))
	wantErr(t, err, "`openshell sandbox stop raw-box`", "after stopping it, rerun `defenseclaw sandbox setup` with the same flags")
	if other := errors.New("other"); retryAfterStop(other) != other {
		t.Fatal("another error was reworded")
	}
}
