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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// stopUndos counts the undo calls that restore and stop (not previews).
func (ta *testApp) stopUndos(name string) int {
	n := 0
	for _, b := range ta.bodies("POST", name+"/undo") {
		if strings.Contains(b, `"stop":true`) && !strings.Contains(b, `"preview":true`) {
			n++
		}
	}
	return n
}

// GAP-0541: a session end's undo stops the sandbox and puts the folder
// back. Terminal 2 connects while terminal 1's keep/undo question is open
// (terminal 1 counted no other session before it): terminal 1's undo is
// decided under the sandbox's exclusive gate, finds terminal 2 and keeps
// the sandbox and the changes, saying how to undo later.
func TestGAP0541SessionUndoKeepsASandboxAnotherSessionAttachedTo(t *testing.T) {
	ta := newTestApp(t, "")
	var other func()
	ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("u\n"), attach: func() { other = holdTestSession(t, ta, sbName) }}
	t.Cleanup(func() {
		if other != nil {
			other()
		}
	})
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	if other == nil {
		t.Fatal("no question was asked")
	}
	if n := ta.stopUndos(sbName); n != 0 {
		t.Fatalf("the undo stopped %s under the session that attached during its question (%d undo calls)", sbName, n)
	}
	has(t, ta.output(), "not undone: 1 other session is attached to it now", "undo once it ends: `defenseclaw sandbox undo "+sbName+"`")
}

// GAP-0542: `sandbox undo NAME` stops a running sandbox. It names the
// sessions attached to it in its question, and decides under the sandbox's
// exclusive gate: one that attached during the question is asked about
// again, with no lock held while that question is open, and a no keeps
// the sandbox and the folder as they are.
func TestGAP0542UndoAsksAboutTheSessionsItWouldEnd(t *testing.T) {
	t.Run("attached before the question", func(t *testing.T) {
		ta := newTestApp(t, "y\n")
		ta.daemon.add(sampleSandbox("box"))
		defer holdTestSession(t, ta, "box")()
		ta.ok(t, ta.Undo(bg, UndoOptions{Name: "box"}))
		has(t, ta.output(), "1 terminal is attached to box", "undo stops the sandbox, which ends it")
		if n := ta.stopUndos("box"); n != 1 {
			t.Fatalf("%d undo calls once the attached session was asked about, want 1", n)
		}
	})
	t.Run("attached during the question", func(t *testing.T) {
		ta := newTestApp(t, "")
		ta.daemon.add(sampleSandbox("box"))
		if err := os.MkdirAll(ta.LifecycleDir, 0o700); err != nil {
			t.Fatal(err)
		}
		shortGateWait(t, 300*time.Millisecond)
		var second func()
		ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("y\n\n"), attach: func() { second = holdTestSession(t, ta, "box") }}
		t.Cleanup(func() {
			if second != nil {
				second()
			}
		})
		var lifecycleErr, attachErr error
		ta.IO.Out = &probeAtQuestion{w: ta.out, text: "now; undo stops the sandbox", probe: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			unlock, err := openshell.LockGatewayLifecycle(ctx, ta.LifecycleDir)
			if lifecycleErr = err; err == nil {
				unlock()
			}
			release, err := ta.holdSession(bg, "box", nil)
			if attachErr = err; err == nil {
				release()
			}
		}}
		ta.ok(t, ta.Undo(bg, UndoOptions{Name: "box"}))
		if n := ta.stopUndos("box"); n != 0 {
			t.Fatalf("the undo stopped box under the session that attached during its question (%d undo calls)", n)
		}
		has(t, ta.output(), "1 terminal is attached to box (a harness session or `defenseclaw sandbox connect --shell`) now", "nothing changed")
		if lifecycleErr != nil || attachErr != nil {
			t.Fatalf("while the question is open the lifecycle lock (%v) and the gate (%v) must be free", lifecycleErr, attachErr)
		}
	})
}

// hookNow records a hook request of sandbox name now.
func (ta *testApp) hookNow(name string) {
	ta.daemon.mu.Lock()
	defer ta.daemon.mu.Unlock()
	ta.daemon.sandboxes[name].Hooks.LastHookAt = time.Now()
}

// stoppedMark is what the CLI recorded of name's copy as it stopped, nil
// when nothing was.
func stoppedMark(ta *testApp, name string) *stoppedCopy {
	rec, _ := ta.readCopyHandover(name)
	return rec.Stopped
}

// GAP-0543: terminal 1's copy session ends, pulls and waits at the apply
// question; terminal 2 connects, changes the copy and ends (or a hook
// request comes). Terminal 1 applies what it pulled and stops the sandbox,
// but does not record its copy as handed over: terminal 2's work is still
// in it, so a delete warns and the next pull reads it.
func TestGAP0543CopyEndDoesNotMarkACopyChangedSinceItsPull(t *testing.T) {
	for name, meanwhile := range map[string]func(ta *testApp){
		"nothing":                           func(*testApp) {},
		"a session attached and ended":      func(ta *testApp) { holdTestSession(t, ta, "fix-tests")() },
		"a hook request came":               func(ta *testApp) { ta.hookNow("fix-tests") },
		"a session attached and is ongoing": nil,
	} {
		t.Run(name, func(t *testing.T) {
			ta := newTestApp(t, "")
			var release func()
			attach := func() { meanwhile(ta) }
			if meanwhile == nil {
				attach = func() { release = holdTestSession(t, ta, "fix-tests") }
			}
			ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("a\n"), attach: attach}
			t.Cleanup(func() {
				if release != nil {
					release()
				}
			})
			ta.ok(t, ta.Run(bg, RunOptions{Harness: "codex", Copy: true, Name: "fix-tests"}))
			has(t, ta.output(), "Bring the changes back?")
			mark := stoppedMark(ta, "fix-tests")
			if name == "nothing" {
				if mark == nil || !mark.Clean {
					t.Fatalf("a copy nothing changed since its pull was not marked handed over: %+v\n%s", mark, ta.output())
				}
				return
			}
			if mark != nil {
				t.Fatalf("the copy was marked %+v though something may have changed it since the pull", mark)
			}
		})
	}
}

// The same for a pull that starts a stopped copy to read it: a session
// that attached and ended while it read leaves no lease for the stop again
// to count, and the copy is not marked.
func TestPullDoesNotMarkACopyASessionChangedWhileItRead(t *testing.T) {
	ta := newTestApp(t, "", copySandbox("copybox"))
	ta.copy.onPull = func() { holdTestSession(t, ta, "copybox")() }
	ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
	ta.wantCalls(t, 1, "POST", "copybox/stop")
	if mark := stoppedMark(ta, "copybox"); mark != nil {
		t.Fatalf("the copy was marked %+v though a session attached during the pull", mark)
	}
}

// And for `sandbox stop`: a session that attached and ended between its
// look at the copy and the stop leaves no lease for the stop's count, and
// the copy is not marked.
func TestStopDoesNotMarkACopyASessionChangedAfterTheLook(t *testing.T) {
	for _, attach := range []bool{false, true} {
		ta := newTestApp(t, "")
		sb := copySandbox("box")
		sb.Phase = "ready"
		ta.daemon.add(sb)
		ta.copy.pending = map[string]workspace.CopyWork{"box": workspace.CopyWorkNone}
		if attach {
			ta.copy.onPending = func() { holdTestSession(t, ta, "box")() }
		}
		ta.ok(t, ta.Stop(bg, StopOptions{Name: "box"}))
		ta.wantCalls(t, 1, "POST", "box/stop")
		if mark := stoppedMark(ta, "box"); (mark != nil) == attach {
			t.Fatalf("a session attached after the look %v: the copy was marked %+v", attach, mark)
		}
	}
}

// A managed refusal's create, deleted again under the sandbox's gate,
// leaves none of the CLI's state of it (the gate it took included).
func TestManagedRefusalLeavesNoCLIState(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Managed = &sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true}
	ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "sandbox", Fatal: true, Admin: true, Constraint: "openshell.admin.allowed_harnesses",
		Message: "claude is not an allowed harness"}}
	wantErr(t, ta.Run(bg, RunOptions{Harness: "claude"}), "claude is not an allowed harness")
	if !ta.deletedOne() {
		t.Fatal("the create was not deleted again")
	}
	if left, _ := filepath.Glob(filepath.Join(ta.dataDir(), "sandboxes", "*", "cli")); len(left) != 0 {
		t.Fatalf("CLI state left for a deleted sandbox: %v", left)
	}
}

// teardownApp is a test app whose teardown finds one sandbox, box, through
// the daemon (and no gateway).
func teardownApp(t *testing.T) *testApp {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	ta.OpenShell = func(context.Context) (openshell.Client, *openshell.Registration, error) {
		return nil, nil, errors.New("no gateway in this test")
	}
	ta.daemon.add(sampleSandbox("box"))
	return ta
}

// `sandbox teardown` deletes every sandbox, each under its exclusive gate
// with the sessions counted again under it: its question names the
// sessions attached as it was asked, and one that attached during it is
// asked about again with no lock held. A no keeps that sandbox, and the
// teardown stops there (removing its providers or restarting the gateway
// would end that session all the same), naming the command to finish.
func TestTeardownDeletesNoSandboxUnderASessionItDidNotAskAbout(t *testing.T) {
	t.Run("attached before the question", func(t *testing.T) {
		ta := teardownApp(t)
		ta.IO.In = strings.NewReader("y\n")
		defer holdTestSession(t, ta, "box")()
		ta.ok(t, ta.Teardown(bg, TeardownOptions{KeepImages: true}))
		has(t, ta.output(), "1 terminal is attached to box", "teardown deletes it, which ends it")
		ta.wantCalls(t, 1, "DELETE", "box")
	})
	t.Run("attached during the question", func(t *testing.T) {
		ta := teardownApp(t)
		if err := os.MkdirAll(ta.LifecycleDir, 0o700); err != nil {
			t.Fatal(err)
		}
		shortGateWait(t, 300*time.Millisecond)
		var second func()
		ta.IO.In = &attachAtCopyQuestion{read: strings.NewReader("y\n\n"), attach: func() { second = holdTestSession(t, ta, "box") }}
		t.Cleanup(func() {
			if second != nil {
				second()
			}
		})
		var lifecycleErr error
		ta.IO.Out = &probeAtQuestion{w: ta.out, text: "now; deleting it ends", probe: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			unlock, err := openshell.LockGatewayLifecycle(ctx, ta.LifecycleDir)
			if lifecycleErr = err; err == nil {
				unlock()
			}
		}}
		err := ta.Teardown(bg, TeardownOptions{KeepImages: true})
		ta.wantCalls(t, 0, "DELETE", "box")
		wantErr(t, err, "kept box")
		has(t, ta.output(), "1 terminal is attached to box (a harness session or `defenseclaw sandbox connect --shell`) now",
			"teardown stopped after the sandboxes: box is kept", "rerun: defenseclaw sandbox teardown")
		if lifecycleErr != nil {
			t.Fatalf("while the question is open the lifecycle lock must be free: %v", lifecycleErr)
		}
	})
}
