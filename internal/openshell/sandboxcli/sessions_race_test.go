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
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func countSessions(t *testing.T, ta *testApp, name string) int {
	t.Helper()
	n, err := ta.attachedSessions(name)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// onNextLeaseOpen runs gone just before the next lease count opens its
// first lease file: after the count listed the leases, as when a third
// terminal ends between the listing and the open.
func onNextLeaseOpen(t *testing.T, gone func()) {
	t.Helper()
	open := openLease
	t.Cleanup(func() { openLease = open })
	var once sync.Once
	openLease = func(path string) (*os.File, error) {
		once.Do(gone)
		return open(path)
	}
}

// failLeaseOpens makes every lease open fail with err.
func failLeaseOpens(t *testing.T, err error) {
	t.Helper()
	open := openLease
	t.Cleanup(func() { openLease = open })
	openLease = func(path string) (*os.File, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
}

// W4b2 review, loop round 1: a lease gone between a count's listing and its
// open is a session that ended. The count still counts every live lease,
// where it returned zero and hid them.
func TestW4B2LeaseGoneDuringCountKeepsTheLiveOnes(t *testing.T) {
	t.Run("released by its session", func(t *testing.T) {
		ta := newTestApp(t, "")
		defer holdTestSession(t, ta, "box")()
		onNextLeaseOpen(t, holdTestSession(t, ta, "box"))
		if n := countSessions(t, ta, "box"); n != 1 {
			t.Fatalf("attached = %d, want the 1 live session", n)
		}
	})
	t.Run("removed as dead by another count", func(t *testing.T) {
		ta := newTestApp(t, "")
		defer holdTestSession(t, ta, "box")()
		dir, err := ta.sessionsDir("box")
		if err != nil {
			t.Fatal(err)
		}
		stale := filepath.Join(dir, "4242-0a0b0c0d0e0f"+leaseSuffix)
		writeFile(t, stale, "")
		onNextLeaseOpen(t, func() { _ = os.Remove(stale) })
		if n := countSessions(t, ta, "box"); n != 1 {
			t.Fatalf("attached = %d, want the 1 live session", n)
		}
	})
	t.Run("several gone", func(t *testing.T) {
		ta := newTestApp(t, "")
		defer holdTestSession(t, ta, "box")()
		a, b := holdTestSession(t, ta, "box"), holdTestSession(t, ta, "box")
		onNextLeaseOpen(t, func() { a(); b() })
		if n := countSessions(t, ta, "box"); n != 1 {
			t.Fatalf("attached = %d, want the 1 live session", n)
		}
	})
}

// Three terminals: the first ends the mounted sandbox it started while the
// second stays attached, and the third ends during the first's count. The
// sandbox keeps running (and with --rm is not deleted) under the second.
func TestW4B2ThirdTerminalEndingDoesNotStopTheSandboxUnderTheSecond(t *testing.T) {
	for _, rm := range []bool{false, true} {
		t.Run(map[bool]string{false: "stop", true: "rm"}[rm], func(t *testing.T) {
			ta := newTestApp(t, "u\n")
			defer holdTestSession(t, ta, sbName)()
			onNextLeaseOpen(t, holdTestSession(t, ta, sbName))
			ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: rm}))
			if stop, undo, del := ta.calls("POST", sbName+"/stop"), ta.calls("POST", sbName+"/undo"), ta.calls("DELETE", sbName); stop+undo+del != 0 {
				t.Fatalf("stop %d, undo %d, delete %d calls under the second terminal's session", stop, undo, del)
			}
			has(t, ta.output(), sbName+" keeps running: 1 other session is attached to it")
		})
	}
}

// An explicit stop or delete still names the attached session (and asks,
// defaulting to no) when another terminal ends during its count.
func TestW4B2StopAndDeleteNameTheSessionWhileAnotherEnds(t *testing.T) {
	ta := newTestApp(t, "n\nn\n", sampleSandbox("box"))
	runAnswers(ta, "run=none\n", "")
	defer holdTestSession(t, ta, "box")()
	onNextLeaseOpen(t, holdTestSession(t, ta, "box"))
	ta.ok(t, ta.Stop(bg, StopOptions{Name: "box"}))
	onNextLeaseOpen(t, holdTestSession(t, ta, "box"))
	ta.ok(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}}))
	if ta.calls("POST", "box/stop") != 0 || ta.calls("DELETE", "box") != 0 {
		t.Fatalf("stop %d, delete %d calls: the attached session was ended", ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"))
	}
	has(t, ta.output(), "1 terminal is attached to box (a harness session or `defenseclaw sandbox connect --shell`); stopping the sandbox ends it. Stop anyway? [y/N]",
		"1 terminal is attached to box (a harness session or `defenseclaw sandbox connect --shell`); deleting it ends it. Delete sandbox box")
}

// A count that fails for any other reason is not zero sessions: stop,
// delete (with or without --yes) and a session's end keep the sandbox and
// say how to look at it.
func TestW4B2UnreadableLeasesKeepTheSandbox(t *testing.T) {
	const why = "cannot confirm whether another session uses "
	causes := map[string]func(t *testing.T, ta *testApp, name string){
		"a lease that cannot be opened": func(t *testing.T, ta *testApp, name string) {
			t.Cleanup(holdTestSession(t, ta, name))
			failLeaseOpens(t, syscall.EIO)
		},
		"a sessions directory that cannot be read": func(t *testing.T, ta *testApp, name string) {
			dir, err := ta.sessionsDir(name)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, dir, "not a directory")
		},
	}
	for cause, setup := range causes {
		t.Run(cause, func(t *testing.T) {
			for _, yes := range []bool{false, true} {
				ta := newTestApp(t, "y\ny\n", sampleSandbox("box"))
				runAnswers(ta, "run=none\n", "")
				setup(t, ta, "box")
				wantErr(t, ta.Stop(bg, StopOptions{Name: "box", Yes: yes}), why+"box", "defenseclaw sandbox status box")
				wantErr(t, ta.Delete(bg, DeleteOptions{Names: []string{"box"}, Yes: yes}), why+"box", "defenseclaw sandbox status box")
				if stop, del := ta.calls("POST", "box/stop"), ta.calls("DELETE", "box"); stop+del != 0 {
					t.Fatalf("yes=%v: stop %d, delete %d calls without a session count", yes, stop, del)
				}
			}
			if cause == "a sessions directory that cannot be read" {
				// No lease can be taken there either: a session refuses to
				// attach before it starts (holdSession).
				return
			}
			for _, rm := range []bool{false, true} {
				ta := newTestApp(t, "u\n")
				setup(t, ta, sbName)
				wantErr(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: rm}), why+sbName)
				if stop, undo, del := ta.calls("POST", sbName+"/stop"), ta.calls("POST", sbName+"/undo"), ta.calls("DELETE", sbName); stop+undo+del != 0 {
					t.Fatalf("rm=%v: stop %d, undo %d, delete %d calls without a session count", rm, stop, undo, del)
				}
			}
		})
	}
}

// A pull that started a stopped copy stops it again and records the copy
// as it stopped; without a session count it leaves the sandbox running
// (GAP-0466: an uncertain count is not zero sessions) and records nothing.
func TestW4B2PullWithoutASessionCountKeepsTheCopyRunning(t *testing.T) {
	marked := func(t *testing.T, fail bool) bool {
		t.Helper()
		ta := newTestApp(t, "", copySandbox("copybox"))
		if fail {
			t.Cleanup(holdTestSession(t, ta, "copybox"))
			failLeaseOpens(t, syscall.EIO)
		}
		ta.ok(t, ta.Pull(bg, PullOptions{Name: "copybox", Branch: true}))
		if fail {
			has(t, ta.output(), "copybox keeps running: cannot confirm whether another session uses copybox")
			ta.wantCalls(t, 0, "POST", "copybox/stop")
		} else {
			has(t, ta.output(), "stopped copybox again")
		}
		sb := copySandbox("copybox")
		rec := ta.copyHandoverOf(&sb)
		return rec != nil && rec.Stopped != nil
	}
	if !marked(t, false) {
		t.Fatal("a pull with no session attached did not mark the copy (the test cannot see the mark)")
	}
	if marked(t, true) {
		t.Fatal("a pull whose session count failed marked the copy as it stopped")
	}
}
