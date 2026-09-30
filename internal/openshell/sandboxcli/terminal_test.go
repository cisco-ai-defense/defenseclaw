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
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// While the child owns the terminal, the terminal's signals do not end this
// process (the session's review and stop come after): an interrupt is the
// child's, and a hang-up or TERM goes to it; its own status comes back.
func TestForegroundTerminalSurvivesTerminalSignals(t *testing.T) {
	inv := openshell.Invocation{Argv: []string{"/bin/sh", "-c", "kill -INT $PPID; kill -TSTP $PPID; sleep 0.2; exit 5"}, Interactive: true}
	if code, err := (ForegroundTerminal{}).Run(bg, inv); err != nil || code != 5 {
		t.Fatalf("Run = %d, %v; want the child's exit status 5", code, err)
	}
	if _, err := (ForegroundTerminal{}).Run(bg, openshell.Invocation{Argv: []string{"true"}}); err == nil {
		t.Fatal("a non-interactive invocation was run on the terminal")
	}
	for _, sig := range []string{"HUP", "TERM"} {
		script := "trap 'kill $! 2>/dev/null; exit 7' " + sig + "; sleep 5 & kill -" + sig + " $PPID; wait; exit 9"
		inv := openshell.Invocation{Argv: []string{"/bin/sh", "-c", script}, Interactive: true}
		if code, err := (ForegroundTerminal{}).Run(bg, inv); err != nil || code != 7 {
			t.Fatalf("SIG%s: Run = %d, %v; want the child's trap status 7", sig, code, err)
		}
	}
}

// While the attached harness owns the terminal, the interrupt signals are
// its own: a Ctrl-C the terminal sends the whole job leaves the command's
// context alone. Released, an interrupt is the command's again.
func TestForegroundTerminalHoldsTheInterrupts(t *testing.T) {
	ta := newTestApp(t, "")
	ctx, done := ta.interruptible(bg)
	defer done()
	inv := openshell.Invocation{Interactive: true, Argv: []string{"/bin/sh", "-c", "kill -INT $PPID; sleep 0.3; exit 3"}}
	if code, err := (ForegroundTerminal{}).Run(ctx, inv); err != nil || code != 3 {
		t.Fatalf("Run = %d, %v; the harness must run to its end", code, err)
	}
	if ctx.Err() != nil || ta.intr.fired.Load() {
		t.Fatal("the harness's interrupt cancelled the command")
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("an interrupt after the harness did not cancel the command")
	}
	if !ta.intr.fired.Load() {
		t.Fatal("the interrupt was not recorded")
	}
}

// TestSessionContextEndsOnSignals: a headless run's context ends when the
// user interrupts or the terminal hangs up, and this process lives on.
func TestSessionContextEndsOnSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		run, interrupted, stop := sessionContext(bg)
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		select {
		case <-run.Done():
		case <-time.After(5 * time.Second):
			t.Fatalf("%v did not end the run", sig)
		}
		if !interrupted() {
			t.Fatalf("%v: interrupted() = false", sig)
		}
		stop()
	}
	run, interrupted, stop := sessionContext(bg)
	stop()
	if interrupted() || run.Err() == nil {
		t.Fatal("stop left the run going or reported a signal")
	}
}

// TestExecSessionShellLeavesKeystrokeSignalsToTheCommand pins that the
// session shell survives the Ctrl-C a terminal sends the whole foreground
// group, waits for its command and exits with the command's status: a
// command that handles SIGINT (a REPL) keeps its session.
func TestExecSessionShellLeavesKeystrokeSignalsToTheCommand(t *testing.T) {
	argv := execSessionArgv(strings.Repeat("c", 32), []string{"/bin/sh", "-c", `trap 'exit 5' INT; sleep 2 & wait; exit 0`})
	cmd := exec.Command(argv[0], argv[1:]...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	// SIGINT to the session shell alone: it must keep waiting.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := cmd.Wait()
	if time.Since(start) < time.Second {
		t.Fatalf("the session shell ended at SIGINT (%v) instead of waiting for its command", err)
	}
	if err != nil {
		t.Fatalf("the session shell's status = %v, want its command's 0", err)
	}
}

func TestCommandStreamerReportsExitStatus(t *testing.T) {
	var out bytes.Buffer
	code, err := CommandStreamer{}.Stream(bg, openshell.Invocation{Argv: []string{"/bin/sh", "-c", "echo hi; exit 4"}}, &out, &out)
	if err != nil || code != 4 || out.String() != "hi\n" {
		t.Fatalf("Stream = %d, %v, %q", code, err, out.String())
	}
	if _, err := (CommandStreamer{}).Stream(bg, openshell.Invocation{Argv: []string{"/nonexistent/bin"}}, &out, &out); err == nil {
		t.Fatal("a missing binary was not an error")
	}
}

// The terminal and the streamer run the OpenShell CLI with DefenseClaw's
// ssh shim first on its PATH: sandbox connect and the harness session
// attach through ForegroundTerminal, streamed execs through
// CommandStreamer. So the user's ssh connection sharing cannot attach the
// terminal to another sandbox.
func TestTerminalAndStreamerRunTheSSHShim(t *testing.T) {
	rec := openshelltest.NewSSHRecorder(t)
	cli := openshell.CLI{Binary: rec.OpenShell, Gateway: "openshell"}
	connect, err := cli.Connect("box")
	if err != nil {
		t.Fatal(err)
	}
	session, err := cli.Exec("box", []string{"claude"}, openshell.CLIExecOptions{TTY: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, inv := range []openshell.Invocation{connect, session} {
		if code, err := (ForegroundTerminal{}).Run(bg, inv); err != nil || code != 0 {
			t.Fatalf("Run(%q) = %d, %v", inv.Argv, code, err)
		}
	}
	streamed, err := cli.Exec("box", []string{"ls"}, openshell.CLIExecOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code, err := (CommandStreamer{}).Stream(bg, streamed, &out, &out); err != nil || code != 0 {
		t.Fatalf("Stream = %d, %v: %s", code, err, out.String())
	}
	calls := rec.ExpectShimmed(t, 3)
	if args := calls[0].Args; !slices.Contains(args, "connect") || args[len(args)-1] != "box" {
		t.Fatalf("connect ran ssh with %q", args)
	}
}

// signalingStreamer answers like fakeStreamer, but an invocation when
// matches sends this process sig and then runs until its context ends, as
// a command does until the interrupt reaches it.
type signalingStreamer struct {
	*fakeStreamer
	sig  syscall.Signal
	when func(argv []string) bool
}

func (s signalingStreamer) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if !s.when(inv.Argv) {
		return s.fakeStreamer.Stream(ctx, inv, stdout, stderr)
	}
	if err := syscall.Kill(os.Getpid(), s.sig); err != nil {
		return -1, err
	}
	select {
	case <-ctx.Done():
		return 128 + int(syscall.SIGKILL), nil
	case <-time.After(10 * time.Second):
		return 0, nil
	}
}

func isProbe(argv []string) bool {
	cmd := sandboxCommand(argv)
	return len(cmd) == 1 && cmd[0] == "true"
}

// Ctrl-C, a closed terminal or a TERM ends a run through its cleanup and
// exits as interrupted. Before the harness runs, the sandbox the launch
// created is deleted (the process used to die with the sandbox left
// behind); during a one-prompt run it ends the harness, and the session
// still reviews the changes, stops the sandbox and honours --rm.
func TestRunInterruptedEndsThroughItsCleanup(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String()+" before the harness", func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.Streamer = signalingStreamer{fakeStreamer: ta.stream, sig: sig, when: isProbe}
			wantExit(t, ta.Run(bg, RunOptions{Harness: "claude"}), exitInterrupted)
			if n := ta.calls("DELETE", sbName); n != 1 || len(ta.term.runs) != 0 {
				t.Fatalf("delete calls = %d, harness runs %d; the interrupted launch's sandbox must go\n%s", n, len(ta.term.runs), ta.output())
			}
		})
		t.Run(sig.String()+" during a headless session", func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			ta.Streamer = signalingStreamer{fakeStreamer: ta.stream, sig: sig, when: runsHarness}
			wantExit(t, ta.Run(bg, RunOptions{Harness: "claude", Prompt: "fix it", Rm: true}), exitInterrupted)
			has(t, strings.Join(ta.daemon.paths(), "\n"), "POST "+sbPath+"/stop", "POST "+sbPath+"/review", "DELETE "+sbPath)
			has(t, ta.err.String(), "interrupted: ending the session")
		})
	}
}

// interruptingReader sends this process an interrupt when a prompt first
// reads an answer, and then blocks like a terminal nobody types on.
type interruptingReader struct {
	once   sync.Once
	closed chan struct{}
}

func (r *interruptingReader) Read([]byte) (int, error) {
	r.once.Do(func() { _ = syscall.Kill(os.Getpid(), syscall.SIGINT) })
	<-r.closed
	return 0, io.EOF
}

// Ctrl-C at a copy-mode session's "Bring the changes back?" keeps the
// changes in the sandbox and still stops it (and does not delete it, --rm
// or not); the run exits as interrupted.
func TestCopySessionInterruptedAtThePromptStopsItsSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	in := &interruptingReader{closed: make(chan struct{})}
	defer close(in.closed)
	ta.IO.In = in
	wantExit(t, ta.Run(bg, RunOptions{Harness: "claude", Copy: true, Name: "copybox", Rm: true}), exitInterrupted)
	has(t, ta.output(), "Bring the changes back?", "changes are kept in the sandbox")
	if stops, deletes := ta.calls("POST", "copybox/stop"), ta.calls("DELETE", "copybox"); stops != 1 || deletes != 0 {
		t.Fatalf("stop calls = %d, delete calls = %d; the sandbox holds the unpulled changes", stops, deletes)
	}
}

// Two sessions can share a sandbox (a second `claude` in the folder resumes
// it): one session's end stops nothing, undoes nothing and deletes nothing
// (--rm) under the other's harness, whichever of them started it.
func TestSessionLeavesASandboxAnotherSessionIsAttachedTo(t *testing.T) {
	check := func(t *testing.T, ta *testApp, name string) {
		t.Helper()
		if stop, undo, del := ta.calls("POST", name+"/stop"), ta.calls("POST", name+"/undo"), ta.calls("DELETE", name); stop+undo+del != 0 {
			t.Errorf("stop %d, undo %d, delete %d calls under the other session", stop, undo, del)
		}
		has(t, ta.output(), name+" keeps running: 1 other session is attached to it, so what changes after this review is not in it",
			"1 other session is attached to it; review or undo once they end: `defenseclaw sandbox review "+name+"`",
			name+" is not deleted (--rm): 1 other session is attached to it",
			"Sandbox "+name+" keeps running: 1 other session is attached to it → stop it once they end: defenseclaw sandbox stop "+name)
		lacks(t, ta.output(), "Keep changes?")
	}
	t.Run("the session that started it", func(t *testing.T) {
		ta := newTestApp(t, "u\n")
		// The other session resumed the sandbox this run creates.
		defer ta.holdSession(sbName)()
		ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude", Rm: true}))
		check(t, ta, sbName)
	})
	t.Run("a session that resumed it", func(t *testing.T) {
		ta := newTestApp(t, "u\n")
		sb := sampleSandbox("m1-b")
		sb.Snapshot = &sandboxapi.SnapshotInfo{Kind: "git", CreatedAt: time.Now().Add(-time.Hour)}
		ta.daemon.add(sb)
		runAnswers(ta, "", "")
		defer ta.holdSession("m1-b")()
		ta.ok(t, ta.Connect(bg, ConnectOptions{Name: "m1-b", Rm: true}))
		check(t, ta, "m1-b")
	})
	t.Run("once the other session ended", func(t *testing.T) {
		ta := newTestApp(t, "y\n")
		ta.holdSession(sbName)()
		ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
		ta.wantCalls(t, 1, "POST", sbName+"/stop")
	})
	// The offer to resume a sandbox another session is attached to says so.
	ta := newTestApp(t, "y\ny\n")
	ta.daemon.add(folderSandbox(ta, "ready"))
	runAnswers(ta, "", "")
	defer ta.holdSession("proj-0a1b")()
	ta.ok(t, ta.Run(bg, RunOptions{Harness: "claude"}))
	has(t, ta.output(), "Sandbox proj-0a1b (ready, mount) already holds this folder, and 1 session is attached to it. Resume it? [Y/n]")
}

// A session's lease lasts while its process holds it: released, or left by
// a process that is gone, it no longer counts, and a count removes it.
func TestSessionLeases(t *testing.T) {
	ta := newTestApp(t, "")
	if n := ta.attachedSessions("box"); n != 0 {
		t.Fatalf("attached = %d before any session", n)
	}
	one, two := ta.holdSession("box"), ta.holdSession("box")
	if n := ta.attachedSessions("box"); n != 2 {
		t.Fatalf("attached = %d, want 2", n)
	}
	one()
	one()
	if n := ta.attachedSessions("box"); n != 1 {
		t.Fatalf("attached = %d after one release, want 1", n)
	}
	two()
	dir, err := ta.sessionsDir("box")
	if err != nil {
		t.Fatal(err)
	}
	// A lease file nobody holds (its process died).
	stale := filepath.Join(dir, "4242-0a0b0c0d0e0f"+leaseSuffix)
	writeFile(t, stale, "")
	if n := ta.attachedSessions("box"); n != 0 {
		t.Fatalf("attached = %d with only a stale lease", n)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("the stale lease is still there: %v", err)
	}
}

// TestForegroundTerminalRestoresTheTerminalMode: a harness that puts the
// terminal in raw mode and dies without undoing it (here SIGKILL) leaves it
// cooked again for the end-of-session prompts, which read lines ended by
// Enter and stop on Ctrl-C.
func TestForegroundTerminalRestoresTheTerminalMode(t *testing.T) {
	if _, err := exec.LookPath("stty"); err != nil {
		t.Skip("no stty")
	}
	_, slave := openPTY(t)
	cooked := func() bool {
		tio, err := unix.IoctlGetTermios(int(slave.Fd()), ioctlGetTermios)
		if err != nil {
			t.Fatal(err)
		}
		const want = unix.ICANON | unix.ECHO | unix.ISIG
		return tio.Lflag&want == want
	}
	if !cooked() {
		t.Fatal("a new pseudo-terminal is not in cooked mode")
	}
	// The child inherits this process's stdin (openshell.Invocation).
	stdin := os.Stdin
	os.Stdin = slave
	defer func() { os.Stdin = stdin }()
	inv := openshell.Invocation{Interactive: true, Argv: []string{"/bin/sh", "-c", "stty raw -echo && kill -KILL $$"}}
	code, err := ForegroundTerminal{}.Run(context.Background(), inv)
	if err != nil || code != 128+int(syscall.SIGKILL) {
		t.Fatalf("Run = %d, %v; want the child killed", code, err)
	}
	if !cooked() {
		t.Fatal("the terminal was left in the raw mode the killed child set")
	}
}
