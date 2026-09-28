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

//go:build unix

package sandboxcli

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// probeInterrupter sends this process an interrupt while the sandbox's
// probe runs (before the harness), and waits for it to end the probe.
type probeInterrupter struct {
	*fakeStreamer
	sig syscall.Signal
}

func (s probeInterrupter) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if cmd := sandboxCommand(inv.Argv); len(cmd) != 1 || cmd[0] != "true" {
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

// Ctrl-C (or a hang-up, or a TERM) before the harness runs ends the run
// through its cleanup: the sandbox the launch created is deleted, and the
// run exits as interrupted. It used to kill the process with the sandbox
// left behind.
func TestRunInterruptedBeforeTheHarnessDeletesItsSandbox(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.Streamer = probeInterrupter{fakeStreamer: ta.stream, sig: sig}
			wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "claude"}), exitInterrupted)
			if n := len(ta.daemon.callsTo("DELETE", sbPath)); n != 1 {
				t.Fatalf("delete calls = %d; the interrupted launch's sandbox must go\n%s", n, ta.output())
			}
			if len(ta.term.runs) != 0 {
				t.Fatal("the harness ran after the interrupt")
			}
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
	wantExit(t, ta.Run(context.Background(), RunOptions{Harness: "claude", Copy: true, Name: "copybox", Rm: true}), exitInterrupted)
	out := ta.output()
	if !strings.Contains(out, "Bring the changes back?") || !strings.Contains(out, "changes are kept in the sandbox") {
		t.Fatalf("output:\n%s", out)
	}
	if n := len(ta.daemon.callsTo("POST", "/api/v1/sandbox/sandboxes/copybox/stop")); n != 1 {
		t.Fatalf("stop calls = %d; the session's sandbox must be stopped", n)
	}
	if n := len(ta.daemon.callsTo("DELETE", "/api/v1/sandbox/sandboxes/copybox")); n != 0 {
		t.Fatalf("delete calls = %d; the sandbox holds the unpulled changes", n)
	}
}

// While the attached harness owns the terminal, the interrupt signals are
// its own: a Ctrl-C the terminal sends the whole job leaves the command's
// context alone.
func TestForegroundTerminalHoldsTheInterrupts(t *testing.T) {
	ta := newTestApp(t, "")
	ctx, done := ta.interruptible(context.Background())
	defer done()
	inv := openshell.Invocation{Interactive: true, Argv: []string{"/bin/sh", "-c", "kill -INT $PPID; sleep 0.3; exit 3"}}
	code, err := ForegroundTerminal{}.Run(ctx, inv)
	if err != nil || code != 3 {
		t.Fatalf("Run = %d, %v; the harness must run to its end", code, err)
	}
	if ctx.Err() != nil || ta.intr.fired.Load() {
		t.Fatal("the harness's interrupt cancelled the command")
	}
	// Released, an interrupt is the command's again.
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
