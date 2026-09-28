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
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestForegroundTerminalSurvivesTerminalSignals: while the child owns the
// terminal, the interrupt the terminal sends the whole foreground group
// must not end this process, and the child's own status comes back.
func TestForegroundTerminalSurvivesTerminalSignals(t *testing.T) {
	inv := openshell.Invocation{Argv: []string{"/bin/sh", "-c", "kill -INT $PPID; kill -TSTP $PPID; sleep 0.2; exit 5"}, Interactive: true}
	code, err := ForegroundTerminal{}.Run(context.Background(), inv)
	if err != nil || code != 5 {
		t.Fatalf("Run = %d, %v; want the child's exit status 5", code, err)
	}
	if _, err := (ForegroundTerminal{}).Run(context.Background(), openshell.Invocation{Argv: []string{"true"}}); err == nil {
		t.Fatal("a non-interactive invocation was run on the terminal")
	}
}

// TestForegroundTerminalPassesOnHangupAndTerm: a closed terminal window or
// a termination request goes to the child, which ends, instead of ending
// this process before the session's review and stop.
func TestForegroundTerminalPassesOnHangupAndTerm(t *testing.T) {
	for _, sig := range []string{"HUP", "TERM"} {
		script := "trap 'kill $! 2>/dev/null; exit 7' " + sig + "; sleep 5 & kill -" + sig + " $PPID; wait; exit 9"
		inv := openshell.Invocation{Argv: []string{"/bin/sh", "-c", script}, Interactive: true}
		code, err := ForegroundTerminal{}.Run(context.Background(), inv)
		if err != nil || code != 7 {
			t.Fatalf("SIG%s: Run = %d, %v; want the child's trap status 7", sig, code, err)
		}
	}
}

// TestSessionContextEndsOnSignals: a headless run's context ends when the
// user interrupts or the terminal hangs up, and this process lives on.
func TestSessionContextEndsOnSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		run, interrupted, stop := sessionContext(context.Background())
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
	run, interrupted, stop := sessionContext(context.Background())
	stop()
	if interrupted() || run.Err() == nil {
		t.Fatal("stop left the run going or reported a signal")
	}
}

// signalStreamer answers like fakeStreamer, but a harness run sends this
// process sig and then runs until its context ends, as the harness does
// until the interrupt reaches it.
type signalStreamer struct {
	*fakeStreamer
	sig syscall.Signal
}

func (s signalStreamer) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if !runsHarness(inv.Argv) {
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

// TestHeadlessSessionSurvivesInterrupt: Ctrl-C, a closed terminal or a
// TERM during a one-prompt run ends the harness, and the session still
// reviews the changes, stops the sandbox and honours --rm.
func TestHeadlessSessionSurvivesInterrupt(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.IO.TTY = false
			ta.Streamer = signalStreamer{fakeStreamer: ta.stream, sig: sig}
			err := ta.Run(context.Background(), RunOptions{Harness: "claude", Prompt: "fix it", Rm: true})
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != exitInterrupted {
				t.Fatalf("Run = %v, want exit status %d\n%s", err, exitInterrupted, ta.output())
			}
			paths := strings.Join(ta.daemon.paths(), "\n")
			for _, want := range []string{"POST /api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/stop", "POST /api/v1/sandbox/sandboxes/dc-claude-proj-1a2b/review",
				"DELETE /api/v1/sandbox/sandboxes/dc-claude-proj-1a2b"} {
				if !strings.Contains(paths, want) {
					t.Errorf("calls lack %s:\n%s", want, paths)
				}
			}
			if !strings.Contains(ta.err.String(), "interrupted: ending the session") {
				t.Errorf("stderr = %q", ta.err.String())
			}
		})
	}
}

func TestCommandStreamerReportsExitStatus(t *testing.T) {
	var out bytes.Buffer
	code, err := CommandStreamer{}.Stream(context.Background(), openshell.Invocation{Argv: []string{"/bin/sh", "-c", "echo hi; exit 4"}}, &out, &out)
	if err != nil || code != 4 || out.String() != "hi\n" {
		t.Fatalf("Stream = %d, %v, %q", code, err, out.String())
	}
	if _, err := (CommandStreamer{}).Stream(context.Background(), openshell.Invocation{Argv: []string{"/nonexistent/bin"}}, &out, &out); err == nil {
		t.Fatal("a missing binary was not an error")
	}
}
