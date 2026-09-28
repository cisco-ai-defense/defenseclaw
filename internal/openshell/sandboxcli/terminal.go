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

package sandboxcli

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"sync/atomic"

	"golang.org/x/term"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// ForegroundTerminal runs an interactive invocation as a child that
// inherits the terminal. While it runs, this process swallows the job
// control and interrupt signals the terminal sends to its foreground
// process group (Ctrl-C, Ctrl-Z, Ctrl-\): the child owns the terminal and
// decides what they mean, and the end-of-session review still runs after
// it exits. A hang-up (the terminal window closed) or a termination
// request is passed on to the child instead of ending this process, so
// the session still ends with its review and stop (or --rm). The signals
// are caught rather than ignored, so the child starts with the default
// dispositions.
type ForegroundTerminal struct{}

// Run implements Terminal.
func (ForegroundTerminal) Run(ctx context.Context, inv openshell.Invocation) (int, error) {
	if !inv.Interactive {
		return -1, errors.New("sandbox: the terminal runs interactive invocations only")
	}
	cmd, cancel, err := inv.Command(ctx)
	if err != nil {
		return -1, err
	}
	defer cancel()
	// The harness puts the terminal in raw mode. One that ends without
	// undoing it (the forwarded SIGTERM, a crash, SIGKILL) would leave the
	// end-of-session prompts reading raw input, where Enter sends no newline
	// and Ctrl-C no interrupt: the terminal gets back the mode it had.
	restore := saveTerminalMode(cmd.Stdin)
	defer restore()
	sig := make(chan os.Signal, 16)
	signal.Notify(sig, append(append([]os.Signal(nil), terminalSignals...), forwardedSignals...)...)
	defer signal.Stop(sig)
	if err := cmd.Start(); err != nil {
		return exitStatus(err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for s := range sig {
			if slices.Contains(forwardedSignals, s) {
				_ = cmd.Process.Signal(s)
			}
		}
	}()
	err = cmd.Wait()
	signal.Stop(sig)
	close(sig)
	<-drained
	return exitStatus(err)
}

// saveTerminalMode records the mode of in when it is a terminal, and
// returns what puts it back.
func saveTerminalMode(in io.Reader) (restore func()) {
	f, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return func() {}
	}
	fd := int(f.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(fd, state) }
}

// exitInterrupted is the exit status of a session a signal ended (a
// shell's 128 + SIGINT).
const exitInterrupted = 130

// sessionContext is ctx for a headless harness run, cancelled (which ends
// the harness) when the user interrupts, the terminal hangs up or this
// process is asked to terminate: the session then still ends with its
// review and stop (or --rm) instead of this process dying with the sandbox
// left running. interrupted reports whether a signal ended it.
func sessionContext(ctx context.Context) (run context.Context, interrupted func() bool, stop func()) {
	run, cancel := context.WithCancel(ctx)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, sessionSignals...)
	var got atomic.Bool
	done := make(chan struct{})
	go func() {
		select {
		case <-sig:
			got.Store(true)
			cancel()
		case <-done:
		}
	}()
	return run, got.Load, func() {
		signal.Stop(sig)
		close(done)
		cancel()
	}
}

// CommandStreamer runs a non-interactive invocation with its output on the
// given writers.
type CommandStreamer struct{}

// Stream implements Streamer.
func (CommandStreamer) Stream(ctx context.Context, inv openshell.Invocation, stdout, stderr io.Writer) (int, error) {
	if inv.Interactive {
		return -1, errors.New("sandbox: interactive invocations need the terminal")
	}
	cmd, cancel, err := inv.Command(ctx)
	if err != nil {
		return -1, err
	}
	defer cancel()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	return exitStatus(cmd.Run())
}

// exitStatus turns a finished command's error into its exit status; only
// failures to run at all are errors.
func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if code := exit.ExitCode(); code >= 0 {
			return code, nil
		}
		return 128 + signalNumber(exit), nil
	}
	return -1, err
}
