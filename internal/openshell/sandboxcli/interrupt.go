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
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"
)

// Interrupts. `run` and `connect` stage, create, upload and probe before
// the harness runs, and ask at the session's end: a Ctrl-C, a hang-up or a
// termination request there must end the command through its cleanup (a
// launch that failed deletes its sandbox, a session stops the sandbox it
// started) rather than kill it half way. They run on a context those
// signals cancel (interruptible), and a prompt waiting for an answer then
// returns context.Canceled. A phase that hands the signals to its child
// (the attached terminal, a headless session) holds them (holdSignals):
// while it runs, only it receives them. A second signal after the first
// ends the process as it would without the handler.

// interrupts is the process's one interruptible context: signals are
// process-wide.
var interrupts struct {
	mu sync.Mutex
	// ch receives the signals for the interruptible context; nil when none
	// runs, or once it fired.
	ch    chan os.Signal
	holds int
}

// interruption is the interrupt state of one command.
type interruption struct {
	ctx   context.Context
	fired atomic.Bool
}

// interruptible returns ctx cancelled by the first interrupt, hang-up or
// termination signal that arrives while no phase holds them. done releases
// the signals. A nested call (a run that resumes with connect) shares the
// first one.
func (a *App) interruptible(ctx context.Context) (context.Context, func()) {
	interrupts.mu.Lock()
	if a.intr != nil || interrupts.ch != nil {
		interrupts.mu.Unlock()
		return ctx, func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	in := &interruption{ctx: ctx}
	// The grace after a harness quit is that command's own.
	harnessQuitAt.Store(0)
	ch := make(chan os.Signal, 1)
	interrupts.ch = ch
	if interrupts.holds == 0 {
		signal.Notify(ch, sessionSignals...)
	}
	interrupts.mu.Unlock()
	a.intr = in
	stopped := make(chan struct{})
	forget := func() {
		interrupts.mu.Lock()
		if interrupts.ch == ch {
			signal.Stop(ch)
			interrupts.ch = nil
		}
		interrupts.mu.Unlock()
	}
	go func() {
		for {
			select {
			case <-ch:
				if harnessJustQuit() {
					continue
				}
				in.fired.Store(true)
				cancel()
				forget()
			case <-stopped:
			}
			return
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			forget()
			close(stopped)
			cancel()
			a.intr = nil
		})
	}
}

// harnessQuitGrace is how long after an attached harness exits a Ctrl-C is
// taken for the rest of the keys that quit it, not for an interrupt of the
// command: Codex quits on Ctrl-C twice, and a second press that lands after
// it restored the terminal reached this process, so a session that ended
// as documented closed with "✗ interrupted" (GAP-0321).
const harnessQuitGrace = 2 * time.Second

// harnessQuitAt is when the last attached harness exited (UnixNano).
var harnessQuitAt atomic.Int64

// noteHarnessQuit records that an attached harness just exited.
func noteHarnessQuit() { harnessQuitAt.Store(time.Now().UnixNano()) }

// harnessJustQuit reports a signal within harnessQuitGrace of an attached
// harness's exit.
func harnessJustQuit() bool {
	at := harnessQuitAt.Load()
	return at != 0 && time.Since(time.Unix(0, at)) < harnessQuitGrace
}

// interruptedExit is the result of a command a signal interrupted: its
// cleanup ran, and whatever its cancelled steps returned, it exits as
// interrupted (130).
func (a *App) interruptedExit(err error) error {
	if a.intr == nil || !a.intr.fired.Load() {
		return err
	}
	return &ExitError{Code: exitInterrupted, Err: errors.New("interrupted")}
}

// holdSignals hands the interrupt signals to the calling phase until
// release: the interruptible context ignores them meanwhile. The phase
// must already receive them (signal.Notify) when it calls holdSignals, and
// still receive them when it calls release, or a signal in between would
// end the process.
func holdSignals() (release func()) {
	interrupts.mu.Lock()
	interrupts.holds++
	if interrupts.holds == 1 && interrupts.ch != nil {
		signal.Stop(interrupts.ch)
	}
	interrupts.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			interrupts.mu.Lock()
			interrupts.holds--
			if interrupts.holds == 0 && interrupts.ch != nil {
				signal.Notify(interrupts.ch, sessionSignals...)
			}
			interrupts.mu.Unlock()
		})
	}
}
