// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// answerWatchdogLogPrepareLead is how long before its answer deadline a tool
// call that is still waiting opens its hook-failure log
// (preparedFailureLog). The watchdog that answers at the deadline then only
// appends its line to the open file inside answerWatchdogLogWait. Before,
// it looked up the folder and opened the file shared by every hook of the
// account after its answer, and on a saturated host (par 128 on 16 vCPU)
// that took longer than the wait: the process ended and the denied call had
// no record (rel-1-0-6 GAP-0407). A call answered before the lead opens
// nothing.
var answerWatchdogLogPrepareLead = time.Second

// openHookFailureLog opens the hook-failure log; tests replace it to stall
// the open.
var openHookFailureLog = os.OpenFile

// preparedFailureLog is the hook-failure log of one tool call, opened ahead
// of its answer deadline. Every copy of the call's Options shares it
// (Options.failureLog), and the first failure line of the call takes it.
type preparedFailureLog struct {
	once sync.Once
	done chan struct{}

	mu     sync.Mutex
	home   string
	file   *os.File
	taken  bool
	closed bool
}

func newPreparedFailureLog() *preparedFailureLog {
	return &preparedFailureLog{done: make(chan struct{})}
}

// prepare opens home/logs/hook-failures.jsonl for appending, once, in the
// background. It never creates the folder or the file: a log that does not
// exist yet is opened the usual way when a line is written (logHookFailure).
func (p *preparedFailureLog) prepare(home func() string) {
	if p == nil || home == nil {
		return
	}
	p.once.Do(func() {
		go func() {
			defer close(p.done)
			h := home()
			if h == "" {
				return
			}
			f, err := openHookFailureLog(filepath.Join(h, "logs", "hook-failures.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				return
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			if p.closed {
				_ = f.Close()
				return
			}
			p.home, p.file = h, f
		}()
	})
}

// take hands the open log of home to the first failure line of the call, and
// nil when it was not opened, is for another home, was taken or closed. An
// open still in progress is waited for: it is the open the line would make.
func (p *preparedFailureLog) take(home string) *os.File {
	if p == nil || home == "" {
		return nil
	}
	// Not started yet: nothing to wait for, and no later prepare.
	p.once.Do(func() { close(p.done) })
	<-p.done
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.taken || p.closed || p.file == nil || p.home != home {
		return nil
	}
	p.taken = true
	return p.file
}

// close closes the log unless a failure line took it.
func (p *preparedFailureLog) close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	if !p.taken && p.file != nil {
		_ = p.file.Close()
	}
}

// failureLogHomeOf is the directory the failure lines of the call go to: the
// invoking user's diagnostic directory of a managed call (FailureLogHome,
// the one lookup of the watchdog), the per-user home otherwise.
func failureLogHomeOf(opts Options) func() string {
	if opts.ManagedEnterprise {
		return opts.FailureLogHome
	}
	home := opts.Home
	if home == "" {
		return nil
	}
	return func() string { return home }
}
