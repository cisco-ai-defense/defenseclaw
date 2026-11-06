// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookexec

import (
	"sync"
	"time"
)

// answerDeadlineWaiter waits for a tool call's answer deadline unless it is
// cancelled first. The deadline only moves later (extendTo, after the
// gateway reported that it waits on a remote scanner).
type answerDeadlineWaiter struct {
	once sync.Once
	done chan struct{}

	mu       sync.Mutex
	deadline time.Time
}

func newAnswerDeadlineWaiter() *answerDeadlineWaiter {
	return &answerDeadlineWaiter{done: make(chan struct{})}
}

func (w *answerDeadlineWaiter) cancel() { w.once.Do(func() { close(w.done) }) }

// extendTo moves the deadline to t when t is later.
func (w *answerDeadlineWaiter) extendTo(t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t.After(w.deadline) {
		w.deadline = t
	}
}

// passed reports a deadline that is set and has come.
func (w *answerDeadlineWaiter) passed() bool {
	deadline := w.current()
	return !deadline.IsZero() && !time.Now().Before(deadline)
}

func (w *answerDeadlineWaiter) current() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.deadline
}

// wait reports whether the deadline came before a cancel.
func (w *answerDeadlineWaiter) wait(deadline time.Time) bool {
	w.extendTo(deadline)
	for {
		timer := time.NewTimer(time.Until(w.current()))
		select {
		case <-w.done:
			timer.Stop()
			return false
		case <-timer.C:
		}
		select {
		case <-w.done:
			return false
		default:
		}
		if !time.Now().Before(w.current()) {
			return true
		}
	}
}
