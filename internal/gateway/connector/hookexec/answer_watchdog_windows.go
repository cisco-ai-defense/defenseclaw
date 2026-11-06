// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// threadPriorityTimeCritical is THREAD_PRIORITY_TIME_CRITICAL.
const threadPriorityTimeCritical = 15

var procSetThreadPriority = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetThreadPriority")

// answerDeadlineWaiter waits for a tool call's answer deadline unless it is
// cancelled first. The wait runs on its own thread at the highest priority of
// the process and blocks in the kernel (an event with a timeout), so the
// Windows scheduler wakes it on time on a host whose CPU ordinary-priority
// work fills (an attestation repair, GAP-0155). The thread only writes the
// prepared answer and ends the process, so it cannot take the CPU from
// anything else. The deadline only moves later (extendTo, after the gateway
// reported that it waits on a remote scanner).
type answerDeadlineWaiter struct {
	once sync.Once
	done chan struct{}

	mu       sync.Mutex
	deadline time.Time
	event    windows.Handle // zero: the Go timer alone
	closed   bool
}

func newAnswerDeadlineWaiter() *answerDeadlineWaiter {
	w := &answerDeadlineWaiter{done: make(chan struct{})}
	if event, err := windows.CreateEvent(nil, 1, 0, nil); err == nil {
		w.event = event
	}
	return w
}

func (w *answerDeadlineWaiter) cancel() {
	w.once.Do(func() {
		close(w.done)
		w.mu.Lock()
		if w.event != 0 && !w.closed {
			_ = windows.SetEvent(w.event)
		}
		w.mu.Unlock()
	})
}

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
	// The thread ends with this goroutine; it is never handed back to the
	// scheduler at the raised priority.
	runtime.LockOSThread()
	_, _, _ = procSetThreadPriority.Call(uintptr(windows.CurrentThread()), uintptr(threadPriorityTimeCritical))
	w.extendTo(deadline)
	if w.event != 0 {
		w.waitEvent()
	}
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

// waitEvent blocks in the kernel until the (current) deadline or a cancel,
// then releases the event.
func (w *answerDeadlineWaiter) waitEvent() {
	defer func() {
		w.mu.Lock()
		w.closed = true
		_ = windows.CloseHandle(w.event)
		w.mu.Unlock()
	}()
	for {
		left := time.Until(w.current())
		if left <= 0 {
			return
		}
		millis := uint32(min(left, time.Hour)/time.Millisecond) + 1
		result, err := windows.WaitForSingleObject(w.event, millis)
		if err != nil || result != uint32(windows.WAIT_TIMEOUT) {
			return
		}
	}
}
