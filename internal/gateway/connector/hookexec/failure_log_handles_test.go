// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// handleRecorder remembers every file the hook-failure log opener returned.
type handleRecorder struct {
	mu    sync.Mutex
	files []*os.File
}

func (r *handleRecorder) wrap(t *testing.T) {
	t.Helper()
	previous := openHookFailureLog
	openHookFailureLog = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		f, err := previous(name, flag, perm)
		if err == nil {
			r.mu.Lock()
			r.files = append(r.files, f)
			r.mu.Unlock()
		}
		return f, err
	}
	t.Cleanup(func() { openHookFailureLog = previous })
}

// open lists the recorded files that are still open.
func (r *handleRecorder) open() (opened int, stillOpen []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.files {
		if _, err := f.Stat(); err == nil {
			stillOpen = append(stillOpen, filepath.Base(f.Name()))
		}
	}
	return len(r.files), stillOpen
}

// waitClosed waits for every recorded file to be closed. A call closes the
// handles of its failure log when it ends, and a handle opened ahead of the
// answer deadline can be closed by the goroutine that opened it.
func (r *handleRecorder) waitClosed(t *testing.T) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		opened, stillOpen := r.open()
		if len(stillOpen) == 0 {
			return opened
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d hook-failure log handles are still open after the call ended: %v (Windows cannot remove the folder of an open file)", len(stillOpen), opened, stillOpen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// rel-1-0-6 GAP-1022: a call whose answer deadline passes opens its
// hook-failure log and the per-user marker ahead of the deadline, and the
// line of the deny takes one of the two. The other stayed open after the
// answer, and on Windows the account folder of a simulated exit could not be
// removed. Every handle the deadline path opened is closed when it is done.
func TestWatchdogDenyClosesEveryFailureLogHandleItOpened(t *testing.T) {
	const budget = 600 * time.Millisecond
	shortAnswerBudget(t, budget)
	shortAnswerFloor(t)
	var handles handleRecorder
	handles.wrap(t)

	hung := make(chan struct{})
	exited := make(chan int, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		run(t, "claudecode", nil, func(o *Options) {
			o.FailMode = "closed"
			o.StartedAt = time.Now()
			o.HTTPClient = &http.Client{Transport: ignoringContextRT{release: hung}}
			if err := os.MkdirAll(filepath.Join(o.Home, "logs"), 0o700); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(filepath.Join(o.Home, "logs", "hook-failures.jsonl"), nil, 0o600); err != nil {
				t.Error(err)
			}
			o.Exit = func(code int) { exited <- code }
		})
	}()
	t.Cleanup(func() { close(hung); <-returned })
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog did not answer a gateway that gave no answer")
	}
	if opened := handles.waitClosed(t); opened < 2 {
		t.Fatalf("the call opened %d hook-failure log files, want the log and the marker", opened)
	}
}

// A call answered in time closes the handles it opened ahead of the
// deadline, too.
func TestCallAnsweredInTimeClosesEveryFailureLogHandleItOpened(t *testing.T) {
	const budget = 1500 * time.Millisecond
	shortAnswerBudget(t, budget)
	previousLead := answerWatchdogLogPrepareLead
	answerWatchdogLogPrepareLead = budget
	t.Cleanup(func() { answerWatchdogLogPrepareLead = previousLead })
	var handles handleRecorder
	handles.wrap(t)
	result := run(t, "claudecode", ok(`{"action":"allow"}`), func(o *Options) {
		o.FailMode = "closed"
		o.StartedAt = time.Now()
		o.Exit = func(int) {}
		if err := os.MkdirAll(filepath.Join(o.Home, "logs"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(o.Home, "logs", "hook-failures.jsonl"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	})
	if claudeBlocked(result) {
		t.Fatalf("code %d stdout %q, want the gateway's allow", result.code, result.stdout)
	}
	handles.waitClosed(t)
}
