// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type lockedRetentionLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (log *lockedRetentionLog) Write(p []byte) (int, error) {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buf.Write(p)
}

func (log *lockedRetentionLog) String() string {
	log.mu.Lock()
	defer log.mu.Unlock()
	return log.buf.String()
}

// rel-1-0-6:GAP-0263: a failed run names its cause and the next try in the
// gateway log (the status keeps only the bounded label), and the first
// success after failures says so.
func TestRetentionControllerLogsTheCauseOfAFailedRunAndItsRecovery(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	scheduler := newScriptedRetentionScheduler()
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 16)}
	log := &lockedRetentionLog{}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler, Reporter: reporter, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{err: fmt.Errorf("wrapped: %w", errors.New("database is locked"))}
	failed := receiveRetentionTest(t, reporter.statuses)
	if failed.Failure != RetentionFailureRun {
		t.Fatalf("status: %#v", failed)
	}
	receiveRetentionTest(t, scheduler.waits)
	line := log.String()
	for _, want := range []string{"audit retention run failed (audit_store, 1 in a row)", "database is locked", "tries again in 1m0s"} {
		if !strings.Contains(line, want) {
			t.Fatalf("log %q lacks %q", line, want)
		}
	}
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, reporter.statuses)
	receiveRetentionTest(t, scheduler.waits)
	if !strings.Contains(log.String(), "audit retention ran again after 1 failed runs") {
		t.Fatalf("no recovery line: %q", log.String())
	}
	if err := controller.Stop(lifecycleTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionRetryIntervalDoublesUpToItsCap(t *testing.T) {
	for failed, want := range map[int64]time.Duration{
		1: time.Minute, 2: 2 * time.Minute, 3: 4 * time.Minute, 5: 16 * time.Minute, 6: RetentionRetryMax, 1000: RetentionRetryMax,
	} {
		if got := retryInterval(failed); got != want {
			t.Errorf("retryInterval(%d) = %s, want %s", failed, got, want)
		}
	}
}

// A Run failure keeps its cause behind the class for the log only.
func TestRetentionFailureDetailNamesTheCause(t *testing.T) {
	class, cause := audit.RetentionFailureDetail(errors.New("disk I/O error"))
	if class != audit.RetentionFailureAuditStore || cause != "disk I/O error" {
		t.Fatalf("detail = %q %q", class, cause)
	}
	if class, cause := audit.RetentionFailureDetail(nil); class != "" || cause != "" {
		t.Fatalf("nil detail = %q %q", class, cause)
	}
}
