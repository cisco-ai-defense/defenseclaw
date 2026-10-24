// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type fakeWALCheckpointer struct {
	deadline time.Duration
	budget   time.Duration
	limit    int64
	result   audit.WALCheckpoint
	err      error
}

func (f *fakeWALCheckpointer) CheckpointWALIfLarge(ctx context.Context, limit int64, budget time.Duration) (audit.WALCheckpoint, error) {
	if deadline, ok := ctx.Deadline(); ok {
		f.deadline = time.Until(deadline)
	}
	f.limit, f.budget = limit, budget
	return f.result, f.err
}

// rel-1-0-2:GAP-0709: the guard ran the whole pass under the writer's 200 ms
// budget. SQLite keeps a checkpoint's progress only when it finishes, so the
// copy of a large log never finished and the log grew without bound. Only
// the writer phase may have the short budget.
func TestAuditWALGuardPassGivesTheCopyMoreThanTheWriterBudget(t *testing.T) {
	fake := &fakeWALCheckpointer{}
	var log bytes.Buffer
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if fake.deadline < auditWALCopyTimeout-time.Second {
		t.Fatalf("copy deadline = %s, want about %s", fake.deadline, auditWALCopyTimeout)
	}
	if fake.budget != auditWALWriterBudget || fake.limit != auditWALLimitBytes {
		t.Fatalf("writer budget %s, limit %d; want %s, %d", fake.budget, fake.limit, auditWALWriterBudget, int64(auditWALLimitBytes))
	}
	if log.Len() != 0 {
		t.Fatalf("a clean pass logged %q", log.String())
	}
}

func TestAuditWALGuardPassReportsAYieldedWriterPhase(t *testing.T) {
	fake := &fakeWALCheckpointer{err: fmt.Errorf("audit: WAL checkpoint yielded the writer after 200ms: %w", context.DeadlineExceeded)}
	var log bytes.Buffer
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if !strings.Contains(log.String(), "audit WAL checkpoint yielded") {
		t.Fatalf("log = %q", log.String())
	}
}

func TestAuditWALGuardPassReportsAWriterHoldOverTheBudget(t *testing.T) {
	fake := &fakeWALCheckpointer{result: audit.WALCheckpoint{Restarted: true, WriterHeld: auditWALWriterBudget / 2}}
	var log bytes.Buffer
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if log.Len() != 0 {
		t.Fatalf("a hold within the budget logged %q", log.String())
	}
	fake.result.WriterHeld = 3 * auditWALWriterBudget
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if !strings.Contains(log.String(), "audit WAL checkpoint held the audit writer for 600ms (budget 200ms)") {
		t.Fatalf("log = %q", log.String())
	}
}

// A bounded catch-up (a log over the limit) says why the hooks waited.
func TestAuditWALGuardPassReportsABoundedCatchUp(t *testing.T) {
	fake := &fakeWALCheckpointer{result: audit.WALCheckpoint{
		Bounded: true, Restarted: true, LogBytes: 300 << 20, WriterHeld: 480 * time.Millisecond, HoldCap: 4 * time.Second,
	}}
	var log bytes.Buffer
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if want := "audit WAL over its 256 MiB limit (300 MiB): held the audit writer for 480ms of up to 4s to bring it back (restarted true)"; !strings.Contains(log.String(), want) {
		t.Fatalf("log = %q, want %q", log.String(), want)
	}
}

// rel-1-0-3 GAP-0288: a writer statement that overran its budget returned a
// deadline error, and the guard logged only "yielded the writer after 200ms",
// so a 1.1-1.7 s hold never produced the held line. Both lines are logged,
// the held one with the real duration.
func TestAuditWALGuardPassReportsTheRealHoldOfAYieldedWriterPhase(t *testing.T) {
	fake := &fakeWALCheckpointer{
		err:    fmt.Errorf("audit: WAL checkpoint yielded the writer after 200ms: %w", context.DeadlineExceeded),
		result: audit.WALCheckpoint{WriterHeld: 1118 * time.Millisecond},
	}
	var log bytes.Buffer
	auditWALGuardPass(t.Context(), fake, &auditWALAlarm{}, time.Now(), &log)
	if !strings.Contains(log.String(), "audit WAL checkpoint yielded") ||
		!strings.Contains(log.String(), "audit WAL checkpoint held the audit writer for 1.118s (budget 200ms)") {
		t.Fatalf("log = %q", log.String())
	}
}

func TestAuditWALGuardPassIsQuietAfterShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	fake := &fakeWALCheckpointer{err: context.Canceled, result: audit.WALCheckpoint{FileBytes: 2 * auditWALAlarmBytes}}
	var log bytes.Buffer
	auditWALGuardPass(ctx, fake, &auditWALAlarm{}, time.Now(), &log)
	if log.Len() != 0 {
		t.Fatalf("shutdown pass logged %q", log.String())
	}
}

func TestAuditWALAlarmRaisesRepeatsAndClears(t *testing.T) {
	var alarm auditWALAlarm
	start := time.Now()
	if line := alarm.observe(start, auditWALLimitBytes); line != "" {
		t.Fatalf("under the bound: %q", line)
	}
	over := int64(auditWALAlarmBytes) + 1<<20
	if line := alarm.observe(start, over); !strings.Contains(line, "WARNING: the audit WAL file is 1025 MiB, over its 1024 MiB bound") {
		t.Fatalf("over the bound: %q", line)
	}
	if line := alarm.observe(start.Add(time.Minute), over); line != "" {
		t.Fatalf("repeated within %s: %q", auditWALAlarmRepeat, line)
	}
	if line := alarm.observe(start.Add(auditWALAlarmRepeat), over); !strings.Contains(line, "WARNING") {
		t.Fatalf("not repeated after %s: %q", auditWALAlarmRepeat, line)
	}
	if line := alarm.observe(start.Add(auditWALAlarmRepeat+time.Second), 0); !strings.Contains(line, "back under its 1024 MiB bound") {
		t.Fatalf("cleared: %q", line)
	}
	if line := alarm.observe(start.Add(auditWALAlarmRepeat+2*time.Second), 0); line != "" {
		t.Fatalf("cleared twice: %q", line)
	}
}
