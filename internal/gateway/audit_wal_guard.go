// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	// auditWALGuardInterval is how often the audit write-ahead log's active
	// frame count is checked on its dedicated checkpoint connection.
	auditWALGuardInterval = 2 * time.Second
	// auditWALLimitBytes is the published on-disk flood ceiling. The
	// registered T9 flood grew the WAL by up to about 18 MiB/s at 10 hooks/s.
	auditWALLimitBytes = audit.WALHardLimitBytes
	// Start the bounded catch-up with room for two guard ticks at 10 hooks/s.
	// A catch-up first requested at the ceiling can arrive one or more ticks
	// late and leave the on-disk WAL above it (GAP-0952).
	auditWALGuardHeadroomBytes = 80 << 20
	auditWALGuardTriggerBytes  = auditWALLimitBytes - auditWALGuardHeadroomBytes
	// auditWALWriterBudget bounds the ordinary writer hold. Once the WAL
	// reaches the published ceiling, the guard uses a fixed emergency hold
	// to restart a log whose final copy needs more time. Hook audit writes
	// can see that occasional latency spike.
	auditWALWriterBudget = 200 * time.Millisecond
	// auditWALCopyTimeout bounds the copy on the dedicated checkpoint
	// connection, which does not hold off the writer. SQLite keeps a
	// checkpoint's progress only when it finishes, so this must be long enough
	// to copy a log many times the limit: under the writer's 200 ms budget the
	// copy never finished once the log was large, and the log grew without
	// bound (rel-1-0-2:GAP-0709).
	auditWALCopyTimeout = 2 * time.Minute
	// Warn as soon as the published flood ceiling is crossed. A failed
	// checkpoint must not remain silent while the WAL consumes the volume.
	auditWALAlarmBytes = auditWALLimitBytes
	// auditWALAlarmRepeat is how often a WAL that stays over the bound is
	// reported again.
	auditWALAlarmRepeat = 10 * time.Minute
)

// auditWALCheckpointer is the part of *audit.Store the WAL guard uses.
type auditWALCheckpointer interface {
	CheckpointWALIfLarge(ctx context.Context, limitBytes int64, writerBudget time.Duration) (audit.WALCheckpoint, error)
}

// runAuditWALGuard checkpoints the audit database's write-ahead log and
// alarms if a flood outpaces the checkpoint (see audit.Store.CheckpointWALIfLarge).
func (s *Sidecar) runAuditWALGuard(ctx context.Context) {
	if s == nil || s.store == nil || s.currentConfig().SecureClientIntegration() {
		return
	}
	ticker := time.NewTicker(auditWALGuardInterval)
	defer ticker.Stop()
	var alarm auditWALAlarm
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		// A signed bundle's config rename starts this gate before its
		// generation rebuild. Defer maintenance until that swap has settled.
		if !configReloadInFlight.wait(0) {
			continue
		}
		auditWALGuardPass(ctx, s.store, &alarm, time.Now(), os.Stderr)
	}
}

// auditWALGuardPass runs one checkpoint pass and reports its outcome.
func auditWALGuardPass(ctx context.Context, store auditWALCheckpointer, alarm *auditWALAlarm, now time.Time, log io.Writer) {
	copyCtx, cancel := context.WithTimeout(ctx, auditWALCopyTimeout)
	pass, err := store.CheckpointWALIfLarge(copyCtx, auditWALGuardTriggerBytes, auditWALWriterBudget)
	cancel()
	if ctx.Err() != nil {
		return
	}
	// A pass that yields is retried at the next tick; the dedicated
	// connection's copy is kept.
	if errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(log, "[sidecar] audit WAL checkpoint yielded: %v\n", err)
	} else if err != nil {
		fmt.Fprintf(log, "[sidecar] audit WAL checkpoint failed: %v\n", err)
	}
	// Whether or not the pass then yielded: a statement on the writer is not
	// interrupted while SQLite syncs or truncates a file, so its real hold can
	// be longer than the budget. Hooks waited this long for their audit
	// records (rel-1-0-3 GAP-0288).
	switch {
	case pass.Bounded && pass.WriterHeld > 0:
		// A flood on a slow disk: hooks waited so the log can restart.
		// Name the published ceiling accurately when catch-up began below it.
		if pass.LogBytes > auditWALLimitBytes {
			fmt.Fprintf(log, "[sidecar] audit WAL over its %d MiB limit (%d MiB): held the audit writer for %s of up to %s to bring it back (restarted %t)\n",
				int64(auditWALLimitBytes)>>20, pass.LogBytes>>20, pass.WriterHeld.Round(time.Millisecond), pass.HoldCap, pass.Restarted)
		} else {
			fmt.Fprintf(log, "[sidecar] audit WAL nearing its %d MiB ceiling (%d MiB): held the audit writer for %s of up to %s to bring it back (restarted %t)\n",
				int64(auditWALLimitBytes)>>20, pass.LogBytes>>20, pass.WriterHeld.Round(time.Millisecond), pass.HoldCap, pass.Restarted)
		}
	case pass.WriterHeld > auditWALWriterBudget:
		fmt.Fprintf(log, "[sidecar] audit WAL checkpoint held the audit writer for %s (budget %s)\n",
			pass.WriterHeld.Round(time.Millisecond), auditWALWriterBudget)
	}
	if line := alarm.observe(now, pass.FileBytes); line != "" {
		fmt.Fprintln(log, line)
	}
}

// auditWALAlarm says when the audit WAL file passes auditWALAlarmBytes, again
// every auditWALAlarmRepeat while it stays there, and once when it is back.
type auditWALAlarm struct {
	raised   bool
	reported time.Time
}

func (a *auditWALAlarm) observe(now time.Time, walBytes int64) string {
	if walBytes > auditWALAlarmBytes {
		if a.raised && now.Sub(a.reported) < auditWALAlarmRepeat {
			return ""
		}
		a.raised, a.reported = true, now
		return fmt.Sprintf("[sidecar] WARNING: the audit WAL file is %d MiB, over its %d MiB bound: checkpoints are not keeping up with audit writes. "+
			"A process that keeps audit.db open for reading can cause this; check free disk space",
			walBytes>>20, int64(auditWALAlarmBytes)>>20)
	}
	if a.raised {
		a.raised = false
		return fmt.Sprintf("[sidecar] the audit WAL file is back under its %d MiB bound (%d MiB)", int64(auditWALAlarmBytes)>>20, walBytes>>20)
	}
	return ""
}
