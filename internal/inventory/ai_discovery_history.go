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

package inventory

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Scan-history retention cadence. The continuous service records a scan on
// every full and process tick, so inventory.db grows without bound unless
// old scans are pruned; see sweepHistoryIfDue.
const (
	inventoryHistorySweepStartupDelay = 2 * time.Minute
	inventoryHistorySweepInterval     = time.Hour
	inventoryHistorySweepPoll         = time.Minute
	// inventoryHistorySweepBudget caps the prune part of one sweep so a
	// large backlog is drained over several sweeps.
	inventoryHistorySweepBudget = 25 * time.Second
	// inventoryHistoryDiagnosticInterval rate-limits repeated stderr
	// diagnostics of the same kind.
	inventoryHistoryDiagnosticInterval = 6 * time.Hour
	// inventoryHistoryBacklogLogScans is the prune size worth reporting
	// even when the pass drained the backlog.
	inventoryHistoryBacklogLogScans = 1000
)

// inventoryHistorySweeper schedules retention sweeps for one service.
type inventoryHistorySweeper struct {
	// now is the injectable clock; nil means time.Now.
	now     func() time.Time
	running atomic.Bool

	mu          sync.Mutex
	started     time.Time
	last        time.Time
	diagnostics map[string]time.Time
}

func (w *inventoryHistorySweeper) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *inventoryHistorySweeper) markStarted(now time.Time) {
	w.mu.Lock()
	if w.started.IsZero() {
		w.started = now
	}
	w.mu.Unlock()
}

// claimDue reports whether a sweep is due at now and, if so, records it as
// the latest sweep: once shortly after start, then at most once per interval.
func (w *inventoryHistorySweeper) claimDue(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started.IsZero() {
		w.started = now
	}
	if w.last.IsZero() {
		if now.Sub(w.started) < inventoryHistorySweepStartupDelay {
			return false
		}
	} else if now.Sub(w.last) < inventoryHistorySweepInterval {
		return false
	}
	w.last = now
	return true
}

// allowDiagnostic rate-limits stderr output per kind.
func (w *inventoryHistorySweeper) allowDiagnostic(kind string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if last, ok := w.diagnostics[kind]; ok && now.Sub(last) < inventoryHistoryDiagnosticInterval {
		return false
	}
	if w.diagnostics == nil {
		w.diagnostics = map[string]time.Time{}
	}
	w.diagnostics[kind] = now
	return true
}

// SetHistoryRetentionDays sets how many days of scan history inventory.db
// keeps. The gateway passes the effective observability.local.retention_days
// window (default config.ObservabilityV8DefaultRetentionDays) and updates it
// on config reload; 0 keeps history unbounded. Services built outside the
// gateway keep the default. Negative values are ignored.
func (s *ContinuousDiscoveryService) SetHistoryRetentionDays(days int) {
	if s == nil || days < 0 {
		return
	}
	s.historyRetentionDays.Store(int64(days))
}

// HistoryRetentionDays reports the scan-history window in days; 0 means
// unbounded.
func (s *ContinuousDiscoveryService) HistoryRetentionDays() int {
	if s == nil {
		return 0
	}
	return int(s.historyRetentionDays.Load())
}

// startHistoryRetention runs retention sweeps on a background goroutine so a
// prune or compaction never delays a scan. The returned stop function
// cancels the sweeper and waits for it, and must run before the inventory
// store is closed.
func (s *ContinuousDiscoveryService) startHistoryRetention(ctx context.Context) func() {
	if s == nil || s.invStore == nil {
		return func() {}
	}
	s.historySweep.markStarted(s.historySweep.clock())
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(inventoryHistorySweepPoll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sweepHistoryIfDue(ctx)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// sweepHistoryIfDue prunes scan history and agent identities older than the
// retention window and compacts the file when a sweep is due. It never runs concurrently with
// itself and only reports failures to stderr: history is additive, so a
// failed sweep must never fail or block scanning. Returns whether a sweep
// ran.
func (s *ContinuousDiscoveryService) sweepHistoryIfDue(ctx context.Context) bool {
	if s == nil || s.invStore == nil {
		return false
	}
	w := &s.historySweep
	if !w.running.CompareAndSwap(false, true) {
		return false
	}
	defer w.running.Store(false)
	now := w.clock()
	if !w.claimDue(now) {
		return false
	}
	days := s.HistoryRetentionDays()
	if days <= 0 {
		return true
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	// The identity ledger is small and not tied to a scan, so it is pruned
	// first and a failed or partial scan prune cannot skip it.
	pruneAgentLedger(ctx, s.invStore, cutoff, days, w, now, "ai-discovery")
	pruned, err := s.invStore.PruneScanHistory(ctx, cutoff, inventoryHistorySweepBudget)
	if err != nil {
		if ctx.Err() == nil && w.allowDiagnostic("prune", now) {
			fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history prune failed: %v\n", err)
		}
		if pruned.ScansDeleted == 0 {
			return true
		}
	}
	if !pruned.Drained || pruned.ScansDeleted >= inventoryHistoryBacklogLogScans {
		remaining := "older history is fully pruned"
		if !pruned.Drained {
			remaining = "older history remains and is pruned on the next sweep"
		}
		fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history: pruned %d scans older than %d days; %s\n",
			pruned.ScansDeleted, days, remaining)
	}
	compacted, err := s.invStore.CompactScanHistory(ctx, pruned)
	switch {
	case err != nil:
		if ctx.Err() == nil && w.allowDiagnostic("compact", now) {
			fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history compaction failed: %v\n", err)
		}
	case compacted.Vacuumed:
		fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history compacted; freed space is now returned automatically\n")
	case compacted.Skipped != "":
		if w.allowDiagnostic("compact-skipped", now) {
			fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history compaction skipped: %s\n", compacted.Skipped)
		}
	}
	return true
}

// pruneAgentLedger prunes the agent identities and the session ids they
// counted that were last seen before cutoff, reporting failures to stderr
// under tag.
func pruneAgentLedger(ctx context.Context, store *InventoryStore, cutoff time.Time, days int,
	w *inventoryHistorySweeper, now time.Time, tag string) {
	if agents, err := store.PruneAgentIdentities(ctx, cutoff); err != nil {
		if ctx.Err() == nil && w.allowDiagnostic("prune-agents", now) {
			fmt.Fprintf(os.Stderr, "[%s] agent identity prune failed: %v\n", tag, err)
		}
	} else if agents > 0 {
		fmt.Fprintf(os.Stderr, "[%s] inventory history: pruned %d agent identities not seen for %d days\n", tag, agents, days)
	}
	// So are the session ids the ledger remembers it counted.
	if _, err := store.PruneAgentIdentitySessions(ctx); err != nil {
		if ctx.Err() == nil && w.allowDiagnostic("prune-agent-sessions", now) {
			fmt.Fprintf(os.Stderr, "[%s] agent identity session prune failed: %v\n", tag, err)
		}
	}
}

// AgentLedgerSweeper prunes the agent identity ledger of an inventory.db
// that no discovery service sweeps: the gateway records agent identities in
// a store it opens itself while AI discovery is off (GAP-0289). It runs on
// the scan-history cadence, shortly after the first call and then hourly.
type AgentLedgerSweeper struct {
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	w   inventoryHistorySweeper
}

// SweepIfDue prunes the agent identities and sessions of store not seen for
// days when a sweep is due; days <= 0 keeps them. It reports whether a
// prune ran.
func (a *AgentLedgerSweeper) SweepIfDue(ctx context.Context, store *InventoryStore, days int) bool {
	if a == nil || store == nil {
		return false
	}
	w := &a.w
	if !w.running.CompareAndSwap(false, true) {
		return false
	}
	defer w.running.Store(false)
	w.now = a.Now
	now := w.clock()
	if !w.claimDue(now) || days <= 0 {
		return false
	}
	pruneAgentLedger(ctx, store, now.Add(-time.Duration(days)*24*time.Hour), days, w, now, "sidecar")
	return true
}
