// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"
)

const (
	// auditWALGuardInterval is how often the audit write-ahead log's active
	// frame count is checked on its dedicated checkpoint connection.
	auditWALGuardInterval = 2 * time.Second
	// auditWALLimitBytes is the size past which the log is checkpointed. A busy
	// gateway writes about 3.4 MB of log per hook decision, so this is the log
	// of roughly 75 hooks.
	auditWALLimitBytes = 256 << 20
	// A checkpoint may copy and sync frames on the audit store's only writer
	// connection. Hooks need that connection for correlation and their verdict
	// records, so never let maintenance consume a hook's three-second budget.
	auditWALGuardTimeout = 200 * time.Millisecond
)

// runAuditWALGuard keeps the audit database's write-ahead log bounded under
// sustained hook traffic (see audit.Store.CheckpointWALIfLarge).
func (s *Sidecar) runAuditWALGuard(ctx context.Context) {
	if s == nil || s.store == nil || s.currentConfig().SecureClientIntegration() {
		return
	}
	ticker := time.NewTicker(auditWALGuardInterval)
	defer ticker.Stop()
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
		err := checkpointAuditWALWithin(ctx, func(checkpointCtx context.Context) error {
			_, err := s.store.CheckpointWALIfLarge(checkpointCtx, auditWALLimitBytes)
			return err
		})
		// An interrupted checkpoint is retried at the next tick. The
		// dedicated connection still performs the bulk of the copy.
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] audit WAL checkpoint yielded elapsed_ms=%d\n", auditWALGuardTimeout.Milliseconds())
		} else if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] audit WAL checkpoint failed: %v\n", err)
		}
	}
}

func checkpointAuditWALWithin(ctx context.Context, checkpoint func(context.Context) error) error {
	checkpointCtx, cancel := context.WithTimeout(ctx, auditWALGuardTimeout)
	defer cancel()
	err := checkpoint(checkpointCtx)
	if checkpointCtx.Err() != nil {
		return checkpointCtx.Err()
	}
	return err
}
