// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"time"
)

const (
	// auditWALGuardInterval is how often the audit write-ahead log's size is
	// checked (one stat call).
	auditWALGuardInterval = 2 * time.Second
	// auditWALLimitBytes is the size past which the log is checkpointed. A busy
	// gateway writes about 3.4 MB of log per hook decision, so this is the log
	// of roughly 75 hooks.
	auditWALLimitBytes = 256 << 20
)

// runAuditWALGuard keeps the audit database's write-ahead log bounded under
// sustained hook traffic (see audit.Store.CheckpointWALIfLarge).
func (s *Sidecar) runAuditWALGuard(ctx context.Context) {
	if s == nil || s.store == nil {
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
		if _, err := s.store.CheckpointWALIfLarge(ctx, auditWALLimitBytes); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] audit WAL checkpoint failed: %v\n", err)
		}
	}
}
