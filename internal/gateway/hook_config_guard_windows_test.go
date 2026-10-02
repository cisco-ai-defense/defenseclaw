// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestHookConfigGuard_RearmsAfterBusyConfig holds the stripped config open
// without delete sharing, as an editor or scanner can, so the guard's atomic
// replacement fails. The guard must re-arm itself and finish the repair once
// the handle closes, without another file event.
func TestHookConfigGuard_RearmsAfterBusyConfig(t *testing.T) {
	conn, opts, cfgPath := installedCursorConnector(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := NewHookConfigGuard(nil, nil, guardTestDebounce)
	repairs := observeRepairs(guard)
	guard.Start(ctx, conn, opts)
	defer guard.Stop()

	// os.Open shares read and write but not delete. Opening before the strip
	// guarantees the handle is held when the debounced repair runs.
	holder, err := os.Open(cfgPath)
	if err != nil {
		t.Fatalf("hold config open: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte("{}\n"), 0o600); err != nil {
		_ = holder.Close()
		t.Fatalf("strip hook block: %v", err)
	}
	busy := <-repairs
	if closeErr := holder.Close(); closeErr != nil {
		t.Fatalf("release config: %v", closeErr)
	}
	if busy.err == nil || !connector.FileBusyError(busy.err) || !busy.rearmed {
		t.Fatalf("first repair = err %v rearmed %v; want a re-armed busy failure", busy.err, busy.rearmed)
	}

	waitForRepair(t, repairs, conn, opts)
}
