// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"testing"

	"golang.org/x/sys/unix"
)

// rel-1-0-3 GAP-0244: on RHEL (transparent huge pages "always", khugepaged
// max_ptes_none 511) khugepaged refilled the heap pages an idle release had
// returned, and the gateway resident size climbed back to its flood level
// minutes after the release. The release loop turns huge pages off for the
// gateway process before it starts.
func TestIdleReleaseLoopTurnsOffTransparentHugePagesForTheGateway(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runIdleMemoryRelease(ctx, func() {})
	disabled, err := unix.PrctlRetInt(unix.PR_GET_THP_DISABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_THP_DISABLE: %v", err)
	}
	if disabled != 1 {
		t.Fatalf("transparent huge pages still enabled for the gateway process (PR_GET_THP_DISABLE = %d), khugepaged can refill released heap pages", disabled)
	}
}
