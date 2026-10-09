// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"
)

// The start lock serializes start and restart on every platform; on Windows
// it was a no-op, so concurrent restarts raced and printed FAILED (GAP-0528).
func TestGatewayStartLockSerializesStarts(t *testing.T) {
	dataDir := t.TempDir()
	release, err := acquireGatewayStartLock(dataDir, time.Second)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if _, err := acquireGatewayStartLock(dataDir, 200*time.Millisecond); err == nil ||
		!strings.Contains(err.Error(), "still in progress") {
		t.Fatalf("second lock while held = %v, want a timeout", err)
	}
	release()
	again, err := acquireGatewayStartLock(dataDir, time.Second)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()
}
