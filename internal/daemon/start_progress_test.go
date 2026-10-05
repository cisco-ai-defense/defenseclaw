// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"strings"
	"testing"
	"time"
)

// GAP-1858: start printed nothing while it waited up to 240 s for the
// gateway child to register its PID, so a slow start looked hung.
func TestWaitForChildPIDRegistrationReportsProgress(t *testing.T) {
	previous := startProgressInterval
	t.Cleanup(func() { startProgressInterval = previous })
	startProgressInterval = 5 * time.Millisecond

	d := New(t.TempDir())
	var steps []string
	d.SetStartProgress(func(_ time.Duration, step string) { steps = append(steps, step) })
	_, _, err := d.waitForChildPIDRegistration(999999, "gateway", "", make(chan error), 60*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for child PID registration") {
		t.Fatalf("err = %v, want a registration timeout", err)
	}
	if len(steps) == 0 || steps[0] != "waiting for the gateway process to register" {
		t.Fatalf("progress steps = %q, want the registration step", steps)
	}
}
