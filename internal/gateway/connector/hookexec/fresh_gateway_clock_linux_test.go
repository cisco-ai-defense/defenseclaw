// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// freshGatewayClock installs the proof clock for a test that drives a real
// process through the fresh-gateway proof, standing one second after the
// start of that process. The 12 s window of the proof is then read on this
// clock: a slow host cannot age the gateway, and a test moves the clock to
// the limit to pin it. It returns the start of the process.
func freshGatewayClock(t *testing.T, pid int) (*proofclocktest.Clock, time.Time) {
	t.Helper()
	start, ok := procidentity.StartTime(pid)
	if !ok {
		t.Fatal("helper start time unavailable")
	}
	clock := proofclocktest.Install(t)
	clock.Set(start.Add(time.Second))
	return clock, start
}

// dateGatewayRecord sets the modification time of the gateway record, which
// the cheap first look of the native hook reads, so a test decides it and
// the host does not.
func dateGatewayRecord(t *testing.T, dataDir string, at time.Time) {
	t.Helper()
	if err := os.Chtimes(filepath.Join(dataDir, "gateway.pid"), at, at); err != nil {
		t.Fatal(err)
	}
}

// eventually waits for cond, which a real process makes true in its own
// time. It ends on the result: a condition that never comes ends the test at
// the go test timeout, or here after two minutes.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Minute); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatalf("%s never happened", what)
		}
	}
}

// TestFreshGatewayWindowsKeepTheirProductValues pins the limits the
// fresh-gateway proof reads on the proof clock.
func TestFreshGatewayWindowsKeepTheirProductValues(t *testing.T) {
	if perUserFreshGatewayWindow != 12*time.Second || freshOwnerCaptureWait != time.Second {
		t.Fatalf("window %v, owner read %v, want 12s and 1s", perUserFreshGatewayWindow, freshOwnerCaptureWait)
	}
}
