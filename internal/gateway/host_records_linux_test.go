// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestGAP2042JournalRoundTrip: a record sent the way the managed hook sends
// it (a syslog datagram to /dev/log under the gateway tag) is read back by
// the journald reader (rel-1-0-10:GAP-2042).
func TestGAP2042JournalRoundTrip(t *testing.T) {
	conn, err := net.Dial("unixgram", "/dev/log")
	if err != nil {
		t.Skipf("no /dev/log on this host: %v", err)
	}
	defer conn.Close()
	if _, err := os.Stat("/usr/bin/journalctl"); err != nil {
		t.Skipf("no journalctl: %v", err)
	}
	source := fmt.Sprintf("DefenseClawHostRecordTest%d", time.Now().UnixNano())
	since := time.Now().Add(-time.Minute)
	for _, line := range []string{hookRecordLine(managed.MarkerBoundary, "block"), hookRecordLine(managed.MarkerDegraded, "allow")} {
		message := fmt.Sprintf("<27>%s %s[%d]: %s", time.Now().Format(time.Stamp), source, os.Getpid(), line)
		if _, err := conn.Write([]byte(message)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := readHostRecordLines(context.Background(), source, since)
		if err != nil {
			t.Fatal(err)
		}
		snap := countHostRecords(got)
		if snap.Blocks == 1 && snap.Allows == 1 && snap.Dropped == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("journal read back %+v from %q", snap, got.lines)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
