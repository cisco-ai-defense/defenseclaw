// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc/eventlog"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// TestGAP2042EventLogRoundTrip: records written the way the managed hook
// writes them (Application log, event ID 3, Error and Warning) are read
// back by the wevtutil reader; another event ID is not (rel-1-0-10:GAP-2042).
func TestGAP2042EventLogRoundTrip(t *testing.T) {
	source := fmt.Sprintf("DefenseClawHostRecordTest%d", time.Now().UnixNano())
	events, err := eventlog.Open(source)
	if err != nil {
		t.Fatalf("open the event source: %v", err)
	}
	defer events.Close()
	since := time.Now().Add(-time.Minute)
	if err := events.Error(hookexec.ManagedHookDecisionEventID, hookRecordLine(managed.MarkerBoundary, "block")); err != nil {
		t.Fatal(err)
	}
	if err := events.Warning(hookexec.ManagedHookDecisionEventID, hookRecordLine(managed.MarkerDegraded, "allow")); err != nil {
		t.Fatal(err)
	}
	if err := events.Error(2, hookRecordLine(managed.MarkerBoundary, "block")); err != nil {
		t.Fatal(err)
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
			t.Fatalf("event log read back %+v from %q", snap, got.lines)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestGAP2042EventLogSourceQuoting: a source name that would break the
// query is refused, not read.
func TestGAP2042EventLogSourceQuoting(t *testing.T) {
	if _, err := readHostRecordLines(context.Background(), "x' or '1'='1", time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("a quoted source was queried")
	}
}
