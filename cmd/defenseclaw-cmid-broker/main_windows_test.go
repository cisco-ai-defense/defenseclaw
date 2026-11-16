// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"context"
	"log"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

func TestDriftSinkFlushesBufferedReportsAfterStartupInOrder(t *testing.T) {
	sink := newDriftSink()
	sink.trust(`C:\ProgramData\Cisco\logs`, "broker log directory", "untrusted Windows principal S-1-5-32-545")
	sink.trust(`C:\Program Files\Cisco\broker.exe`, "CMID broker executable", "owner S-1-5-21-1 is not trusted")
	// The same line again is written once.
	sink.trust(`C:\ProgramData\Cisco\logs`, "broker log directory", "untrusted Windows principal S-1-5-32-545")

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	logger.Print("stage=startup version=test")
	sink.attach(logger)
	sink.key(cmidbroker.KeyDriftReport{
		Action:      cmidbroker.KeyDriftAccepted,
		Object:      "broker authentication key",
		Path:        `C:\ProgramData\Cisco\broker-auth.key`,
		Reason:      "DACL is not protected",
		RepairError: "open key for repair: Access is denied.",
	})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		"stage=startup version=test",
		`stage=acl-drift action=accepted object="broker log directory" path="C:\\ProgramData\\Cisco\\logs" reason="untrusted Windows principal S-1-5-32-545"`,
		`stage=acl-drift action=accepted object="CMID broker executable" path="C:\\Program Files\\Cisco\\broker.exe" reason="owner S-1-5-21-1 is not trusted"`,
		`stage=acl-drift action=accepted object="broker authentication key" path="C:\\ProgramData\\Cisco\\broker-auth.key" reason="DACL is not protected" repair_error="open key for repair: Access is denied."`,
	}
	if len(lines) != len(want) {
		t.Fatalf("log lines = %q, want %q", lines, want)
	}
	for index := range want {
		if lines[index] != want[index] {
			t.Fatalf("line %d = %q, want %q", index, lines[index], want[index])
		}
	}
}

func TestDriftSinkReportsRepairedKey(t *testing.T) {
	sink := newDriftSink()
	var buf bytes.Buffer
	sink.attach(log.New(&buf, "", 0))
	sink.key(cmidbroker.KeyDriftReport{
		Action: cmidbroker.KeyDriftRepaired,
		Object: "broker authentication key",
		Path:   `C:\key`,
		Reason: "DACL is not protected",
	})
	if got := strings.TrimSpace(buf.String()); !strings.HasPrefix(got, "stage=acl-drift action=repaired ") ||
		strings.Contains(got, "repair_error") {
		t.Fatalf("repaired line = %q", got)
	}
}

func TestServeBrokerKeyFailureIsAStartupFailure(t *testing.T) {
	sink := newDriftSink()
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	sink.attach(logger)
	options := brokerOptions{
		authKeyPath:        filepath.Join(t.TempDir(), "missing", "broker-auth.key"),
		gatewayServiceName: "DefenseClawGateway",
	}
	ready := make(chan struct{})
	stage, err := serveBroker(context.Background(), options, cmidbroker.ServerConfig{}, logger, sink, ready)
	if err == nil {
		t.Fatal("serveBroker succeeded without a key")
	}
	if stage != "startup-failed" {
		t.Fatalf("stage = %q, want startup-failed", stage)
	}
	select {
	case <-ready:
		t.Fatal("ready was signalled for a failed startup")
	default:
	}
}

func TestDriftSinkPendingSummaryCarriesUnflushedLines(t *testing.T) {
	sink := newDriftSink()
	if got := sink.pendingSummary(); got != "" {
		t.Fatalf("empty sink summary = %q", got)
	}
	sink.trust(`C:\logs`, "broker log directory", strings.Repeat("x", 5000))
	got := sink.pendingSummary()
	if !strings.HasPrefix(got, "stage=acl-drift action=accepted") || !strings.HasSuffix(got, "\n...") || len(got) > 4100 {
		t.Fatalf("summary = %.80q... (len %d), want a capped acl-drift summary", got, len(got))
	}
}
