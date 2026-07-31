// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadWatchdogPIDInfoRejectsOversizedRecord(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), watchdogPIDFile)
	if err := os.WriteFile(
		pidPath,
		bytes.Repeat([]byte("x"), maxWatchdogPIDFileBytes+1),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	_, err := readWatchdogPIDInfo(pidPath)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized watchdog PID record error = %v", err)
	}
}
