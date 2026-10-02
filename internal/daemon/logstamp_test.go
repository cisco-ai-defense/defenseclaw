// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GAP-1319: every gateway.log line written through os.Stderr gets a time.
func TestStampLogPrefixesEachLine(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	origStderr, origStdout := os.Stderr, os.Stdout
	t.Cleanup(func() { os.Stderr, os.Stdout = origStderr, origStdout })

	at := time.Date(2026, 10, 2, 11, 0, 0, 0, time.UTC)
	restore := stampLog(f, f, func() time.Time { return at })
	if RawStderr() != f {
		t.Fatal("RawStderr must be the log file while stamping")
	}
	fmt.Fprintln(os.Stderr, "[config] reload failed: x")
	fmt.Fprint(os.Stdout, "[sidecar] up\n")
	fmt.Fprint(os.Stderr, "partial")
	restore()
	if os.Stderr != f {
		t.Fatal("restore did not put the log file back")
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"2026-10-02T11:00:00Z [config] reload failed: x",
		"2026-10-02T11:00:00Z [sidecar] up",
		"2026-10-02T11:00:00Z partial",
	}
	if got := strings.Split(string(raw), "\n"); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("log =\n%s\nwant\n%s", raw, strings.Join(want, "\n"))
	}
}

func TestStampChildLogIsANoOpOutsideTheDaemonChild(t *testing.T) {
	t.Setenv(EnvDaemon, "")
	orig := os.Stderr
	StampChildLog()()
	if os.Stderr != orig {
		t.Fatal("stderr changed outside a daemon child")
	}
}
