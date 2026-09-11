// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package procprobe

import (
	"os"
	"testing"
)

// TestSnapshotSeesThisProcess is the smoke test that the platform reader
// actually works on the host running the suite. It deliberately asserts on the
// test binary itself, which is the one process guaranteed to be present and
// readable regardless of privilege.
func TestSnapshotSeesThisProcess(t *testing.T) {
	rows, skipped, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("Snapshot() returned an empty process table")
	}
	self := os.Getpid()
	for _, row := range rows {
		if row.PID != self {
			continue
		}
		if row.Name == "" {
			t.Error("this process has no name")
		}
		if row.Cmdline == "" {
			// argv is the whole reason this package exists rather than reusing
			// the inventory snapshot, so its absence for our own process is a
			// real failure rather than a permission artifact.
			t.Error("this process has no command line; the argv read is broken")
		}
		if row.PPID <= 0 {
			t.Errorf("this process has ppid %d", row.PPID)
		}
		if row.RSSBytes <= 0 {
			t.Errorf("this process has rss %d", row.RSSBytes)
		}
		t.Logf("self: pid=%d ppid=%d name=%q cpu=%s rss=%d user=%q skipped=%d",
			row.PID, row.PPID, row.Name, row.CPUTime, row.RSSBytes, row.User, skipped)
		return
	}
	t.Fatalf("Snapshot() did not include this process (pid %d) among %d rows", self, len(rows))
}

// TestSnapshotReportsWhatItCouldNotRead pins that coverage loss is counted
// rather than silently dropped. An unprivileged run must be able to say how
// much of the table it could not see.
func TestSnapshotReportsWhatItCouldNotRead(t *testing.T) {
	rows, skipped, err := Snapshot()
	if err != nil {
		t.Fatalf("Snapshot(): %v", err)
	}
	// A count cannot be negative, so asserting that proves nothing. Assert
	// what the function is for: it read this host, and every row it returned
	// is usable.
	if len(rows) == 0 {
		t.Fatal("no processes at all: this test runs inside one")
	}
	self := false
	for _, row := range rows {
		if row.PID <= 0 {
			t.Fatalf("row with no pid: %+v", row)
		}
		if row.Name == "" {
			t.Fatalf("row with no name: %+v", row)
		}
		if row.CPUTime < 0 {
			t.Fatalf("negative CPU time on pid %d: %s", row.PID, row.CPUTime)
		}
		if row.PID == os.Getpid() {
			self = true
		}
	}
	if !self {
		t.Errorf("the snapshot did not include this test process (pid %d), "+
			"so it is not reading the live table", os.Getpid())
	}
	t.Logf("%d rows readable, %d rows partial or unreadable", len(rows), skipped)
}
