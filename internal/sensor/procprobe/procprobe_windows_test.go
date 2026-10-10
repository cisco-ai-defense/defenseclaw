// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procprobe

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWMIProcessOwnerForCurrentProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	owner, ok := lookupWMIProcessOwners(map[uint32]int{pid: 0})[pid]
	if !ok || owner.name == "" || owner.sid == "" {
		t.Fatalf("Win32_Process.GetOwnerSid returned no owner for pid %d: %+v", pid, owner)
	}
}

// GAP-1250: the kernel's process list names each process's session without
// a handle to it, and it agrees with ProcessIdToSessionId for this process.
// GAP-1372: it also carries the creation time GetProcessTimes reports, which
// the snapshot row keeps as the start half of the process's ProcKey.
func TestProcessSessionsNamesTheSessionOfThisProcess(t *testing.T) {
	pid := uint32(os.Getpid())
	var want uint32
	if err := windows.ProcessIdToSessionId(pid, &want); err != nil {
		t.Skipf("ProcessIdToSessionId: %v", err)
	}
	fact, ok := processFacts()[pid]
	if !ok || fact.session != want {
		t.Fatalf("processFacts()[%d] = %+v (%v), want session %d", pid, fact, ok, want)
	}
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	if !fact.created.Equal(time.Unix(0, creation.Nanoseconds())) {
		t.Fatalf("processFacts()[%d].created = %s, want %s", pid, fact.created, time.Unix(0, creation.Nanoseconds()))
	}
	rows, _, err := snapshot()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.PID == int(pid) && (row.SessionID != want || !row.StartedAt.Equal(fact.created)) {
			t.Fatalf("snapshot row session = %d start = %s, want %d %s", row.SessionID, row.StartedAt, want, fact.created)
		}
	}
}

// TestUsableCmdlineBytesRejectsLengthsThatCannotBeIndexed pins the guard on a
// value read out of another process's PEB.
//
// A length of 1 passed the "greater than zero" check, then rounding down to
// a whole UTF-16 unit made it 0, and &buffer[0] on the empty slice panicked.
// This runs against every process on the host, so one process presenting an
// odd length took down the sensor and the gateway with it.
func TestUsableCmdlineBytesRejectsLengthsThatCannotBeIndexed(t *testing.T) {
	for _, test := range []struct {
		name       string
		length     int
		hasBuffer  bool
		wantLength int
		wantUsable bool
	}{
		{"one odd byte is not a UTF-16 unit", 1, true, 0, false},
		{"zero length", 0, true, 0, false},
		{"negative length", -2, true, 0, false},
		{"no buffer pointer", 64, false, 0, false},
		{"ordinary even length", 64, true, 64, true},
		{"odd length rounds down to a whole unit", 65, true, 64, true},
		{"oversize length is capped", maxCmdlineBytes + 4096, true, maxCmdlineBytes, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			length, usable := usableCmdlineBytes(test.length, test.hasBuffer)
			if usable != test.wantUsable {
				t.Fatalf("usable = %v, want %v", usable, test.wantUsable)
			}
			if length != test.wantLength {
				t.Fatalf("length = %d, want %d", length, test.wantLength)
			}
			if usable && length%2 != 0 {
				t.Fatalf("length %d is not a whole UTF-16 unit", length)
			}
			if usable && length == 0 {
				t.Fatal("reported usable with nothing to index")
			}
		})
	}
}

// maxCmdlineBytes must stay even, or the cap itself can produce a length that
// is not a whole UTF-16 unit.
func TestMaxCmdlineBytesIsAWholeNumberOfUTF16Units(t *testing.T) {
	if maxCmdlineBytes%2 != 0 {
		t.Fatalf("maxCmdlineBytes = %d, which is not a whole UTF-16 unit", maxCmdlineBytes)
	}
}
