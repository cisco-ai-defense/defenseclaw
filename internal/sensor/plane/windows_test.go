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

//go:build windows

package plane

import "testing"

// A representative Security-channel 4688 record, in the exact XML wevtapi
// renders. Decoding is tested against the real wire shape because the shape is
// what a Windows release can change.
const security4688 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4688</EventID><EventRecordID>1033782</EventRecordID>
<TimeCreated SystemTime="2026-09-09T23:16:25.3140000Z"/></System>
<EventData>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="NewProcessId">0x9d0</Data>
<Data Name="NewProcessName">C:\Windows\System32\net.exe</Data>
<Data Name="ProcessId">0x1918</Data>
<Data Name="CommandLine">net  user svc P@ss /add</Data>
</EventData></Event>`

const security4720 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4720</EventID><EventRecordID>99</EventRecordID>
<TimeCreated SystemTime="2026-09-09T23:16:26.0000000Z"/></System>
<EventData>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="TargetUserName">svc</Data>
<Data Name="ProcessId">0x9d0</Data>
</EventData></Event>`

func TestWindowsDecodes4688WithLineageAndArgv(t *testing.T) {
	t.Parallel()
	record, err := decodeSecurityXML(security4688)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if record.RecordID != 1033782 {
		t.Fatalf("RecordID = %d; the poll dedup depends on it", record.RecordID)
	}
	event, ok := translateSecurityRecord(record)
	if !ok {
		t.Fatal("a 4688 record did not translate")
	}
	if event.Kind != KindExec {
		t.Errorf("Kind = %s, want %s", event.Kind, KindExec)
	}
	// Security-log pids are hex. Reading 0x9d0 as decimal would attribute the
	// event to an unrelated process.
	if event.PID != 0x9d0 {
		t.Errorf("PID = %d, want %d", event.PID, 0x9d0)
	}
	if event.PPID != 0x1918 {
		t.Errorf("PPID = %d, want %d", event.PPID, 0x1918)
	}
	if event.Name != "net.exe" {
		t.Errorf("Name = %q, want the basename", event.Name)
	}
	if event.Cmdline != "net  user svc P@ss /add" {
		t.Errorf("Cmdline = %q", event.Cmdline)
	}
	if event.At.IsZero() {
		t.Error("At was not decoded")
	}
}

func TestWindowsDecodesAccountCreation(t *testing.T) {
	t.Parallel()
	record, err := decodeSecurityXML(security4720)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	event, ok := translateSecurityRecord(record)
	if !ok || event.Kind != KindIdentity {
		t.Fatalf("4720 translated to %+v, ok=%t", event, ok)
	}
	if event.Detail == "" {
		t.Error("an identity event carried no detail")
	}
}

func TestWindowsHexAndDecimalPids(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]int{
		"0x9d0": 0x9d0, "0X1918": 0x1918, "4242": 4242, "": 0, "nonsense": 0,
	} {
		if got := parseHexOrDecimal(input); got != want {
			t.Errorf("parseHexOrDecimal(%q) = %d, want %d", input, got, want)
		}
	}
}

// TestWindowsQueryIsBoundedByTime pins the shape that makes the poll viable: a
// Security channel holds hundreds of thousands of records, and an unbounded
// query would render all of them once per poll.
func TestWindowsQueryIsBoundedByTime(t *testing.T) {
	t.Parallel()
	query := securityQuery(30000)
	for _, want := range []string{"timediff", "30000", "EventID=4688"} {
		if !contains(query, want) {
			t.Fatalf("query = %q, want it to contain %q", query, want)
		}
	}
}

// TestWindowsSeenSetSuppressesTheOverlap pins that the deliberately
// overlapping poll window does not deliver an event twice.
func TestWindowsSeenSetSuppressesTheOverlap(t *testing.T) {
	t.Parallel()
	source := &windowsSource{buffer: NewBuffer(), stop: make(chan struct{})}
	if !source.markSeen(42) {
		t.Fatal("a new record id was reported as seen")
	}
	if source.markSeen(42) {
		t.Fatal("a repeated record id was delivered twice")
	}
	if source.markSeen(0) {
		t.Fatal("record id zero was accepted")
	}
	for index := 1; index <= maxSeenRecords+10; index++ {
		source.markSeen(uint64(index) + 1000)
	}
	source.mu.Lock()
	size := len(source.seen)
	source.mu.Unlock()
	if size > maxSeenRecords {
		t.Fatalf("seen set holds %d, above the %d bound", size, maxSeenRecords)
	}
}

func contains(haystack, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}
