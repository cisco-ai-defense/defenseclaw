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

import (
	"fmt"
	"strings"
	"testing"
)

// A representative Security-channel 4688 record, in the exact XML wevtapi
// renders. Decoding is tested against the real wire shape because the shape is
// what a Windows release can change.
const security4688 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4688</EventID><EventRecordID>1033782</EventRecordID>
<TimeCreated SystemTime="2026-09-09T23:16:25.3140000Z"/></System>
<EventData>
<Data Name="SubjectUserSid">S-1-5-21-1-2-3-500</Data>
<Data Name="SubjectUserName">Administrator</Data>
<Data Name="SubjectDomainName">DCLAB</Data>
<Data Name="TargetUserSid">S-1-0-0</Data>
<Data Name="TargetUserName">-</Data>
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
	// The new process runs as its creator unless the target names another
	// account (GAP-1464).
	if event.User != `DCLAB\Administrator` || event.UserSID != "S-1-5-21-1-2-3-500" {
		t.Errorf("owner = %q %q, want the creator", event.User, event.UserSID)
	}
	record, err = decodeSecurityXML(strings.NewReplacer("S-1-0-0", "S-1-5-21-1-2-3-1104",
		`<Data Name="TargetUserName">-</Data>`, `<Data Name="TargetUserName">alice</Data>`).Replace(security4688))
	if err != nil {
		t.Fatal(err)
	}
	if event, _ = translateSecurityRecord(record); event.User != "alice" || event.UserSID != "S-1-5-21-1-2-3-1104" {
		t.Errorf("owner = %q %q, want the target account", event.User, event.UserSID)
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

// security4663 is a Security-channel 4663 record as EvtRenderEventXml
// returns it, taken from a managed Windows host where Claude Code wrote a
// profile settings.json: AccessList holds unresolved %%NNNN message ids, never
// the text the old check looked for.
const security4663 = `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><EventID>4663</EventID><EventRecordID>%d</EventRecordID>
<TimeCreated SystemTime="2026-10-10T21:04:02.1230000Z"/></System>
<EventData>
<Data Name="SubjectUserSid">S-1-5-21-2566694559-2372738039-4094494201-1124</Data>
<Data Name="SubjectUserName">dcw-rv16adm</Data>
<Data Name="ObjectServer">Security</Data>
<Data Name="ObjectType">%s</Data>
<Data Name="ObjectName">%s</Data>
<Data Name="HandleId">0x2dcc</Data>
<Data Name="AccessList">%s</Data>
%s<Data Name="ProcessId">0x2f18</Data>
<Data Name="ProcessName">C:\Users\dcw-rv16adm\.local\bin\claude.exe</Data>
<Data Name="ResourceAttributes">S:AI</Data>
</EventData></Event>`

// TestWindowsClassifiesObjectAccessWrites pins how a 4663 record becomes a
// file write: the AccessMask decides when present, the AccessList ids
// otherwise, and an unrecognised list is a write only on an agent
// configuration path.
func TestWindowsClassifiesObjectAccessWrites(t *testing.T) {
	t.Parallel()
	const settings = `C:\Users\dcw-rv16bob.DCFC-WIN2-RS8\.claude\settings.json.tmp.12056.7572fa2d6107`
	const document = `C:\Users\dcw-rv16bob.DCFC-WIN2-RS8\Documents\notes.txt`
	const runKey = `\REGISTRY\USER\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run`
	mask := func(value string) string { return `<Data Name="AccessMask">` + value + "</Data>\n" }
	for index, tc := range []struct {
		name, objectType, path, accessList, accessMask string
		want                                           Kind
	}{
		{"WriteData with its mask", "File", settings, "%%4417\n\t\t\t\t", mask("0x2"), KindFileWrite},
		{"WriteData without a mask", "File", settings, "%%4417", "", KindFileWrite},
		{"AppendData without a mask", "File", document, "%%4418", "", KindFileWrite},
		{"AppendData mask", "File", document, "", mask("0x4"), KindFileWrite},
		{"resolved WriteData text", "File", document, "WriteData (or AddFile)", "", KindFileWrite},
		{"DELETE mask", "File", settings, "%%1537", mask("0x10000"), KindFileWrite},
		{"WRITE_DAC mask in decimal", "File", document, "%%1539", mask("262144"), KindFileWrite},
		{"ReadData", "File", settings, "%%4416", mask("0x1"), KindFileRead},
		{"SYNCHRONIZE only", "File", settings, "%%1541", mask("0x100000"), KindFileRead},
		{"unknown id on an agent config path", "File", settings, "%%9999", "", KindFileWrite},
		{"unknown id elsewhere", "File", document, "%%9999", "", KindFileRead},
		{"mask wins over a write list", "File", settings, "%%4417", mask("0x1"), KindFileRead},
		{"mask wins over a read list", "File", document, "%%4416", mask("0x2"), KindFileWrite},
		{"registry notify is a read", "Key", runKey, "%%4436", mask("0x10"), KindFileRead},
	} {
		raw := fmt.Sprintf(security4663, 5000+index, tc.objectType, tc.path, tc.accessList, tc.accessMask)
		record, err := decodeSecurityXML(raw)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		event, ok := translateSecurityRecord(record)
		if !ok {
			t.Fatalf("%s: a 4663 record did not translate", tc.name)
		}
		if event.Kind != tc.want {
			t.Errorf("%s: Kind = %s, want %s", tc.name, event.Kind, tc.want)
		}
		if event.PID != 0x2f18 || event.Name != "claude.exe" || event.User != "dcw-rv16adm" || event.Path != tc.path ||
			event.UserSID != "S-1-5-21-2566694559-2372738039-4094494201-1124" {
			t.Errorf("%s: event = %+v; the process, user and path drive attribution", tc.name, event)
		}
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
