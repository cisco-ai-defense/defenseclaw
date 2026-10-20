// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
)

const (
	aceOI = 0x01
	aceCI = 0x02
	aceIO = 0x08

	testTargetSID       = "S-1-5-21-2172085703-1697333806-2105873718-500"
	testCodexSandboxSID = "S-1-5-21-2172085703-1697333806-2105873718-1000"
)

// The canonical directory DACL windowsUserPathAppliedCanonicalACEs produces,
// as a managed ~/.defenseclaw on a Windows 11 test host reported it:
// O:LAG:BAD:PAI(A;;RC;;;OW)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)
// (A;;FA;;;BA)(A;;0x1301ff;;;LA)(A;OICIIO;DTSDGXGWGR;;;LA)
func canonicalTestDirectoryEntries() []managedDACLEntry {
	return []managedDACLEntry{
		{SID: "S-1-3-4", Mask: 0x00020000},
		{SID: testTargetSID, Mask: 0x001301ff},
		{SID: testTargetSID, Mask: 0xe0010040, Flags: aceOI | aceCI | aceIO},
		{SID: "S-1-5-18", Mask: 0x001f01ff},
		{SID: "S-1-5-18", Mask: 0x10000000, Flags: aceOI | aceCI | aceIO},
		{SID: "S-1-5-32-544", Mask: 0x001f01ff},
		{SID: "S-1-5-32-544", Mask: 0x10000000, Flags: aceOI | aceCI | aceIO},
	}
}

func withEntry(entries []managedDACLEntry, extra managedDACLEntry) []managedDACLEntry {
	return append(append([]managedDACLEntry(nil), entries...), extra)
}

// Codex's Windows sandbox grants its CodexSandboxUsers group read and execute
// on the hook runtime folder, (A;OICI;0x1200a9;;;<group>). The exact-count
// check rejected every install afterwards with "has 8 ACEs, expected 7".
func TestManagedDACLAcceptsReadOnlySandboxGrant(t *testing.T) {
	expected := canonicalTestDirectoryEntries()
	codex := managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x001200a9, Flags: aceOI | aceCI}
	if err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw`, true, expected, withEntry(expected, codex)); err != nil {
		t.Fatalf("canonical DACL plus the Codex sandbox read grant rejected: %v", err)
	}
	if err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw`, true, expected, expected); err != nil {
		t.Fatalf("canonical DACL rejected: %v", err)
	}
	generic := managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x80000000 | 0x20000000, Flags: aceOI | aceCI | aceIO}
	if err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw`, true, expected, withEntry(expected, generic)); err != nil {
		t.Fatalf("generic read/execute grant rejected: %v", err)
	}
}

// Anything an extra entry could use to change the managed runtime is still
// rejected, and the error names the principal.
func TestManagedDACLRejectsWriteCapableOrMissingEntries(t *testing.T) {
	expected := canonicalTestDirectoryEntries()
	for _, test := range []struct {
		name   string
		actual []managedDACLEntry
		want   string
	}{
		{"write data", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x001200a9 | 0x2}), "beyond read and execute"},
		{"delete", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x001200a9 | 0x00010000}), "beyond read and execute"},
		{"write DAC", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x00040000}), "beyond read and execute"},
		{"write owner", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x00080000}), "beyond read and execute"},
		{"generic write", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x40000000, Flags: aceOI | aceCI | aceIO}), "beyond read and execute"},
		{"generic all", withEntry(expected, managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x10000000}), "beyond read and execute"},
		{"duplicate canonical", withEntry(expected, expected[0]), "repeats the canonical ACE for principal S-1-3-4"},
		{"Everyone read-only", withEntry(expected, managedDACLEntry{SID: "S-1-1-0", Mask: 0x001200a9, Flags: aceOI | aceCI}), "broad group Everyone"},
		{"Authenticated Users read-only", withEntry(expected, managedDACLEntry{SID: "S-1-5-11", Mask: 0x001200a9}), "broad group Authenticated Users"},
		{"ALL APPLICATION PACKAGES read-only", withEntry(expected, managedDACLEntry{SID: "S-1-15-2-1", Mask: 0x001200a9}), "broad group ALL APPLICATION PACKAGES"},
		{"Remote Desktop Users read-only", withEntry(expected, managedDACLEntry{SID: "S-1-5-32-555", Mask: 0x001200a9}), "broad group Remote Desktop Users"},
		{"Domain Users read-only", withEntry(expected, managedDACLEntry{SID: "S-1-5-21-1004336348-1177238915-682003330-513", Mask: 0x001200a9, Flags: aceOI | aceCI}), "broad group Domain Users"},
		{"deny entry", withEntry(expected, managedDACLEntry{SID: testTargetSID, Type: 1, Mask: 0x001200a9}), "non-canonical ACE type 1 at index 7 (principal " + testTargetSID + ")"},
		{"missing canonical", expected[1:], "missing the canonical ACE for principal S-1-3-4"},
		{"canonical replaced by read-only", append([]managedDACLEntry{{SID: "S-1-5-18", Mask: 0x001200a9}}, expected[:3]...), "missing the canonical ACE"},
	} {
		err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw`, true, expected, test.actual)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: err=%v, want %q", test.name, err, test.want)
		}
	}
}

// Files, which include the connector token files, accept only their canonical
// entries: a read-only grant that is fine on the hook folder would expose a
// credential on a file.
func TestManagedDACLFilesAcceptNoExtraEntry(t *testing.T) {
	file := []managedDACLEntry{
		{SID: "S-1-3-4", Mask: 0x00020000},
		{SID: testTargetSID, Mask: 0x001301bf},
		{SID: "S-1-5-18", Mask: 0x001f01ff},
		{SID: "S-1-5-32-544", Mask: 0x001f01ff},
	}
	if err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw\hooks\.hook-codex.token`, false, file, file); err != nil {
		t.Fatalf("canonical file DACL rejected: %v", err)
	}
	codex := managedDACLEntry{SID: testCodexSandboxSID, Mask: 0x001200a9}
	err := checkManagedDACLEntries(`C:\Users\u\.defenseclaw\hooks\.hook-codex.token`, false, file, withEntry(file, codex))
	if err == nil || !strings.Contains(err.Error(), "files accept only the canonical entries") {
		t.Fatalf("read-only extra on a file: err=%v, want rejection", err)
	}
}

// A machine-local group whose RID only looks like a domain group's is matched
// on the full SID shape, so the Codex sandbox group (RID 1000) and a local
// group with RID 513 under a longer SID are not mistaken for Domain Users.
func TestManagedDACLBroadPrincipalName(t *testing.T) {
	for sid, want := range map[string]string{
		"S-1-1-0": "Everyone",
		"s-1-5-21-1004336348-1177238915-682003330-513": "Domain Users",
		"S-1-5-21-1004336348-1177238915-682003330-514": "Domain Guests",
		testCodexSandboxSID:                            "",
		"S-1-5-21-1-2-3-4-513":                         "",
		"S-1-5-32-544":                                 "",
	} {
		if got := managedDACLBroadPrincipalName(sid); got != want {
			t.Errorf("managedDACLBroadPrincipalName(%s)=%q want %q", sid, got, want)
		}
	}
}
