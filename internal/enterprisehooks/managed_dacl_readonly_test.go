// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	readOnlyTestTarget = "S-1-5-21-2172085703-1697333806-2105873718-500"
	readOnlyTestCodex  = "S-1-5-21-2172085703-1697333806-2105873718-1000"
	// The rights Codex's Windows sandbox grants CodexSandboxUsers.
	readOnlyTestCodexMask uint32 = 0x001200a9
)

func TestWindowsReadOnlyAccessMask(t *testing.T) {
	readOnly := []uint32{
		readOnlyTestCodexMask, // FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
		0x00120089,            // FILE_GENERIC_READ
		0x001200a0,            // FILE_GENERIC_EXECUTE
		0x00000001,            // FILE_LIST_DIRECTORY
		0x00000020,            // FILE_TRAVERSE
		0x00020000,            // READ_CONTROL
		0x80000000,            // GENERIC_READ
		0xa0000000,            // GENERIC_READ | GENERIC_EXECUTE
	}
	for _, mask := range readOnly {
		if !windowsReadOnlyAccessMask(mask) {
			t.Errorf("mask 0x%08x is read-only, classifier refused it", mask)
		}
	}
	writeLike := map[string]uint32{
		"none":                   0,
		"FILE_WRITE_DATA":        0x00000002,
		"FILE_APPEND_DATA":       0x00000004,
		"FILE_WRITE_EA":          0x00000010,
		"FILE_DELETE_CHILD":      0x00000040,
		"FILE_WRITE_ATTRIBUTES":  0x00000100,
		"DELETE":                 0x00010000,
		"WRITE_DAC":              0x00040000,
		"WRITE_OWNER":            0x00080000,
		"ACCESS_SYSTEM_SECURITY": 0x01000000,
		"MAXIMUM_ALLOWED":        0x02000000,
		"GENERIC_ALL":            0x10000000,
		"GENERIC_WRITE":          0x40000000,
		"FILE_ALL_ACCESS":        0x001f01ff,
		"modify":                 0x001301bf,
		"read plus write data":   readOnlyTestCodexMask | 0x00000002,
		"read plus delete child": readOnlyTestCodexMask | 0x00000040,
		"unknown bit":            readOnlyTestCodexMask | 0x00000200,
	}
	for name, mask := range writeLike {
		if windowsReadOnlyAccessMask(mask) {
			t.Errorf("%s (0x%08x) is not read-only, classifier accepted it", name, mask)
		}
	}
	if windowsReadOnlyGrantMask&windowsWriteLikeGrantMask != 0 {
		t.Fatalf("read-only grant mask 0x%08x overlaps write-like mask 0x%08x", windowsReadOnlyGrantMask, windowsWriteLikeGrantMask)
	}
	for bit := uint32(1); bit != 0; bit <<= 1 {
		if bit&windowsWriteLikeGrantMask != 0 && windowsReadOnlyAccessMask(readOnlyTestCodexMask|bit) {
			t.Errorf("write-like bit 0x%08x was accepted", bit)
		}
	}
}

func TestWindowsReadOnlyExtraACE(t *testing.T) {
	codex := windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x03, mask: readOnlyTestCodexMask, sid: readOnlyTestCodex}
	if !windowsReadOnlyExtraACE(codex, readOnlyTestTarget) {
		t.Fatal("Codex sandbox read grant was refused")
	}
	inheritOnly := codex
	inheritOnly.flags = 0x0b // OI|CI|IO
	inheritOnly.mask = 0xa0000000
	if !windowsReadOnlyExtraACE(inheritOnly, readOnlyTestTarget) {
		t.Fatal("inherit-only generic read grant was refused")
	}
	refused := map[string]windowsDACLEntry{}
	deny := codex
	deny.aceType = 0x01
	refused["deny"] = deny
	object := codex
	object.aceType = 0x05
	refused["object allow"] = object
	inherited := codex
	inherited.flags = 0x13 // OI|CI|INHERITED
	refused["inherited"] = inherited
	audit := codex
	audit.flags = 0x43 // SUCCESSFUL_ACCESS audit flag
	refused["audit flag"] = audit
	write := codex
	write.mask |= 0x00000002
	refused["write"] = write
	empty := codex
	empty.sid = ""
	refused["no SID"] = empty
	for name, sid := range map[string]string{
		"target":         readOnlyTestTarget,
		"target case":    "s-1-5-21-2172085703-1697333806-2105873718-500",
		"LocalSystem":    "S-1-5-18",
		"Administrators": "S-1-5-32-544",
		"OWNER RIGHTS":   "S-1-3-4",
		"CREATOR OWNER":  "S-1-3-0",
		// Broad groups: a sandbox grants its own group, never these.
		"Everyone":      "S-1-1-0",
		"Dialup":        "S-1-5-1",
		"Batch":         "S-1-5-3",
		"Service":       "S-1-5-6",
		"Local account": "S-1-5-113",
		"Local account and member of Administrators": "S-1-5-114",
		"Authenticated Users":                        "S-1-5-11",
		"Users":                                      "S-1-5-32-545",
		"Remote Desktop Users":                       "S-1-5-32-555",
		"ALL APPLICATION PACKAGES":                   "S-1-15-2-1",
		"Domain Users":                               "S-1-5-21-1004336348-1177238915-682003330-513",
		"Domain Guests":                              "s-1-5-21-1004336348-1177238915-682003330-514",
	} {
		entry := codex
		entry.sid = sid
		refused[name] = entry
	}
	for name, entry := range refused {
		if windowsReadOnlyExtraACE(entry, readOnlyTestTarget) {
			t.Errorf("%s: extra ACE %+v was accepted", name, entry)
		}
	}
}

func TestWindowsReadOnlyExtraTolerantPath(t *testing.T) {
	for _, path := range []string{
		`C:\Users\dclawadmin\.defenseclaw`,
		`C:\Users\dclawadmin\.DefenseClaw\`,
		`C:\Users\dclawadmin\.defenseclaw\hooks`,
		`C:\Users\dclawadmin\.defenseclaw\HOOKS`,
		`\\?\C:\Users\dclawadmin\.defenseclaw`,
		`C:/Users/dclawadmin/.defenseclaw/hooks`,
	} {
		if !windowsReadOnlyExtraTolerantPath(path) {
			t.Errorf("%s should tolerate read-only grants", path)
		}
	}
	for _, path := range []string{
		``,
		`.defenseclaw`,
		`hooks`,
		`\.defenseclaw\hooks`,
		`C:\Users\dclawadmin\..\.defenseclaw`,
		`C:\Users\dclawadmin\.defenseclaw\connector_backups`,
		`C:\Users\dclawadmin\.defenseclaw\hooks\.hookcfg`,
		`C:\Users\dclawadmin\.defenseclaw\acp`,
		`C:\Users\dclawadmin\.defenseclaw-stage-0011`,
		`C:\Users\dclawadmin\.config\hooks`,
		`C:\Users\dclawadmin\.defenseclaw.rollback-00ff`,
	} {
		if windowsReadOnlyExtraTolerantPath(path) {
			t.Errorf("%s should keep the exact DACL", path)
		}
	}
}

func TestWindowsReadOnlyExtraACEsToleratedHonorsStrictMode(t *testing.T) {
	path := `C:\Users\dclawadmin\.defenseclaw`
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	if !windowsReadOnlyExtraACEsTolerated(path, true) {
		t.Fatal("default mode should tolerate read-only grants on the data folder")
	}
	if windowsReadOnlyExtraACEsTolerated(path, false) {
		t.Fatal("a file must keep the exact DACL")
	}
	t.Setenv(managed.TrustStrictAncestorsEnv, "1")
	if windowsReadOnlyExtraACEsTolerated(path, true) {
		t.Fatal("strict mode must keep the exact DACL")
	}
}

// readOnlyTestCanonical is the applied canonical directory DACL of the field
// report: O:LA, D:PAI(A;;RC;;;OW)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)
// (A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;;0x1301ff;;;LA)(A;OICIIO;DTSDGXGWGR;;;LA).
func readOnlyTestCanonical() ([]windowsDACLExpectedEntry, []windowsDACLEntry) {
	expected := []windowsDACLExpectedEntry{
		{sid: "S-1-3-4", mask: 0x00020000},
		{sid: "S-1-5-18", mask: 0x001f01ff},
		{sid: "S-1-5-18", mask: 0x10000000, flags: 0x0b},
		{sid: "S-1-5-32-544", mask: 0x001f01ff},
		{sid: "S-1-5-32-544", mask: 0x10000000, flags: 0x0b},
		{sid: readOnlyTestTarget, mask: 0x001301ff},
		{sid: readOnlyTestTarget, mask: 0xe0010040, flags: 0x0b},
	}
	entries := make([]windowsDACLEntry, 0, len(expected))
	for _, want := range expected {
		entries = append(entries, windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: want.flags, mask: want.mask, sid: want.sid})
	}
	return expected, entries
}

func TestMatchWindowsCanonicalDACL(t *testing.T) {
	expected, canonical := readOnlyTestCanonical()
	codex := windowsDACLEntry{aceType: windowsACEAccessAllowedType, flags: 0x03, mask: readOnlyTestCodexMask, sid: readOnlyTestCodex}
	field := append([]windowsDACLEntry{codex}, canonical...)

	if got := matchWindowsCanonicalDACL(canonical, expected, readOnlyTestTarget, false); got.failure != windowsDACLMatched || len(got.extras) != 0 {
		t.Fatalf("exact canonical DACL: %+v", got)
	}
	if got := matchWindowsCanonicalDACL(canonical, expected, readOnlyTestTarget, true); got.failure != windowsDACLMatched || len(got.extras) != 0 {
		t.Fatalf("exact canonical DACL, tolerant: %+v", got)
	}
	// The field report: 8 ACEs, refused exactly unless tolerated.
	if got := matchWindowsCanonicalDACL(field, expected, readOnlyTestTarget, false); got.failure != windowsDACLCountMismatch {
		t.Fatalf("strict field DACL: %+v, want count mismatch", got)
	}
	got := matchWindowsCanonicalDACL(field, expected, readOnlyTestTarget, true)
	if got.failure != windowsDACLMatched || len(got.extras) != 1 || got.extras[0] != 0 {
		t.Fatalf("tolerant field DACL: %+v, want one read-only extra at index 0", got)
	}

	cases := map[string]struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{}
	writeExtra := codex
	writeExtra.mask = 0x001301bf
	cases["write-capable extra"] = struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{append([]windowsDACLEntry{writeExtra}, canonical...), windowsDACLUnexpectedEntry}
	deny := codex
	deny.aceType = 0x01
	cases["deny extra"] = struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{append([]windowsDACLEntry{deny}, canonical...), windowsDACLNonAllowedType}
	usersRead := codex
	usersRead.sid = readOnlyTestTarget
	cases["duplicate target read"] = struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{append([]windowsDACLEntry{usersRead}, canonical...), windowsDACLUnexpectedEntry}
	// A canonical entry replaced by a read-only grant is not canonical.
	replaced := append([]windowsDACLEntry{codex}, canonical[1:]...)
	cases["missing canonical"] = struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{replaced, windowsDACLMissingCanonical}
	// The target's canonical entry with a changed mask is drift.
	weakened := append([]windowsDACLEntry(nil), canonical...)
	weakened[5].mask = 0x001200a9
	cases["changed canonical"] = struct {
		entries []windowsDACLEntry
		want    windowsDACLMatchFailure
	}{weakened, windowsDACLUnexpectedEntry}
	for name, tc := range cases {
		if got := matchWindowsCanonicalDACL(tc.entries, expected, readOnlyTestTarget, true); got.failure != tc.want {
			t.Errorf("%s: failure %d, want %d", name, got.failure, tc.want)
		}
	}
}

// A domain group is matched on the full S-1-5-21-<a>-<b>-<c>-<rid> shape, so a
// local group (the Codex sandbox group, RID 1000) or a longer SID ending in 513
// is not taken for Domain Users.
func TestWindowsReadOnlyExtraBroadSID(t *testing.T) {
	for sid, want := range map[string]bool{
		"S-1-1-0":              true,
		"S-1-5-21-1-2-3-513":   true,
		"S-1-5-21-1-2-3-514":   true,
		readOnlyTestCodex:      false,
		"S-1-5-21-1-2-3-4-513": false,
		"S-1-5-32-544":         false,
	} {
		if got := windowsReadOnlyExtraBroadSID(sid); got != want {
			t.Errorf("windowsReadOnlyExtraBroadSID(%s)=%v want %v", sid, got, want)
		}
	}
}
