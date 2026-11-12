// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// A marker this account wrote in a folder it made is trusted; a folder or a
// reparse point in its place is not a marker, and neither is a marker with a
// second link (cowork-1-0-8 GAP-0085).
func TestCoworkMarkerTrustedReadsTheRealSecurity(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	marker, _ := CoworkRemovalPaths(dataDir)
	if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !coworkMarkerTrusted(marker) {
		t.Fatal("this account's marker in its own folder was not trusted")
	}
	link := marker + ".link"
	if err := os.Link(marker, link); err != nil {
		t.Fatal(err)
	}
	if coworkMarkerTrusted(marker) {
		t.Fatal("a marker with a second link was trusted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if !coworkMarkerTrusted(marker) {
		t.Fatal("the marker was not trusted again after its second link was removed")
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	if coworkMarkerTrusted(marker) {
		t.Fatal("a folder at the marker path was trusted as a marker")
	}
	if _, _, err := coworkPathSecurity(filepath.Join(filepath.Dir(marker), "missing"), false); err == nil {
		t.Fatal("a missing marker has a security descriptor")
	}
}

// After a refused marker the guard keeps blocking when the launcher is gone,
// and names both ways out; the same marker with one link is honoured.
func TestCoworkGuardNamesBothWaysOutAfterARefusedMarker(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, ".defenseclaw")
	launcher := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	marker, _ := CoworkRemovalPaths(dataDir)
	if err := os.WriteFile(marker, []byte("removed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(marker, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := RunCowork(dataDir, launcher, "PreToolUse", strings.NewReader("{}"), &stdout, &stderr); code != 2 {
		t.Fatalf("refused marker: exit %d, want 2", code)
	}
	if got := stderr.String(); !strings.Contains(got, MissingMessage) || !strings.Contains(got, CoworkMarkerRefusedMessage) {
		t.Fatalf("refused marker: stderr %q, want the missing and the refused-marker sentences", got)
	}
	if err := os.Remove(filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := RunCowork(dataDir, launcher, "PreToolUse", strings.NewReader("{}"), &stdout, &stderr); code != 0 ||
		stdout.String() != CoworkUninstalledJSON("PreToolUse", true)+"\n" || stderr.Len() != 0 {
		t.Fatalf("honoured marker: exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

// The marker's folder must also keep other accounts from adding or renaming
// entries, and the marker must have one link (cowork-1-0-8 GAP-0085, review S1).
func TestCoworkMarkerSecurityRefusesWritableFoldersAndLinkedMarkers(t *testing.T) {
	const current = "S-1-5-21-1-2-3-1001"
	const other = "S-1-5-21-1-2-3-1002"
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	const profile = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + current + ")"
	const ownMarker = "O:" + current + "D:P(A;;FA;;;" + current + ")"
	for _, tc := range []struct {
		name, marker, folder string
		links                uint32
		want                 bool
	}{
		{"benign: own marker in own profile", ownMarker, "O:" + current + profile, 1, true},
		{"benign: Administrators-owned profile with CREATOR OWNER inherit-only",
			ownMarker, "O:BA" + profile + "(A;OICIIO;FA;;;CO)", 1, true},
		{"benign: OWNER RIGHTS and TrustedInstaller writers, Users read, a deny ACE",
			ownMarker, "O:SY" + profile + "(A;OICI;FA;;;OW)(A;OICI;FA;;;" + trustedInstaller + ")(A;OICI;0x1200a9;;;BU)(D;OICI;0x10000;;;AU)", 1, true},
		{"benign: SYSTEM-owned marker with one link", "O:SYD:P(A;;FA;;;SY)", "O:" + current + profile, 1, true},
		{"NULL DACL", ownMarker, "O:" + current + "D:NO_ACCESS_CONTROL", 1, false},
		{"no DACL", ownMarker, "O:" + current, 1, false},
		{"Authenticated Users Modify", ownMarker, "O:BA" + profile + "(A;OICI;0x1301bf;;;AU)", 1, false},
		{"Users Full Control", ownMarker, "O:BA" + profile + "(A;OICI;FA;;;BU)", 1, false},
		{"Users may add a file", ownMarker, "O:" + current + profile + "(A;;0x2;;;BU)", 1, false},
		{"Authenticated Users inherit-only generic all", ownMarker, "O:" + current + profile + "(A;OICIIO;GA;;;AU)", 1, false},
		{"hard-linked marker owned by SYSTEM", "O:SYD:P(A;;FA;;;SY)", "O:" + current + profile, 2, false},
		{"renamed Administrators-owned file in a folder another account may write",
			"O:BAD:P(A;;FA;;;BA)", "O:" + current + profile + "(A;OICI;0x1301bf;;;" + other + ")", 1, false},
		{"marker owned by another account", "O:" + other + "D:P(A;;FA;;;" + other + ")", "O:" + current + profile, 1, false},
		{"folder owned by another account", ownMarker, "O:" + other + profile, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			marker, err := windows.SecurityDescriptorFromString(tc.marker)
			if err != nil {
				t.Fatal(err)
			}
			folder, err := windows.SecurityDescriptorFromString(tc.folder)
			if err != nil {
				t.Fatal(err)
			}
			if got := coworkMarkerSecurityTrusted(marker, folder, tc.links, current); got != tc.want {
				t.Fatalf("coworkMarkerSecurityTrusted(%q, %q, %d) = %v, want %v", tc.marker, tc.folder, tc.links, got, tc.want)
			}
		})
	}
}
