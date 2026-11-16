//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"strings"
	"testing"
)

func TestAdministratorWriterGroupNamesWheelAndAdminOnly(t *testing.T) {
	if StandaloneTrustScope() {
		t.Skip("a standalone trust scope accepts no administrator group")
	}
	for gid, want := range map[uint32]bool{darwinWheelGID: true, darwinAdminGID: true, 20: false, 12: false, 501: false} {
		if got := administratorWriterGroup(gid); got != want {
			t.Fatalf("administratorWriterGroup(%d) = %v, want %v", gid, got, want)
		}
	}
}

// An ancestor of the install marker that an administrator made group-writable
// for admin (secureclient-reperm: /opt/cisco/secureclient 0775 root:admin)
// passes the mode check and is reported. The same bit for another group, any
// other-write bit, and the admin bit on the marker folder itself stay fatal.
// The temp folder is the test user's, so the owner check still stops it after
// the mode check; the error says which check did. Run as root, the folder is
// root-owned and the accepted bit leaves no error at all.
func TestInstallMarkerAncestorAcceptsOnlyAnAdministratorGroupWriteBit(t *testing.T) {
	if StandaloneTrustScope() {
		t.Skip("a standalone trust scope accepts no administrator group")
	}
	// The strict-ancestor switch makes every ancestor verdict fatal; this test
	// is about the default rule.
	t.Setenv(TrustStrictAncestorsEnv, "")
	dir := t.TempDir()
	if err := os.Chown(dir, -1, darwinAdminGID); err != nil {
		t.Skipf("the test user cannot give a folder to the admin group: %v", err)
	}
	var reported []string
	previous := ReportTrustAdvisory
	ReportTrustAdvisory = func(path, _, reason string) { reported = append(reported, path+": "+reason) }
	t.Cleanup(func() { ReportTrustAdvisory = previous })
	ancestor := func() error {
		return validateTrustedPathElementWriters(dir, true, "install marker", false, administratorWriterGroup)
	}
	chmod := func(mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}

	chmod(0o775)
	err := ancestor()
	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("admin group write on a root-owned ancestor: got %v, want it accepted", err)
		}
	} else if err == nil || strings.Contains(err.Error(), "writable permissions") || !strings.Contains(err.Error(), "owner uid") {
		t.Fatalf("admin group write on an ancestor: got %v, want only the owner check to fail", err)
	}
	if len(reported) != 1 || !strings.Contains(reported[0], "0775") {
		t.Fatalf("the accepted admin group write bit was not reported once: %q", reported)
	}

	chmod(0o777)
	if err := ancestor(); err == nil || !strings.Contains(err.Error(), "writable permissions") {
		t.Fatalf("other write on an ancestor: got %v, want a writable-permissions verdict", err)
	}

	chmod(0o775)
	if err := validateTrustedPathElement(dir, true, "install marker", false); err == nil || !strings.Contains(err.Error(), "writable permissions") {
		t.Fatalf("admin group write on the marker folder itself: got %v, want a writable-permissions verdict", err)
	}

	if gid := os.Getgid(); gid != darwinAdminGID && gid != darwinWheelGID {
		if err := os.Chown(dir, -1, gid); err != nil {
			t.Fatal(err)
		}
		if err := ancestor(); err == nil || !strings.Contains(err.Error(), "writable permissions") {
			t.Fatalf("group %d write on an ancestor: got %v, want a writable-permissions verdict", gid, err)
		}
	}
}
