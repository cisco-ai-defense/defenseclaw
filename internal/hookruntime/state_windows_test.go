// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const (
	stableRuntimeTransactionOne = "00112233445566778899aabbccddeeff"
	stableRuntimeTransactionTwo = "ffeeddccbbaa99887766554433221100"
)

func testRuntimePaths(t *testing.T) Paths {
	t.Helper()
	root := filepath.Join(t.TempDir(), "DefenseClaw", "HookRuntime")
	return Paths{
		Root:     root,
		Launcher: filepath.Join(root, LauncherName),
		State:    filepath.Join(root, StateName),
	}
}

func writeRuntimeSource(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), LauncherName)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRuntimeGateway(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, GatewayName)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestStableRuntimeFailsClosedForTamperedLauncherAndState(t *testing.T) {
	paths := testRuntimePaths(t)
	dataRoot := filepath.Join(t.TempDir(), "data")
	gateway := writeRuntimeGateway(t, "MZ-trusted-gateway")
	source := writeRuntimeSource(t, "MZ-trusted")
	if err := publishAt(paths, source, source, gateway, dataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Launcher, []byte("MZ-tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("tampered launcher was accepted: state=%+v recognized=%v err=%v", state, recognized, err)
	}

	source = writeRuntimeSource(t, "MZ-restored")
	if err := publishAt(paths, source, source, gateway, dataRoot, stableRuntimeTransactionTwo); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(paths.State)
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.Replace(string(body), `"status": "active"`, `"status": "unknown"`, 1))
	if err := os.WriteFile(paths.State, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("tampered state was accepted: state=%+v recognized=%v err=%v", state, recognized, err)
	}

	outside := filepath.Join(t.TempDir(), LauncherName)
	if _, recognized, err := readTrustedAt(paths, outside); recognized || err != nil {
		t.Fatalf("outside executable recognized=%v err=%v", recognized, err)
	}
}

func addDACLDrift(t *testing.T, path string, driftMask windows.ACCESS_MASK) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, entry := range []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{sid: user.User.Sid, mask: windows.GENERIC_ALL},
		{sid: system, mask: windows.GENERIC_ALL},
		{sid: users, mask: driftMask},
	} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: entry.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(entry.sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		t.Fatal(err)
	}
}

func TestStableRuntimeLegacyActiveStateRemainsReadableWithoutColdStartAuthority(t *testing.T) {
	paths := testRuntimePaths(t)
	state := State{
		SchemaVersion:  LegacySchemaVersion,
		Status:         StatusActive,
		RuntimeRoot:    paths.Root,
		LauncherPath:   paths.Launcher,
		LauncherSHA256: strings.Repeat("a", 64),
		DataRoot:       filepath.Join(t.TempDir(), "legacy-data"),
		TransactionID:  stableRuntimeTransactionOne,
	}
	if err := state.Validate(paths); err != nil {
		t.Fatalf("legacy active state rejected during upgrade: %v", err)
	}
	if state.ColdStartCapable() {
		t.Fatal("legacy state gained gateway start authority without a recorded identity")
	}
}

func TestLockVerifiedGatewayPinsDigestAndReplacement(t *testing.T) {
	paths := testRuntimePaths(t)
	gateway := writeRuntimeGateway(t, "MZ-pinned-gateway")
	source := writeRuntimeSource(t, "MZ-hook")
	if err := publishAt(
		paths,
		source,
		source,
		gateway,
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	state, _, err := readTrustedAt(paths, paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := LockVerifiedGateway(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateway, []byte("MZ-replacement"), 0o700); err == nil {
		_ = locked.Close()
		t.Fatal("gateway replacement succeeded while verified image handle was pinned")
	}
	if err := locked.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gateway, []byte("MZ-tampered-after-close"), 0o700); err != nil {
		t.Fatal(err)
	}
	if locked, err := LockVerifiedGateway(state); err == nil {
		_ = locked.Close()
		t.Fatal("tampered gateway matched installer-recorded digest")
	}
}
