// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
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

func TestStableRuntimePublishDisableAndReinstall(t *testing.T) {
	paths := testRuntimePaths(t)
	firstSource := writeRuntimeSource(t, "MZ-first-stable-hook")
	firstGateway := writeRuntimeGateway(t, "MZ-first-gateway")
	firstDataRoot := filepath.Join(t.TempDir(), "first-data")
	if err := publishAt(paths, firstSource, firstSource, firstGateway, firstDataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatalf("first publish: %v", err)
	}

	first, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || !first.Active() {
		t.Fatalf("first active state: state=%+v recognized=%v err=%v", first, recognized, err)
	}
	if !samePath(first.DataRoot, firstDataRoot) || first.TransactionID != stableRuntimeTransactionOne {
		t.Fatalf("first active generation = %+v", first)
	}
	if !first.ColdStartCapable() || !samePath(first.GatewayPath, firstGateway) {
		t.Fatalf("first generation lacks gateway cold-start identity: %+v", first)
	}
	launcherBeforeUninstall, err := os.ReadFile(paths.Launcher)
	if err != nil {
		t.Fatal(err)
	}

	if err := disableAt(paths, stableRuntimeTransactionTwo); err != nil {
		t.Fatalf("disable: %v", err)
	}
	disabled, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || disabled.Active() || disabled.Status != StatusDisabled {
		t.Fatalf("disabled state: state=%+v recognized=%v err=%v", disabled, recognized, err)
	}
	if disabled.DataRoot != "" || disabled.TransactionID != stableRuntimeTransactionTwo {
		t.Fatalf("disabled generation retained active data: %+v", disabled)
	}
	launcherAfterUninstall, err := os.ReadFile(paths.Launcher)
	if err != nil {
		t.Fatalf("stable launcher was removed by uninstall: %v", err)
	}
	if string(launcherAfterUninstall) != string(launcherBeforeUninstall) {
		t.Fatal("disable mutated the stable launcher")
	}
	// DELETEUSERDATA must not affect the launcher or its disabled state.
	if err := os.RemoveAll(firstDataRoot); err != nil {
		t.Fatal(err)
	}
	if afterDelete, _, err := readTrustedAt(paths, paths.Launcher); err != nil || afterDelete.Active() {
		t.Fatalf("DELETEUSERDATA changed disabled behavior: state=%+v err=%v", afterDelete, err)
	}

	secondSource := writeRuntimeSource(t, "MZ-second-stable-hook")
	secondGateway := writeRuntimeGateway(t, "MZ-second-gateway")
	secondDataRoot := filepath.Join(t.TempDir(), "second-data")
	if err := publishAt(paths, secondSource, secondSource, secondGateway, secondDataRoot, stableRuntimeTransactionOne); err != nil {
		t.Fatalf("reinstall publish: %v", err)
	}
	reinstalled, recognized, err := readTrustedAt(paths, paths.Launcher)
	if err != nil || !recognized || !reinstalled.Active() {
		t.Fatalf("reinstalled state: state=%+v recognized=%v err=%v", reinstalled, recognized, err)
	}
	if !samePath(reinstalled.DataRoot, secondDataRoot) || !samePath(reinstalled.GatewayPath, secondGateway) ||
		reinstalled.TransactionID != stableRuntimeTransactionOne {
		t.Fatalf("reinstalled generation = %+v", reinstalled)
	}
	launcherAfterReinstall, err := os.ReadFile(paths.Launcher)
	if err != nil || string(launcherAfterReinstall) != "MZ-second-stable-hook" {
		t.Fatalf("reinstall did not refresh launcher: %q err=%v", launcherAfterReinstall, err)
	}
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

func TestSetupPostureRepairsMalformedAndProtectionDriftedFailClosedState(t *testing.T) {
	for _, test := range []struct {
		name  string
		drift func(*testing.T, Paths)
	}{
		{
			name: "malformed-state",
			drift: func(t *testing.T, paths Paths) {
				if err := os.WriteFile(paths.State, []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "state-dacl",
			drift: func(t *testing.T, paths Paths) {
				addDACLDrift(t, paths.State, windows.GENERIC_READ)
				if err := safefile.ValidatePrivateFile(paths.State); err == nil {
					t.Fatal("DACL drift remained trusted by the launcher reader")
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			paths := testRuntimePaths(t)
			source := writeRuntimeSource(t, "MZ-setup-posture-hook")
			if err := publishAt(
				paths,
				source,
				source,
				writeRuntimeGateway(t, "MZ-setup-posture-gateway"),
				filepath.Join(t.TempDir(), "data"),
				stableRuntimeTransactionOne,
			); err != nil {
				t.Fatal(err)
			}
			test.drift(t, paths)

			state, recognized, err := ReadSetupPostureAt(paths, paths.Launcher)
			if err != nil || !recognized || state.Active() {
				t.Fatalf("setup posture = %+v, recognized=%t, error=%v", state, recognized, err)
			}
			if err := disableAt(paths, stableRuntimeTransactionTwo); err != nil {
				t.Fatalf("writer-side disable did not repair fail-closed state: %v", err)
			}
			disabled, recognized, err := readTrustedAt(paths, paths.Launcher)
			if err != nil || !recognized || disabled.Active() ||
				disabled.Status != StatusDisabled ||
				disabled.TransactionID != stableRuntimeTransactionTwo {
				t.Fatalf("repaired disabled state = %+v, recognized=%t, error=%v", disabled, recognized, err)
			}
		})
	}
}

func TestSetupPostureRejectsUntrustedWriteDACL(t *testing.T) {
	paths := testRuntimePaths(t)
	source := writeRuntimeSource(t, "MZ-untrusted-dacl-hook")
	if err := publishAt(
		paths,
		source,
		source,
		writeRuntimeGateway(t, "MZ-untrusted-dacl-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	addDACLDrift(t, paths.State, windows.GENERIC_WRITE)
	if _, recognized, err := ReadSetupPostureAt(paths, paths.Launcher); !recognized || err == nil {
		t.Fatalf("untrusted-write posture recognized=%t, error=%v", recognized, err)
	}
}

func TestSetupPostureRejectsReparseTopology(t *testing.T) {
	paths := testRuntimePaths(t)
	source := writeRuntimeSource(t, "MZ-reparse-hook")
	if err := publishAt(
		paths,
		source,
		source,
		writeRuntimeGateway(t, "MZ-reparse-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	aliasRoot := filepath.Join(t.TempDir(), "HookRuntime")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", aliasRoot, paths.Root).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v (%s)", err, output)
	}
	defer os.Remove(aliasRoot)
	alias := Paths{
		Root:     aliasRoot,
		Launcher: filepath.Join(aliasRoot, LauncherName),
		State:    filepath.Join(aliasRoot, StateName),
	}
	if _, recognized, err := ReadSetupPostureAt(alias, alias.Launcher); !recognized || err == nil {
		t.Fatalf("reparse posture recognized=%t, error=%v", recognized, err)
	}
}

func TestStableRuntimeMissingLauncherCannotReactivateDisabledState(t *testing.T) {
	paths := testRuntimePaths(t)
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	// Establish the same private directory contract the installer uses.
	source := writeRuntimeSource(t, "MZ-old")
	if err := publishAt(
		paths,
		source,
		source,
		writeRuntimeGateway(t, "MZ-gateway"),
		filepath.Join(t.TempDir(), "data"),
		stableRuntimeTransactionOne,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.Launcher); err != nil {
		t.Fatal(err)
	}
	if err := disableAt(paths, stableRuntimeTransactionTwo); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Launcher, []byte("MZ-copied-later"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state, recognized, err := readTrustedAt(paths, paths.Launcher); !recognized || err == nil || state.Active() {
		t.Fatalf("later launcher inherited stale active state: state=%+v recognized=%v err=%v", state, recognized, err)
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
