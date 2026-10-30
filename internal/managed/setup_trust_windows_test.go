//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func currentTestUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return user.User.Sid
}

// setupTestTree builds <temp>\parent\leaf.bin where parent grants Users full
// control (an untrusted ancestor) and the leaf is protected for SYSTEM,
// Administrators and the test user.
func setupTestTree(t *testing.T) (parent, leaf string, user *windows.SID) {
	t.Helper()
	user = currentTestUserSID(t)
	parent = filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	setTestFileDACL(t, parent, testDACL(t, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+user.String()+")(A;;FA;;;BU)"), true)
	leaf = filepath.Join(parent, "leaf.bin")
	if err := os.WriteFile(leaf, []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	setTestFileDACL(t, leaf, testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user.String()+")"), true)
	return parent, leaf, user
}

func TestValidateSetupPathAcceptsUntrustedAncestor(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	advisoryLogDedupe.reset()
	parent, leaf, user := setupTestTree(t)
	advisories := captureTrustAdvisories(t)
	var accepted []string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		if marker == MarkerAccept {
			accepted = append(accepted, fields["path"])
		}
	}
	t.Cleanup(func() { ReportResilienceEvent = previous })

	if err := ValidateSetupPathWithWriter(leaf, "setup test", SetupPathFile, user); err != nil {
		t.Fatalf("untrusted ancestor refused the Setup rule: %v", err)
	}
	if !reportsMention(*advisories, parent, "untrusted Windows principal") {
		t.Fatalf("advisories = %v, want one for %s", *advisories, parent)
	}
	found := false
	for _, path := range accepted {
		found = found || strings.EqualFold(path, parent)
	}
	if !found {
		t.Fatalf("defenseclaw_accept paths = %v, want %s", accepted, parent)
	}
	// The general rule keeps a foreign ancestor fatal.
	if err := ValidateTrustedFilePath(leaf, "setup test"); err == nil {
		t.Fatal("ValidateTrustedFilePath accepted the leaf it should refuse (leaf owner and foreign ancestor)")
	}
}

func TestValidateSetupPathHonoursStrictPin(t *testing.T) {
	_, leaf, user := setupTestTree(t)
	t.Setenv(TrustStrictAncestorsEnv, "1")
	if err := ValidateSetupPathWithWriter(leaf, "setup test", SetupPathFile, user); err == nil ||
		!strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("strict pin error = %v, want the ancestor verdict", err)
	}
}

func TestValidateSetupPathKeepsLeafStrict(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	_, leaf, user := setupTestTree(t)
	setTestFileDACL(t, leaf, testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user.String()+")(A;;GW;;;BU)"), true)
	if err := ValidateSetupPathWithWriter(leaf, "setup test", SetupPathFile, user); err == nil ||
		!strings.Contains(err.Error(), "untrusted Windows principal") {
		t.Fatalf("leaf untrusted writer error = %v", err)
	}
	if windowsAdminEquivalentOwner(user) {
		return // an administrator-owned leaf is accepted and logged by design
	}
	setTestFileDACL(t, leaf, testDACL(t, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;"+user.String()+")"), true)
	if err := ValidateSetupPath(leaf, "setup test", SetupPathFile); err == nil ||
		!strings.Contains(err.Error(), "owner") {
		t.Fatalf("leaf owned by a non-administrator without a pinned writer = %v", err)
	}
}

func TestValidateSetupPathStructureIsFatal(t *testing.T) {
	t.Setenv(TrustStrictAncestorsEnv, "")
	parent, leaf, user := setupTestTree(t)
	link := filepath.Join(parent, "second-link.bin")
	if err := os.Link(leaf, link); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	for _, path := range []string{leaf, link} {
		if err := ValidateSetupPathWithWriter(path, "setup test", SetupPathFile, user); err == nil ||
			!strings.Contains(err.Error(), "hard links") {
			t.Fatalf("%s: hard link error = %v", path, err)
		}
		if err := ValidateSetupPathStructure(path, "setup test", SetupPathFile); err == nil {
			t.Fatalf("%s: structure check accepted a second hard link", path)
		}
	}
	if err := ValidateSetupPathWithWriter(parent, "setup test", SetupPathFile, user); err == nil {
		t.Fatal("a directory passed as a file")
	}
	target := t.TempDir()
	junction := filepath.Join(t.TempDir(), "junction")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	if err := ValidateSetupPathStructure(junction, "setup test", SetupPathDirectory); err == nil ||
		!strings.Contains(err.Error(), "reparse") {
		t.Fatalf("junction error = %v", err)
	}
	if err := ValidateSetupPathStructure(filepath.Join(junction, "child"), "setup test", SetupPathDirectory); err == nil {
		t.Fatal("a path below a junction passed the structure check")
	}
}

func TestPinSetupPathBlocksReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "staged.bin")
	if err := os.WriteFile(path, []byte("staged payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	pin, err := PinSetupPath(path, SetupPathFile)
	if err != nil {
		t.Fatalf("PinSetupPath: %v", err)
	}
	defer pin.Close()
	if err := os.WriteFile(path, []byte("replaced"), 0o600); err == nil {
		t.Fatal("a pinned file was rewritten")
	}
	if err := os.Rename(path, path+".moved"); err == nil {
		t.Fatal("a pinned file was renamed")
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("a pinned file was deleted")
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatalf("a pinned file refused a reader: %v", err)
	}
	_ = reader.Close()
	body, err := io.ReadAll(pin)
	if err != nil || string(body) != "staged payload" {
		t.Fatalf("read through pin = %q, %v", body, err)
	}
	if err := pin.Rewind(); err != nil {
		t.Fatalf("Rewind: %v", err)
	}
	if same, err := pin.Matches(path); err != nil || !same {
		t.Fatalf("Matches = %t, %v", same, err)
	}
	if err := pin.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := os.Rename(path, path+".moved"); err != nil {
		t.Fatalf("rename after release: %v", err)
	}

	stage := filepath.Join(directory, "stage")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	stagePin, err := PinSetupPath(stage, SetupPathDirectory)
	if err != nil {
		t.Fatalf("pin directory: %v", err)
	}
	defer stagePin.Close()
	if err := os.WriteFile(filepath.Join(stage, "scratch.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("a pinned directory refused a new child: %v", err)
	}
	if err := os.Rename(stage, stage+".moved"); err == nil {
		t.Fatal("a pinned directory was renamed")
	}
	if _, err := PinSetupPath(stage, SetupPathFile); err == nil {
		t.Fatal("a directory was pinned as a file")
	}
}

func TestRemoveSetupTreeNeverFollowsReparsePoints(t *testing.T) {
	outside := t.TempDir()
	keep := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(keep, []byte("outside"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	root := filepath.Join(t.TempDir(), "stage")
	nested := filepath.Join(root, "scratch", "deep")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	readOnly := filepath.Join(nested, "read-only.txt")
	if err := os.WriteFile(readOnly, []byte("x"), 0o400); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	junction := filepath.Join(root, "scratch", "escape")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, outside).CombinedOutput(); err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	if err := RemoveSetupTree(junction); err == nil || !strings.Contains(err.Error(), "reparse point root") {
		t.Fatalf("reparse root error = %v", err)
	}
	if err := RemoveSetupTreeIfSame(root, SetupFileID{}); err == nil ||
		!strings.Contains(err.Error(), "replaced") {
		t.Fatalf("ID mismatch error = %v", err)
	}
	id, err := SetupFileIDOf(root)
	if err != nil {
		t.Fatalf("SetupFileIDOf: %v", err)
	}
	if err := RemoveSetupTreeIfSame(root, id); err != nil {
		t.Fatalf("RemoveSetupTreeIfSame: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("stage survived removal: %v", err)
	}
	if body, err := os.ReadFile(keep); err != nil || string(body) != "outside" {
		t.Fatalf("removal followed the junction: %q, %v", body, err)
	}
	if err := RemoveSetupTree(root); err != nil {
		t.Fatalf("removing a missing tree: %v", err)
	}
}

func TestCollectSetupTreePostOrderSchedulesChildrenFirst(t *testing.T) {
	root := filepath.Join(t.TempDir(), "stage")
	if err := os.MkdirAll(filepath.Join(root, "scratch"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	file := filepath.Join(root, "scratch", "a.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var ordered []string
	if err := collectSetupTreePostOrder(root, 0, &ordered); err != nil {
		t.Fatalf("collect: %v", err)
	}
	want := []string{file, filepath.Join(root, "scratch"), root}
	if len(ordered) != len(want) {
		t.Fatalf("order = %v, want %v", ordered, want)
	}
	for index := range want {
		if ordered[index] != want[index] {
			t.Fatalf("order = %v, want %v", ordered, want)
		}
	}
}

func ageSetupTestDirectory(t *testing.T, path string, age time.Duration) {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer windows.CloseHandle(handle)
	stamp := windows.NsecToFiletime(time.Now().Add(-age).UnixNano())
	if err := windows.SetFileTime(handle, &stamp, &stamp, &stamp); err != nil {
		t.Fatalf("SetFileTime: %v", err)
	}
}

func TestSweepSetupLeftoversRemovesOnlyExpiredCapabilityDirectories(t *testing.T) {
	advisoryLogDedupe.reset()
	root := t.TempDir()
	const capability = "0123456789abcdef0123456789abcdef"
	expired := filepath.Join(root, SetupStagePrefix+capability)
	young := filepath.Join(root, SetupPowerShellTempPrefix+capability)
	foreign := filepath.Join(root, "DefenseClaw-Keep-"+capability)
	for _, dir := range []string{expired, young, foreign} {
		if err := os.MkdirAll(filepath.Join(dir, "scratch"), 0o700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
	}
	ageSetupTestDirectory(t, expired, 3*time.Hour)
	ageSetupTestDirectory(t, foreign, 3*time.Hour)
	var recovered []string
	previous := ReportResilienceEvent
	ReportResilienceEvent = func(marker string, fields map[string]string) {
		if marker == MarkerRecover {
			recovered = append(recovered, fields["path"])
		}
	}
	t.Cleanup(func() { ReportResilienceEvent = previous })

	SweepSetupLeftovers([]string{root, filepath.Join(root, "missing")}, SetupLeftoverPrefixes(), time.Now())
	if _, err := os.Lstat(expired); !os.IsNotExist(err) {
		t.Fatalf("expired leftover survived: %v", err)
	}
	for _, kept := range []string{young, foreign} {
		if _, err := os.Lstat(kept); err != nil {
			t.Fatalf("%s was swept: %v", kept, err)
		}
	}
	if len(recovered) != 1 || !strings.EqualFold(recovered[0], expired) {
		t.Fatalf("defenseclaw_recover paths = %v", recovered)
	}
}

func TestCreateSetupObjectsAreAdministratorsOwned(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("assigning Administrators as owner requires an elevated token")
	}
	root := t.TempDir()
	directory := filepath.Join(root, "scratch")
	if err := CreateSetupDirectory(directory); err != nil {
		t.Fatalf("CreateSetupDirectory: %v", err)
	}
	file, err := CreateSetupFile(filepath.Join(root, "staged.bin"))
	if err != nil {
		t.Fatalf("CreateSetupFile: %v", err)
	}
	if _, err := file.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = file.Close()
	if _, err := CreateSetupFile(filepath.Join(root, "staged.bin")); err == nil {
		t.Fatal("CreateSetupFile replaced an existing file")
	}
	for _, path := range []string{directory, filepath.Join(root, "staged.bin")} {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("GetNamedSecurityInfo: %v", err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			t.Fatalf("%s owner = %v, %v; want Administrators", path, owner, err)
		}
	}
}
