//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"golang.org/x/sys/windows"
)

// g582 review 3 S2: the way out of a refused DefenseClaw policy file is to
// delete it and run Setup /ensure, because an identical rewrite keeps the
// old file object, and a handle another account opened while it could write
// the file keeps working on it (GAP-0561). These rows pin both halves: the
// writer keeps the object for identical bytes, writes a new object once the
// file is gone, and the install path writes the Claude Code record and
// drop-in, and the Cursor guard, new after they are deleted.

func gap633FileID(t *testing.T, path string) [3]uint32 {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		t.Fatal(err)
	}
	return [3]uint32{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}
}

func TestWindowsManagedPolicyWriterWritesAFreshObjectOnlyAfterTheFileIsDeleted(t *testing.T) {
	requireGAP633Elevated(t)
	setGAP633Profile(t, true, nil)
	path := filepath.Join(t.TempDir(), windowsManagedRuntimeSelectorFile)
	data := []byte("{\"schema_version\":1}\n")
	if err := writeWindowsManagedFile(path, data, true); err != nil {
		t.Fatal(err)
	}
	first := gap633FileID(t, path)
	// A handle opened while the file was writable stays open (shared for
	// delete, or the delete below names the holder instead).
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	held, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(held)
	if err := writeWindowsManagedFile(path, data, true); err != nil {
		t.Fatal(err)
	}
	if gap633FileID(t, path) != first {
		t.Fatal("an identical rewrite replaced the file object; the documented way out would not need the delete")
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("delete with a handle open (FILE_SHARE_DELETE): %v", err)
	}
	if err := writeWindowsManagedFile(path, data, true); err != nil {
		t.Fatalf("write after the delete: %v", err)
	}
	if gap633FileID(t, path) == first {
		t.Fatal("the write after the delete reused the old file object")
	}
	if err := validateWindowsManagedMachineFileDescriptor(path, true); err != nil {
		t.Fatalf("the new object is not canonical: %v", err)
	}
}

func TestWindowsClaudeManagedPolicyIsWrittenNewAfterTheRecordAndDropInAreDeleted(t *testing.T) {
	requireGAP633Elevated(t)
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{"allowManagedHooksOnly": true})
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(filepath.Dir(fixture.policyPath), windowsClaudeManagedStateFile)
	stateID, policyID := gap633FileID(t, statePath), gap633FileID(t, fixture.policyPath)
	for _, path := range []string{statePath, fixture.policyPath} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Install(context.Background(), windowsManagedInstallOptions(fixture)); err != nil {
		t.Fatalf("install after deleting the record and the drop-in: %v", err)
	}
	if gap633FileID(t, statePath) == stateID || gap633FileID(t, fixture.policyPath) == policyID {
		t.Fatal("the reinstall did not write new file objects")
	}
	if _, active, err := ReadWindowsClaudeManagedPolicyTargets(); err != nil || !active {
		t.Fatalf("the rewritten policy is not active: active=%t err=%v", active, err)
	}
}

func TestWindowsCursorGuardIsWrittenNewAfterItsStateReceiptAndAdapterAreDeleted(t *testing.T) {
	requireGAP633Elevated(t)
	hook := `C:\Program Files\Cisco\DefenseClaw\defenseclaw-hook.exe`
	paths := installWindowsCursorStandaloneGuardForTest(t, hook, false)
	stateID, receiptID := gap633FileID(t, paths.State), gap633FileID(t, paths.Receipt)
	// The state record, the receipt and the adapter go together: an adapter
	// left without its record is refused as unowned.
	for _, path := range []string{paths.State, paths.Receipt, paths.Adapter} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := EnsureWindowsStandaloneCursorManagedPolicy(connector.SetupOpts{
		APIAddr: "127.0.0.1:18970", HookExecutable: hook,
	}); err != nil {
		t.Fatalf("ensure after deleting the Cursor state, receipt and adapter: %v", err)
	}
	if gap633FileID(t, paths.State) == stateID || gap633FileID(t, paths.Receipt) == receiptID {
		t.Fatal("ensure did not write new Cursor file objects")
	}
	if _, active, err := ReadWindowsCursorManagedPolicyTargets(); err != nil || !active {
		t.Fatalf("the rewritten Cursor guard is not active: active=%t err=%v", active, err)
	}
}
