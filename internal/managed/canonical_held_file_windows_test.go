//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// GAP-0763: on standalone an in-place re-stamp of a recorded content file is
// one transaction on one handle. The handle is opened so that no other
// program can write or delete the object under it (a holder with write or
// delete access, or one that does not share read, makes the open fail), links
// are checked on it, the descriptor is judged on it, and only then is
// anything written. A holder stops the repair before the first write, and the
// refusal names the file.

// holdFileForTest opens path the way a program that keeps a file would, and
// returns the closer. share is the share mode it grants others.
func holdFileForTest(t *testing.T, path string, access, share uint32) func() {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	closed := false
	closer := func() {
		if !closed {
			closed = true
			_ = windows.CloseHandle(handle)
		}
	}
	t.Cleanup(closer)
	return closer
}

var heldHolders = []struct {
	name          string
	access, share uint32
	deleteOnly    bool // a holder the delete-only check of every standalone repair already catches
}{
	{name: "a DELETE handle without delete sharing", access: windows.DELETE | windows.FILE_READ_ATTRIBUTES, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE, deleteOnly: true},
	{name: "a write handle", access: windows.FILE_WRITE_DATA | windows.FILE_READ_ATTRIBUTES, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE},
	{name: "a read handle that does not share read", access: windows.FILE_READ_DATA, share: windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE},
}

func heldTestOptions() CanonicalOptions {
	return CanonicalOptions{Quiet: true, AllowUntrustedOwnerTransfer: true, GatewayServiceAccount: sameHandleGateway}
}

func TestStandaloneRepairRefusesAFileAnotherProgramHolds(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	for _, kind := range []ObjectKind{ObjectAdminFile, ObjectConfigFile} {
		for _, holder := range heldHolders {
			t.Run(string(kind)+" with "+holder.name, func(t *testing.T) {
				pinTrustProfileForTest(t, true)
				path := sameHandleFile(t, t.TempDir(), "record.json", sameHandleTrustedDrift)
				before := privilegedDescriptorForTest(t, path)
				closeHolder := holdFileForTest(t, path, holder.access, holder.share)

				result, err := EnsureCanonical(path, kind, heldTestOptions())
				if err != nil {
					t.Fatal(err)
				}
				if result.Outcome == CanonicalRepaired || result.Outcome == CanonicalOK {
					t.Fatalf("outcome = %+v; want the held file refused", result)
				}
				if !strings.Contains(result.RepairError, heldFileRefusal) || !strings.Contains(result.RepairError, path) {
					t.Fatalf("repair error = %q; want the refusal naming %s", result.RepairError, path)
				}
				if after := privilegedDescriptorForTest(t, path); after != before {
					t.Fatalf("the refused repair changed the descriptor: %s -> %s", before, after)
				}

				closeHolder()
				result, err = EnsureCanonical(path, kind, heldTestOptions())
				if err != nil || result.Outcome != CanonicalRepaired {
					t.Fatalf("after the holder let go: %+v, %v; want the repair", result, err)
				}
				if after := privilegedDescriptorForTest(t, path); strings.Contains(after, ";;;BU)") {
					t.Fatalf("descriptor after the repair = %s, want the canonical one", after)
				}
			})
		}
	}
}

// A runtime file the gateway keeps open for write (the audit database, a log)
// is judged with the delete-only check it always had: a live gateway never
// blocks the guardian's repair, a DELETE handle still does.
func TestStandaloneRepairOfARuntimeFileOnlyRefusesADeleteHolder(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	for _, holder := range heldHolders {
		t.Run(holder.name, func(t *testing.T) {
			pinTrustProfileForTest(t, true)
			// What the same repair does with nobody holding the file.
			free := sameHandleFile(t, t.TempDir(), "audit.db", sameHandleTrustedDrift)
			baseline, err := EnsureCanonical(free, ObjectRuntimeFile, heldTestOptions())
			if err != nil {
				t.Fatal(err)
			}
			path := sameHandleFile(t, t.TempDir(), "audit.db", sameHandleTrustedDrift)
			before := privilegedDescriptorForTest(t, path)
			holdFileForTest(t, path, holder.access, holder.share)

			result, err := EnsureCanonical(path, ObjectRuntimeFile, heldTestOptions())
			if err != nil {
				t.Fatal(err)
			}
			after := privilegedDescriptorForTest(t, path)
			if holder.deleteOnly {
				if result.Outcome == CanonicalRepaired || after != before || !strings.Contains(result.RepairError, heldFileRefusal) {
					t.Fatalf("a delete holder: %+v, descriptor %s -> %s; want the refusal and no change", result, before, after)
				}
				return
			}
			if result.Outcome != baseline.Outcome || strings.Contains(result.RepairError, heldFileRefusal) {
				t.Fatalf("a %s on a runtime file changed the repair: %+v, want %+v", holder.name, result, baseline)
			}
		})
	}
}

// The check is made before any write whatever the cause: an open that fails
// with a sharing violation (injected) leaves the descriptor byte for byte.
func TestStandaloneRepairWritesNothingWhenTheOpenReportsAHolder(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	pinTrustProfileForTest(t, true)
	path := sameHandleFile(t, t.TempDir(), "record.json", sameHandleTrustedDrift)
	before := privilegedDescriptorForTest(t, path)
	previous := canonicalOpenForStamp
	t.Cleanup(func() { canonicalOpenForStamp = previous })
	opens := 0
	canonicalOpenForStamp = func(target string, access, share uint32) (windows.Handle, error) {
		if strings.EqualFold(target, path) {
			opens++
			return windows.InvalidHandle, windows.ERROR_SHARING_VIOLATION
		}
		return previous(target, access, share)
	}

	result, err := EnsureCanonical(path, ObjectAdminFile, heldTestOptions())
	canonicalOpenForStamp = previous
	if err != nil {
		t.Fatal(err)
	}
	if opens != 1 || result.Outcome == CanonicalRepaired || !strings.Contains(result.RepairError, heldFileRefusal) {
		t.Fatalf("opens = %d, result = %+v; want one refused open and no repair", opens, result)
	}
	if after := privilegedDescriptorForTest(t, path); after != before {
		t.Fatalf("a refused open was followed by a write: %s -> %s", before, after)
	}
}

// A file with a second hard link is refused on the same handle with the
// descriptor unchanged (the case the first run of GAP-0763 handled).
func TestStandaloneRepairRefusesAFileWithAnotherHardLinkAndWritesNothing(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	pinTrustProfileForTest(t, true)
	path := sameHandleFile(t, t.TempDir(), "record.json", sameHandleTrustedDrift)
	if err := os.Link(path, path+".sibling"); err != nil {
		t.Skipf("hard links are not available here: %v", err)
	}
	before := privilegedDescriptorForTest(t, path)

	result, err := EnsureCanonical(path, ObjectAdminFile, heldTestOptions())
	// The structural check refuses a second link as an error, before any write.
	if err == nil && (result.Outcome == CanonicalRepaired || result.Outcome == CanonicalOK) {
		t.Fatalf("outcome = %+v; want the linked file refused", result)
	}
	if err != nil && !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("err = %v; want the hard link named", err)
	}
	if after := privilegedDescriptorForTest(t, path); after != before {
		t.Fatalf("the refused repair changed the descriptor: %s -> %s", before, after)
	}
}

// Secure Client keeps the base stamp: the repair handle shares everything, so
// a holder does not stop it.
func TestSecureClientRepairIgnoresAHolderAsBefore(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	pinTrustProfileForTest(t, false)
	for _, holder := range heldHolders {
		t.Run(holder.name, func(t *testing.T) {
			path := sameHandleFile(t, t.TempDir(), "record.json", sameHandleTrustedDrift)
			holdFileForTest(t, path, holder.access, holder.share)
			result, err := EnsureCanonical(path, ObjectAdminFile, heldTestOptions())
			if err != nil || result.Outcome != CanonicalRepaired {
				t.Fatalf("Secure Client with %s: %+v, %v; want the base repair", holder.name, result, err)
			}
		})
	}
}

// StampStandaloneTrustedObject holds a recorded content file the same way.
func TestStampStandaloneTrustedObjectRefusesAFileAnotherProgramHolds(t *testing.T) {
	requireHiddenDescriptorElevated(t)
	t.Setenv(TrustStrictAncestorsEnv, "")
	const canonical = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, holder := range heldHolders {
		t.Run(holder.name, func(t *testing.T) {
			path := sameHandleFile(t, t.TempDir(), "targets.yaml", sameHandleTrustedDrift)
			before := privilegedDescriptorForTest(t, path)
			closeHolder := holdFileForTest(t, path, holder.access, holder.share)

			err := StampStandaloneTrustedObject(path, ObjectAdminFile, canonical)
			if err == nil || !strings.Contains(err.Error(), heldFileRefusal) || !strings.Contains(err.Error(), path) {
				t.Fatalf("stamp = %v; want the refusal naming %s", err, path)
			}
			var drift *StandaloneContentDriftError
			if errors.As(err, &drift) {
				t.Fatalf("a held file is not content drift: %v", err)
			}
			if after := privilegedDescriptorForTest(t, path); after != before {
				t.Fatalf("the refused stamp changed the descriptor: %s -> %s", before, after)
			}
			closeHolder()
			if err := StampStandaloneTrustedObject(path, ObjectAdminFile, canonical); err != nil {
				t.Fatalf("stamp after the holder let go: %v", err)
			}
			if after := privilegedDescriptorForTest(t, path); strings.Contains(after, ";;;BU)") {
				t.Fatalf("descriptor = %s, want the canonical one", after)
			}
		})
	}
}
