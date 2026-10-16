//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsManagedArtifactStampOfPath(t *testing.T, path string) (managedArtifactStamp, bool) {
	t.Helper()
	file, err := openWindowsManagedArtifactExclusive(path)
	if err != nil {
		t.Fatalf("open %s without writers: %v", path, err)
	}
	defer file.Close()
	return windowsManagedArtifactStamp(file)
}

func windowsManagedArtifactAttributeStampOfPath(t *testing.T, path string) managedArtifactStamp {
	t.Helper()
	file, err := openWindowsManagedArtifactExclusive(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stamp, ok := windowsManagedArtifactAttributeStamp(file)
	if !ok {
		t.Fatal("attribute-only stamp unavailable")
	}
	if stamp.USN != 0 {
		t.Fatalf("attribute-only stamp has USN %d, want zero", stamp.USN)
	}
	return stamp
}

func TestWindowsManagedArtifactAttributeStampFollowsFileAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	if err := os.WriteFile(path, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	first := windowsManagedArtifactAttributeStampOfPath(t, path)
	if err := os.WriteFile(path, []byte("release plus"), 0o600); err != nil {
		t.Fatal(err)
	}
	resized := windowsManagedArtifactAttributeStampOfPath(t, path)
	if resized.Size == first.Size {
		t.Fatalf("size did not move: %+v then %+v", first, resized)
	}
	written := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(path, written, written); err != nil {
		t.Fatal(err)
	}
	retimed := windowsManagedArtifactAttributeStampOfPath(t, path)
	if retimed.Written == resized.Written {
		t.Fatalf("write time did not move: %+v then %+v", resized, retimed)
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	hiddenAttributes := retimed.Attributes&^windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_ATTRIBUTE_HIDDEN
	if err := windows.SetFileAttributes(name, hiddenAttributes); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.SetFileAttributes(name, retimed.Attributes) })
	hidden := windowsManagedArtifactAttributeStampOfPath(t, path)
	if hidden.Attributes == retimed.Attributes {
		t.Fatalf("attributes did not move: %+v then %+v", retimed, hidden)
	}
}

// useWindowsManagedArtifactDigestSeams runs one test with the real Windows
// memo seams: the deny-write open, the stamp and the change-epoch close.
func useWindowsManagedArtifactDigestSeams(t *testing.T) (ends *int) {
	t.Helper()
	_, ends = useManagedArtifactDigestSeams(t,
		windowsManagedArtifactStamp,
		openWindowsManagedArtifactExclusive,
		endWindowsManagedArtifactChangeEpoch,
	)
	return ends
}

const managedArtifactDigestSentinel = "sha256:remembered"

// setManagedArtifactDigestSentinel replaces the remembered digest of path, so
// a later call that answers it proves the file was not read again.
func setManagedArtifactDigestSentinel(t *testing.T, path string) {
	t.Helper()
	managedArtifactDigests.Lock()
	defer managedArtifactDigests.Unlock()
	entry, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	if !ok {
		t.Fatal("a full read of an unwritten version was not remembered")
	}
	entry.digest = managedArtifactDigestSentinel
	managedArtifactDigests.entries[managedArtifactDigestKey(path)] = entry
}

// holdManagedArtifact opens path with access and every share mode, as any
// other reader might, until the end of the test.
func holdManagedArtifact(t *testing.T, path string, access uint32) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatalf("hold %s: %v", path, err)
	}
	t.Cleanup(func() { windows.CloseHandle(handle) })
}

var managedArtifactOtherHandles = []struct {
	name   string
	access uint32
}{
	{name: "read handle", access: windows.GENERIC_READ},
	{name: "attribute handle", access: windows.FILE_READ_ATTRIBUTES},
}

// rewriteKeepingTimes changes one byte of path in place, keeps its size and
// puts every time stamp back, as a writer hiding a change would.
func rewriteKeepingTimes(t *testing.T, path string, fill byte) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(attributes)
	var basic windowsManagedArtifactFileBasicInfo
	size := uint32(unsafe.Sizeof(basic))
	if err := windows.GetFileInformationByHandleEx(attributes, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), size); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteAt([]byte{fill}, 4096); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileInformationByHandle(attributes, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), size); err != nil {
		t.Fatal(err)
	}
}

// GAP-0438: the stamp follows the file version: with no other handle open, a
// same-size write whose time stamps were put back still gets a new
// change-journal number when its writer closes the file.
func TestWindowsManagedArtifactStampFollowsTheFileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	writeManagedArtifactFixture(t, path, 1)
	first, ok := windowsManagedArtifactStampOfPath(t, path)
	if !ok {
		t.Skip("the test volume keeps no change journal; the memo is off there")
	}
	if again, _ := windowsManagedArtifactStampOfPath(t, path); again != first {
		t.Fatalf("the stamp of an unchanged file moved: %+v then %+v", first, again)
	}
	rewriteKeepingTimes(t, path, 9)
	later, ok := windowsManagedArtifactStampOfPath(t, path)
	if !ok {
		t.Fatal("no stamp after an in-place write")
	}
	if later.USN == first.USN || later == first {
		t.Fatalf("a same-size write with its times put back kept the stamp: %+v", later)
	}
	if later.Size != first.Size || later.ID != first.ID {
		t.Fatalf("the fixture did not keep size and file id: %+v then %+v", first, later)
	}
}

// The memo answers only for an unchanged file that no writer holds open.
func TestWindowsManagedArtifactDigestMemoAnswersOnlyForAnUnwrittenVersion(t *testing.T) {
	useWindowsManagedArtifactDigestSeams(t)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if _, ok := windowsManagedArtifactStampOfPath(t, path); !ok {
		t.Skip("the test volume keeps no change journal; the memo is off there")
	}
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("digest %s, want %s", got, first)
	}
	setRemembered := func() { setManagedArtifactDigestSentinel(t, path) }
	setRemembered()
	if got := managedArtifactDigestOf(t, path, true); got != managedArtifactDigestSentinel {
		t.Fatalf("an unchanged version was read again: %s", got)
	}

	// A writer that holds the file open could change it under one stamp:
	// the file is read in full and nothing is remembered.
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("with a writer open: digest %s, want the full read %s", got, first)
	}
	if managedArtifactDigestRemembered(path) {
		t.Fatal("a digest read while a writer held the file was remembered")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	// An in-place write with every time stamp put back is read again.
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("digest %s, want %s", got, first)
	}
	setRemembered()
	rewriteKeepingTimes(t, path, 9)
	got := managedArtifactDigestOf(t, path, true)
	if got == managedArtifactDigestSentinel || got == first {
		t.Fatalf("a rewritten file with its times put back kept the remembered digest: %s", got)
	}

	// A replacement by rename (another file id) is read again.
	setRemembered()
	replacement := path + ".new"
	want := writeManagedArtifactFixture(t, replacement, 5)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if got := managedArtifactDigestOf(t, path, true); got != want {
		t.Fatalf("a replaced file kept the remembered digest: %s, want %s", got, want)
	}
}

// GAP-0438 (Codex F1): another open handle, even one that may only read
// attributes, keeps the change epoch of the file open, and in that epoch a
// second change of the same kind posts no new journal record. A full read
// ends the epoch before it takes the stamp it remembers, so a write after it
// still moves the journal number and is read again.
func TestWindowsManagedArtifactDigestMemoSeesAWriteWhileAnotherHandleIsOpen(t *testing.T) {
	for _, other := range managedArtifactOtherHandles {
		t.Run(other.name, func(t *testing.T) {
			useWindowsManagedArtifactDigestSeams(t)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			clean := writeManagedArtifactFixture(t, path, 1)
			if _, ok := windowsManagedArtifactStampOfPath(t, path); !ok {
				t.Skip("the test volume keeps no change journal; the memo is off there")
			}
			holdManagedArtifact(t, path, other.access)
			// A write and its revert, both with the times put back, open an
			// epoch that the other handle keeps open.
			rewriteKeepingTimes(t, path, 9)
			rewriteKeepingTimes(t, path, 1)
			if got := managedArtifactDigestOf(t, path, true); got != clean {
				t.Fatalf("digest %s, want %s", got, clean)
			}
			if !managedArtifactDigestRemembered(path) {
				t.Fatal("a full read of an unwritten version was not remembered")
			}
			rewriteKeepingTimes(t, path, 9)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(data)
			want := "sha256:" + hex.EncodeToString(sum[:])
			if got := managedArtifactDigestOf(t, path, true); got != want {
				t.Fatalf("a write while another handle was open kept the remembered digest: %s, want %s (clean %s)", got, want, clean)
			}
		})
	}
}

// Ending the change epoch moves the journal number once, in the full read.
// Closing that read's own handle and a later memo hit move nothing, so the
// next calls still answer from the memo, with or without another handle open.
func TestWindowsManagedArtifactDigestMemoHitsAfterAFullRead(t *testing.T) {
	cases := append([]struct {
		name   string
		access uint32
	}{{name: "no other handle"}}, managedArtifactOtherHandles...)
	for _, other := range cases {
		t.Run(other.name, func(t *testing.T) {
			ends := useWindowsManagedArtifactDigestSeams(t)
			path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
			first := writeManagedArtifactFixture(t, path, 1)
			if _, ok := windowsManagedArtifactStampOfPath(t, path); !ok {
				t.Skip("the test volume keeps no change journal; the memo is off there")
			}
			if other.access != 0 {
				holdManagedArtifact(t, path, other.access)
			}
			if got := managedArtifactDigestOf(t, path, true); got != first {
				t.Fatalf("digest %s, want %s", got, first)
			}
			if *ends != 1 {
				t.Fatalf("the full read ended %d change epochs, want 1", *ends)
			}
			setManagedArtifactDigestSentinel(t, path)
			for call := 1; call <= 3; call++ {
				if got := managedArtifactDigestOf(t, path, true); got != managedArtifactDigestSentinel {
					t.Fatalf("call %d after a full read with no write in between read the file again: %s", call, got)
				}
			}
			if *ends != 1 {
				t.Fatalf("a memo hit ended the change epoch (%d ends)", *ends)
			}
		})
	}
}

// The guardian's target API shares the connector's post-epoch stamp, while
// the protected copy has no independent ten-minute backstop.
func TestWindowsManagedHookBinaryAPIsShareTargetAndDoNotExpireCopy(t *testing.T) {
	clock, ends := useManagedArtifactDigestSeams(t,
		windowsManagedArtifactStamp,
		openWindowsManagedArtifactExclusive,
		endWindowsManagedArtifactChangeEpoch,
	)
	managedArtifactDigestMemoEligible = func(string) bool { return true }
	managedProtectedHookCopyEligible = func(string) bool { return true }
	target := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	copyPath := filepath.Join(t.TempDir(), "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(copyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	targetDigest := writeManagedArtifactFixture(t, target, 1)
	copyDigest := writeManagedArtifactFixture(t, copyPath, 2)
	if _, ok := windowsManagedArtifactStampOfPath(t, target); !ok {
		t.Skip("the test volume keeps no change journal; the memo is off there")
	}
	if got, err := ManagedEnterpriseHookBinarySHA256Hex(target); err != nil || "sha256:"+got != targetDigest {
		t.Fatalf("target digest %q, err %v", got, err)
	}
	if got, err := ManagedProtectedHookCopySHA256Hex(copyPath); err != nil || "sha256:"+got != copyDigest {
		t.Fatalf("copy digest %q, err %v", got, err)
	}
	if *ends != 2 {
		t.Fatalf("first reads ended %d epochs, want two", *ends)
	}
	setManagedArtifactDigestSentinel(t, copyPath)
	*clock = clock.Add(11 * time.Minute)
	if got, err := ManagedProtectedHookCopySHA256Hex(copyPath); err != nil || got != "remembered" {
		t.Fatalf("copy expired after ten minutes: %q, %v", got, err)
	}
	if got, err := ManagedEnterpriseHookBinarySHA256Hex(target); err != nil || "sha256:"+got != targetDigest {
		t.Fatalf("target backstop digest %q, err %v", got, err)
	}
	if *ends != 3 {
		t.Fatalf("after target backstop, epochs %d, want three", *ends)
	}
}
