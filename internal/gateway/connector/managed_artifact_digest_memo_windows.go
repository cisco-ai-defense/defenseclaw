//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The four are replaced in tests.
var (
	managedArtifactDigestMemoEligible = managedEnterpriseHookBinaryPath
	managedProtectedHookCopyEligible  = managedEnterpriseHookCopyPath
	openManagedArtifactExclusive      = openWindowsManagedArtifactExclusive
	managedArtifactStampOf            = windowsManagedArtifactStamp
	managedArtifactAttributeStampOf   = windowsManagedArtifactAttributeStamp
	endManagedArtifactChangeEpoch     = endWindowsManagedArtifactChangeEpoch
)

// managedEnterpriseHookBinaryPath reports whether path is the hook binary of
// this managed enterprise deployment (managedEnterpriseWindowsHookBinary):
// an administrator-owned file that no untrusted account can write, on a
// fixed NTFS volume. Per-user files, agent executables and repository
// builds are never memoized.
func managedEnterpriseHookBinaryPath(path string) bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	hook := managedEnterpriseWindowsHookBinary(executable)
	return hook != "" && strings.EqualFold(filepath.Clean(hook), filepath.Clean(path))
}

// managedEnterpriseHookCopyPath limits the no-backstop memo to the protected
// copy under the administrator's registered state root. Its path and every
// ancestor must be trusted; arbitrary connector data cannot use this policy.
func managedEnterpriseHookCopyPath(path string) bool {
	if !managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return false
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false
	}
	want := filepath.Join(roots.StateRoot, "hook-guardian", "payload", "defenseclaw-hook.exe")
	return strings.EqualFold(filepath.Clean(want), filepath.Clean(path)) &&
		managed.ValidateTrustedFilePath(path, "guardian hook copy") == nil
}

// openWindowsManagedArtifactExclusive opens path for reading with a share
// mode that admits other readers and a rename, but no writer: it fails while
// any handle may write the file, and while it is open no handle can. It does
// not follow a reparse point at the leaf.
func openWindowsManagedArtifactExclusive(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// windowsManagedArtifactFileBasicInfo is FILE_BASIC_INFO.
type windowsManagedArtifactFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// windowsManagedArtifactStamp takes the full stamp of the open file. ok is
// false when a value cannot be read or the volume keeps no change journal;
// a guarded caller then tries the attribute-only ten-minute backstop. An account that
// may write the file can set every time stamp back, but not the journal
// number. That number names a change epoch, not a write: from the first
// change of the file until its last handle closes, NTFS posts a new record
// only for a kind of change the open record does not list yet, and any other
// open handle, even one that may only read attributes, keeps the epoch open.
// So the stamp a full read remembers is taken after
// endWindowsManagedArtifactChangeEpoch, and any later change moves it.
func windowsManagedArtifactStamp(file *os.File) (managedArtifactStamp, bool) {
	stamp, ok := windowsManagedArtifactAttributeStamp(file)
	if !ok {
		return managedArtifactStamp{}, false
	}
	stamp.USN = windowsManagedArtifactUSN(windows.Handle(file.Fd()))
	return stamp, stamp.USN != 0
}

// windowsManagedArtifactAttributeStamp takes the same handle's identity and
// attributes without opening or reading file data. It leaves USN at zero.
func windowsManagedArtifactAttributeStamp(file *os.File) (managedArtifactStamp, bool) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return managedArtifactStamp{}, false
	}
	var basic windowsManagedArtifactFileBasicInfo
	if err := windows.GetFileInformationByHandleEx(
		handle,
		windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)),
		uint32(unsafe.Sizeof(basic)),
	); err != nil {
		return managedArtifactStamp{}, false
	}
	return managedArtifactStamp{
		Volume:     info.VolumeSerialNumber,
		ID:         uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		Size:       int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow),
		Links:      info.NumberOfLinks,
		Written:    basic.LastWriteTime,
		Changed:    basic.ChangeTime,
		Attributes: basic.FileAttributes,
	}, true
}

// windowsManagedArtifactUSN is the update sequence number the change journal
// of the volume last recorded for the open file, or 0 without a journal.
func windowsManagedArtifactUSN(handle windows.Handle) int64 {
	var record [128]uint64 // USN_RECORD_V2 or V3 with a name of up to 255 characters
	buffer := unsafe.Slice((*byte)(unsafe.Pointer(&record[0])), len(record)*8)
	var returned uint32
	if err := windows.DeviceIoControl(
		handle,
		windows.FSCTL_READ_FILE_USN_DATA,
		nil,
		0,
		&buffer[0],
		uint32(len(buffer)),
		&returned,
		nil,
	); err != nil || returned < 8 {
		return 0
	}
	// The record starts with its length (4 bytes) and major version (2).
	switch binary.LittleEndian.Uint16(buffer[4:6]) {
	case 2: // 64-bit file references
		if returned >= 32 {
			return int64(binary.LittleEndian.Uint64(buffer[24:32]))
		}
	case 3: // 128-bit file references
		if returned >= 48 {
			return int64(binary.LittleEndian.Uint64(buffer[40:48]))
		}
	}
	return 0
}

// endWindowsManagedArtifactChangeEpoch writes a close record for the open
// file to the change journal of its volume (FSCTL_WRITE_USN_CLOSE_RECORD),
// as the last close of the file would: the next change of the file posts a
// new record with a new number, whatever other handles stay open. It fails
// on a volume without a journal. Only a full read calls it: the record moves
// the number itself, so a call on a memo hit would end every hit.
func endWindowsManagedArtifactChangeEpoch(file *os.File) error {
	var usn int64
	var returned uint32
	return windows.DeviceIoControl(
		windows.Handle(file.Fd()),
		windows.FSCTL_WRITE_USN_CLOSE_RECORD,
		nil,
		0,
		(*byte)(unsafe.Pointer(&usn)),
		uint32(unsafe.Sizeof(usn)),
		&returned,
		nil,
	)
}
