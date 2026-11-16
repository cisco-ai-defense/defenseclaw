// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package plane

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// localImageFS reports an image on a local volume: one on a remote volume
// (a mapped drive or UNC path), whose reads may never return, is not hashed.
func localImageFS(file *os.File) bool {
	volume := filepath.VolumeName(file.Name())
	if volume == "" {
		return false
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return false
	}
	return windows.GetDriveType(root) != windows.DRIVE_REMOTE
}

// fileBasicInfo is FILE_BASIC_INFO: times in 100 ns units since 1601.
type fileBasicInfo struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	FileAttributes                                          uint32
	_                                                       uint32
}

// windowsClientImage pins the image a process-creation record names. The
// record is read up to a poll after the exec, when the process may have
// exited, so the file at the exec path is bound to the exec by time: a file
// written, renamed or replaced at that path after the exec has a later write
// or change time and is not read as the image that ran. Digests are cached by
// the file's USN, which only the file system sets; a volume without a change
// journal caches none, and its client images are never identified. A link is
// not followed. Only the open runs here, on the reader; the digest is the
// cached one, or "" while clientImages hashes the file.
//
// Residual: the Security log carries no section identity. Any user can get
// one exec of their own program classified as the client, by image-section
// replacement (process herpaderping: map a section from their own
// claude.exe-named file, overwrite the file through the open handle with the
// signed release, then create the first thread; or transacted doppelganging,
// with no change on disk), or by replacing the file and backdating its times.
// That exec's children are still classified on their own exec events.
// Identification is not restricted to administrator-owned roots: the native
// installer is per user under %USERPROFILE%.
func windowsClientImage(path string, at time.Time, account string) (sum, version string) {
	if at.IsZero() || !strings.EqualFold(filepath.Base(path), "claude.exe") ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", ""
	}
	if version = windowsReleaseVersion(windowsProductVersion(path)); !IsClaudeReleaseVersion(version) {
		return "", ""
	}
	file, key, ok := openImageUnchangedSince(path, at)
	if !ok {
		return "", version
	}
	sum, _ = clientImages.digestOf(file, key, account, nil)
	return sum, version
}

// openImageUnchangedSince opens the regular file at path for reading, with
// writers excluded while it is open, if it has not been written or changed
// after at and its USN is known.
func openImageUnchangedSince(path string, at time.Time) (*os.File, imageKey, bool) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, imageKey{}, false
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, imageKey{}, false
	}
	file := os.NewFile(uintptr(handle), path)
	var basic fileBasicInfo
	exec := windows.NsecToFiletime(at.UnixNano())
	limit := int64(exec.HighDateTime)<<32 | int64(exec.LowDateTime)
	key, ok := statImageKey(file)
	if !ok || windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))) != nil ||
		basic.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		basic.ChangeTime > limit || basic.LastWriteTime > limit {
		file.Close()
		return nil, imageKey{}, false
	}
	return file, key, true
}

// fsctlReadFileUSNData is FSCTL_READ_FILE_USN_DATA.
const fsctlReadFileUSNData = 0x000900eb

// statImageKey is the identity of an open image file: volume, file index,
// size, the file's last USN and its last write time. ok is false without a
// USN.
func statImageKey(file *os.File) (imageKey, bool) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil {
		return imageKey{}, false
	}
	// READ_FILE_USN_DATA asks for a version 2 record, whose Usn is at 24.
	request := [2]uint16{2, 2}
	var record [512]byte
	var returned uint32
	if windows.DeviceIoControl(handle, fsctlReadFileUSNData, (*byte)(unsafe.Pointer(&request[0])),
		uint32(unsafe.Sizeof(request)), &record[0], uint32(len(record)), &returned, nil) != nil || returned < 32 {
		return imageKey{}, false
	}
	usn := *(*int64)(unsafe.Pointer(&record[24]))
	if usn <= 0 {
		return imageKey{}, false
	}
	return imageKey{
		device: uint64(info.VolumeSerialNumber), file: uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		size: int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow), changed: usn,
		written: info.LastWriteTime.Nanoseconds(),
	}, true
}

// windowsProductVersion is the ProductVersion string of the image's version
// resource, which names the release; "" when it has none.
func windowsProductVersion(path string) string {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 || size > 1<<20 {
		return ""
	}
	buffer := make([]byte, size)
	defer runtime.KeepAlive(buffer)
	block := unsafe.Pointer(&buffer[0])
	if windows.GetFileVersionInfo(path, 0, size, block) != nil {
		return ""
	}
	within := func(pointer unsafe.Pointer, count uintptr) bool {
		start, at := uintptr(block), uintptr(pointer)
		return pointer != nil && at >= start && at-start <= uintptr(len(buffer)) &&
			count <= uintptr(len(buffer))-(at-start)
	}
	var translation unsafe.Pointer
	var length uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&translation), &length) != nil ||
		length < 4 || !within(translation, 4) {
		return ""
	}
	language := *(*uint16)(translation)
	codePage := *(*uint16)(unsafe.Add(translation, 2))
	var value unsafe.Pointer
	length = 0
	key := fmt.Sprintf(`\StringFileInfo\%04x%04x\ProductVersion`, language, codePage)
	if windows.VerQueryValue(block, key, unsafe.Pointer(&value), &length) != nil ||
		length == 0 || length > 256 || !within(value, uintptr(length)*2) {
		return ""
	}
	return strings.TrimSpace(windows.UTF16ToString(unsafe.Slice((*uint16)(value), length)))
}
