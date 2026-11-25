// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/sys/windows"
)

// OpenDirectoryNoFollow acquires a directory one component at a time from its
// volume root or UNC share anchor. Every component below that anchor is opened
// relative to the previous handle and must be a plain directory. The returned
// handle supports ReadDir and anchors all subsequent child lookups.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	if path == "" {
		return nil, os.ErrInvalid
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	absolute = filepath.Clean(absolute)
	volume := filepath.VolumeName(absolute)
	if volume == "" {
		return nil, os.ErrInvalid
	}
	anchor := volume + `\`
	if SameWindowsPath(absolute, anchor) {
		return openReadDirectoryAnchor(absolute)
	}
	return OpenBelow(anchor, absolute, BelowDirectory)
}

// An anchor itself needs a listing handle; OpenBelow's initial anchor handle
// needs only attribute access because a child provides the listing handle.
func openReadDirectoryAnchor(path string) (*os.File, error) {
	ptr, err := UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(ptr,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|
			windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if err := checkReadChildHandle(handle, path, BelowDirectory); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// OpenChildNoFollow opens one child of an already-open plain directory.
// BelowFile also denies write sharing, keeping existing or new content writers
// from changing the bytes while the caller hashes the returned handle.
func OpenChildNoFollow(parent *os.File, name string, kind BelowKind) (*os.File, error) {
	if kind != BelowDirectory && kind != BelowFile {
		return nil, fmt.Errorf("open child: unsupported file kind")
	}
	return openReadChild(parent, name, kind)
}

// ReadChildLink reads one symbolic link or junction itself, relative to the
// held parent. No operation opens or resolves the link target.
func ReadChildLink(parent *os.File, name string) (string, error) {
	file, err := openReadChild(parent, name, belowInspect)
	if err != nil {
		return "", err
	}
	defer file.Close()
	link, surrogate, err := readReparseLink(windows.Handle(file.Fd()))
	if err != nil {
		return "", err
	}
	if !surrogate {
		return "", &os.PathError{Op: "readlink", Path: file.Name(), Err: windows.ERROR_NOT_A_REPARSE_POINT}
	}
	return normalizedReadLinkTarget(link), nil
}

// StatChildNoFollow reads one child's attributes and size relative to the
// held parent, opened for attribute access only: no share conflict with a
// writer holding it, and no read access to its content needed. A link, and a
// device, is refused as OpenChildNoFollow refuses them.
func StatChildNoFollow(parent *os.File, name string) (attributes uint32, size int64, err error) {
	file, err := openReadChild(parent, name, belowCheck)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	info, err := handleInformation(windows.Handle(file.Fd()))
	if err != nil {
		return 0, 0, &os.PathError{Op: "stat", Path: file.Name(), Err: err}
	}
	return info.FileAttributes, int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow), nil
}

func openReadChild(parent *os.File, name string, kind BelowKind) (*os.File, error) {
	if err := validateReadChildName(name); err != nil {
		return nil, err
	}
	if parent == nil {
		return nil, os.ErrInvalid
	}
	defer runtime.KeepAlive(parent)
	if _, err := parent.Stat(); err != nil {
		return nil, err
	}
	parentHandle := windows.Handle(parent.Fd())
	if err := checkReadChildHandle(parentHandle, parent.Name(), BelowDirectory); err != nil {
		return nil, err
	}
	sharing := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	if kind == BelowFile {
		sharing &^= windows.FILE_SHARE_WRITE
	}
	handle, err := openBelowChildWithSharing(parentHandle, name, true, kind, sharing)
	path := filepath.Join(parent.Name(), name) // diagnostic name only
	if err != nil {
		return nil, belowOpenError(err, path, true, kind, windowsBelowOps.status)
	}
	if err := checkReadChildHandle(handle, path, kind); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func checkReadChildHandle(handle windows.Handle, path string, kind BelowKind) error {
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if fileType != windows.FILE_TYPE_DISK {
		return fmt.Errorf("%s: %w", path, ErrNotRegularBelow)
	}
	info, err := handleInformation(handle)
	if err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return checkBelowAttributes(info.FileAttributes, path, true, kind)
}
