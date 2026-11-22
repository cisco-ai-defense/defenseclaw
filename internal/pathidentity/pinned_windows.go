// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// nameSurrogateBit marks the reparse tags that name another file (symbolic
// links and mount points); os.Stat follows those and no others.
const nameSurrogateBit = 0x20000000

func lstatPinned(path string) (os.FileInfo, error) {
	// As os.Lstat: a trailing separator resolves a link in the last element.
	follow := path != "" && os.IsPathSeparator(path[len(path)-1])
	return pinnedStat("Lstat", path, follow)
}

func statPinned(path string) (os.FileInfo, error) {
	return pinnedStat("Stat", path, true)
}

// pinnedStat opens the path itself (never a reparse point it names, unless
// follow is set and it is a name surrogate) for attributes only, and builds
// the FileInfo from that handle. A FileInfo from a handle carries its file
// ID, so os.SameFile never reads it again by path.
func pinnedStat(op, path string, follow bool) (os.FileInfo, error) {
	if path == "" {
		return nil, &os.PathError{Op: op, Path: path, Err: windows.ERROR_PATH_NOT_FOUND}
	}
	name, err := windows.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil, &os.PathError{Op: op, Path: path, Err: err}
	}
	handle, err := openForIdentity(name, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err == windows.ERROR_SHARING_VIOLATION {
		// No handle at all (pagefile.sys and the like): os answers from
		// FindFirstFile. Its FileInfo loads the ID lazily and that open fails
		// the same way, so os.SameFile refuses it: the guard fails closed.
		if follow {
			return os.Stat(path)
		}
		return os.Lstat(path)
	}
	if err != nil {
		return nil, &os.PathError{Op: op, Path: path, Err: err}
	}
	// Only a disk file can be a reparse point; a device such as NUL has no
	// file information to read.
	if fileType, typeErr := windows.GetFileType(handle); follow && typeErr == nil && fileType == windows.FILE_TYPE_DISK {
		surrogate, err := isNameSurrogate(handle)
		if err != nil {
			_ = windows.CloseHandle(handle)
			return nil, &os.PathError{Op: op, Path: path, Err: err}
		}
		if surrogate {
			_ = windows.CloseHandle(handle)
			if handle, err = openForIdentity(name, 0); err != nil {
				return nil, &os.PathError{Op: op, Path: path, Err: err}
			}
		}
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, &os.PathError{Op: op, Path: path, Err: windows.ERROR_INVALID_HANDLE}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		if pathErr, ok := err.(*os.PathError); ok {
			err = pathErr.Err
		}
		return nil, &os.PathError{Op: op, Path: path, Err: err}
	}
	return info, nil
}

// openForIdentity opens name with no data access (as os.Lstat does), sharing
// everything, so it neither needs read access nor holds off a writer.
func openForIdentity(name *uint16, flags uint32) (windows.Handle, error) {
	return windows.CreateFile(
		name,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|flags,
		0,
	)
}

func isNameSurrogate(handle windows.Handle) (bool, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return false, nil
	}
	var tag struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(
		handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)),
	); err != nil {
		return false, err
	}
	return tag.ReparseTag&nameSurrogateBit != 0, nil
}

// longPath adds the extended-length prefix where os does (a path of 248
// characters or more), so a short path keeps the Win32 normalization that
// os.Open applies to the same spelling.
func longPath(path string) string {
	if len(path) < 248 {
		return path
	}
	// Already a device or NT namespace path in either slash spelling
	// (\\?\, \\.\, \??\, //?/, //./): leave it to Win32 as os does.
	if prefix := strings.ReplaceAll(path[:4], "/", `\`); prefix == `\\?\` || prefix == `\\.\` || prefix == `\??\` {
		return path
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if strings.HasPrefix(absolute, `\\`) {
		return `\\?\UNC\` + strings.TrimPrefix(absolute, `\\`)
	}
	return `\\?\` + absolute
}

func holdUnlinked(path string) (func() bool, error) {
	if path == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_PATH_NOT_FOUND}
	}
	name, err := windows.UTF16PtrFromString(longPath(path))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	pinned := true
	// Without delete sharing the component cannot be renamed or deleted, so
	// not replaced by a link, while the handle is open.
	handle, err := openUnfollowed(name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err == windows.ERROR_SHARING_VIOLATION {
		pinned = false
		handle, err = openUnfollowed(name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	}
	switch {
	case err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND:
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	case err != nil:
		// No handle at all (pagefile.sys and the like): the read reads it as
		// the system does.
		return func() bool { return !linkedNow(name) }, nil
	}
	linked, err := handleIsLink(handle)
	if err != nil || linked {
		_ = windows.CloseHandle(handle)
		if linked {
			return nil, ErrLinked
		}
		return func() bool { return !linkedNow(name) }, nil
	}
	return func() bool {
		stayed := pinned || !linkedNow(name)
		_ = windows.CloseHandle(handle)
		return stayed
	}, nil
}

// openUnfollowed opens the last component of name itself, a link as the
// link, for its attributes only.
func openUnfollowed(name *uint16, share uint32) (windows.Handle, error) {
	return windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, share, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// handleIsLink reports a handle opened on a name surrogate (a link). Only a
// disk file can be one; a device such as NUL has no file information.
func handleIsLink(handle windows.Handle) (bool, error) {
	if fileType, err := windows.GetFileType(handle); err != nil || fileType != windows.FILE_TYPE_DISK {
		return false, nil
	}
	return isNameSurrogate(handle)
}

// linkedNow reports that the last component of name is a link now.
func linkedNow(name *uint16) bool {
	handle, err := openUnfollowed(name, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // a handle opened for attributes only
	linked, err := handleIsLink(handle)
	return err == nil && linked
}
