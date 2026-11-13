// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/windows"
)

// RejectReparseBelow is CheckNoReparseBelow on the file system: each element
// from root down to path is read with GetFileAttributes, which reports a
// link's own attributes without following it. A missing element is
// fs.ErrNotExist. Unlike RejectReparseChain it does not check the folders
// above root.
func RejectReparseBelow(root, path string) error {
	return CheckNoReparseBelow(root, path, func(element string) (bool, error) {
		attributes, err := windowsPathAttributes(element)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return false, fs.ErrNotExist
		}
		if err != nil {
			return false, err
		}
		return attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
	})
}

// VerifyOpenedBelow checks, on the handle the caller reads, that the file
// opened through path was reached from root through plain folders: its final
// path is root's final path plus path's own elements (long names, compared
// case-insensitively). Root is opened without following a link and must be
// a plain folder. It closes the gap between a RejectReparseBelow walk and the
// open: a link swapped in between makes the final path differ, and the error
// wraps ErrLinkBelowRoot.
func VerifyOpenedBelow(handle windows.Handle, root, path string) error {
	final, err := finalPathByHandle(handle)
	if err != nil {
		return fmt.Errorf("read the final path of %s: %w", path, err)
	}
	rootPtr, err := UTF16Ptr(root)
	if err != nil {
		return err
	}
	rootHandle, err := windows.CreateFile(rootPtr, windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", root, err)
	}
	defer windows.CloseHandle(rootHandle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(rootHandle, &info); err != nil {
		return fmt.Errorf("inspect %s: %w", root, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: %s", ErrLinkBelowRoot, root)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf("%s is not a folder", root)
	}
	finalRoot, err := finalPathByHandle(rootHandle)
	if err != nil {
		return fmt.Errorf("read the final path of %s: %w", root, err)
	}
	longRoot, err := extendedLongPathName(root)
	if err != nil {
		return err
	}
	longPath, err := extendedLongPathName(path)
	if err != nil {
		return err
	}
	want, err := ExpectedFinalPathBelow(finalRoot, longRoot, longPath)
	if err != nil {
		return err
	}
	if !SameWindowsPath(want, final) {
		return fmt.Errorf("%w: %s opens %s", ErrLinkBelowRoot, path, plainWindowsPath(final))
	}
	return nil
}

// OwnedByAdministratorsOrSystem reports whether the owner of path itself (a
// link is not followed) is LocalSystem or the Administrators group: a folder
// or file a standard user created under ProgramData has that user as owner.
func OwnedByAdministratorsOrSystem(path string) (bool, error) {
	ptr, err := UTF16Ptr(path)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(ptr, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil {
		return false, nil
	}
	return owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid), nil
}

func finalPathByHandle(handle windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
	if err != nil {
		return "", err
	}
	if n == 0 || n >= uint32(len(buf)) {
		return "", errors.New("final path exceeds the Windows path limit")
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// extendedLongPathName is path with long names (lookupLongPathName on its
// extended-length spelling).
func extendedLongPathName(path string) (string, error) {
	extended, err := Extended(path)
	if err != nil {
		return "", err
	}
	long, ok := lookupLongPathName(extended)
	if !ok {
		return "", fmt.Errorf("read the long name of %s", path)
	}
	return long, nil
}
