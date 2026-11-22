// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// RejectReparseBelow refuses a path with a link from root down to it: root
// and then each element below it are opened from the previous handle without
// following a link (walkBelow, attribute access only), and the first reparse
// point is ErrLinkBelowRoot naming it. A missing element is fs.ErrNotExist.
// No element is resolved by name, so a link swapped in during the walk is
// never followed. Unlike RejectReparseChain it does not check the folders
// above root.
func RejectReparseBelow(root, path string) error {
	handle, _, err := walkBelow(root, path, belowCheck, windowsBelowOps)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

// VerifyOpenedBelow checks, on the handle the caller reads, that the file
// opened through path was reached from root through plain folders: its final
// path is root's final path plus path's own elements below root (compared
// case-insensitively). Root is opened without following a link and must be
// a plain folder. Only root is resolved by name: an element below it spelled
// in 8.3 form does not compare equal and is refused, which is safe (the file
// is then not read). A link swapped in between a walk and the open makes the
// final path differ, and the error wraps ErrLinkBelowRoot.
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
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
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
	want, err := ExpectedFinalPathBelow(finalRoot, root, path)
	if err != nil {
		return err
	}
	if !SameWindowsPath(want, final) {
		return fmt.Errorf("%w: %s opens %s", ErrLinkBelowRoot, path, plainWindowsPath(final))
	}
	return nil
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
