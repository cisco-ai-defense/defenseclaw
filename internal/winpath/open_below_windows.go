// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The decision constants of open_below.go are the Windows values: each pair
// of subtractions is a compile error unless both sides are equal.
const (
	_ uint32 = uint32(windows.STATUS_STOPPED_ON_SYMLINK) - statusStoppedOnSymlink
	_ uint32 = statusStoppedOnSymlink - uint32(windows.STATUS_STOPPED_ON_SYMLINK)
	_ uint32 = uint32(windows.STATUS_OBJECT_NAME_NOT_FOUND) - statusObjectNameNotFound
	_ uint32 = statusObjectNameNotFound - uint32(windows.STATUS_OBJECT_NAME_NOT_FOUND)
	_ uint32 = uint32(windows.STATUS_OBJECT_PATH_NOT_FOUND) - statusObjectPathNotFound
	_ uint32 = statusObjectPathNotFound - uint32(windows.STATUS_OBJECT_PATH_NOT_FOUND)
	_ uint32 = uint32(windows.STATUS_DELETE_PENDING) - statusDeletePending
	_ uint32 = statusDeletePending - uint32(windows.STATUS_DELETE_PENDING)
	_ uint32 = uint32(windows.STATUS_FILE_IS_A_DIRECTORY) - statusFileIsADirectory
	_ uint32 = statusFileIsADirectory - uint32(windows.STATUS_FILE_IS_A_DIRECTORY)
	_ uint32 = uint32(windows.STATUS_NOT_A_DIRECTORY) - statusNotADirectory
	_ uint32 = statusNotADirectory - uint32(windows.STATUS_NOT_A_DIRECTORY)
	_ uint32 = uint32(windows.STATUS_IO_REPARSE_TAG_NOT_HANDLED) - statusIOReparseTagNotHandled
	_ uint32 = statusIOReparseTagNotHandled - uint32(windows.STATUS_IO_REPARSE_TAG_NOT_HANDLED)
	_ uint32 = uint32(windows.STATUS_REPARSE_POINT_ENCOUNTERED) - statusReparsePointEncountered
	_ uint32 = statusReparsePointEncountered - uint32(windows.STATUS_REPARSE_POINT_ENCOUNTERED)
	_ uint32 = windows.FILE_ATTRIBUTE_DIRECTORY - fileAttributeDirectory
	_ uint32 = fileAttributeDirectory - windows.FILE_ATTRIBUTE_DIRECTORY
	_ uint32 = windows.FILE_ATTRIBUTE_DEVICE - fileAttributeDevice
	_ uint32 = fileAttributeDevice - windows.FILE_ATTRIBUTE_DEVICE
	_ uint32 = windows.FILE_ATTRIBUTE_REPARSE_POINT - fileAttributeReparsePoint
	_ uint32 = fileAttributeReparsePoint - windows.FILE_ATTRIBUTE_REPARSE_POINT
)

// OpenBelow opens path for reading (a file) or listing (a folder) from
// root's handle, one element at a time, without following a link anywhere
// from root down (walkBelow): a junction, symbolic link or mount point at or
// below root fails inside the open with ErrLinkBelowRoot, before anything it
// points to is reached. Each open asks for identification-level impersonation
// only. kind is BelowFile, BelowDirectory or BelowAny. The returned file
// reads or lists (ReadDir) through the handle.
func OpenBelow(root, path string, kind BelowKind) (*os.File, error) {
	handle, _, err := walkBelow(root, path, kind, windowsBelowOps)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// InspectBelow opens path from root's handle as OpenBelow does, but opens
// the last element whatever it is (a link itself, not followed) and reports
// whether it is a link or a folder and whether LocalSystem or Administrators
// own it, read on the opened handle.
func InspectBelow(root, path string) (BelowInfo, error) {
	handle, attributes, err := walkBelow(root, path, belowInspect, windowsBelowOps)
	if err != nil {
		return BelowInfo{}, err
	}
	defer windows.CloseHandle(handle)
	owned, err := handleOwnedByAdministratorsOrSystem(handle)
	if err != nil {
		return BelowInfo{}, err
	}
	return BelowInfo{
		Link:       attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0,
		Directory:  attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
		AdminOwned: owned,
	}, nil
}

var windowsBelowOps = belowOps[windows.Handle]{
	openRoot:  openBelowRoot,
	openChild: openBelowChild,
	attributes: func(handle windows.Handle) (uint32, error) {
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return 0, err
		}
		return info.FileAttributes, nil
	},
	status: func(err error) (uint32, bool) {
		var status windows.NTStatus
		if errors.As(err, &status) {
			return uint32(status), true
		}
		return 0, false
	},
	close: func(handle windows.Handle) { _ = windows.CloseHandle(handle) },
}

// openBelowRoot opens root itself (a link is opened, not followed) with
// identification-level impersonation only.
func openBelowRoot(root string) (windows.Handle, error) {
	ptr, err := UTF16Ptr(root)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
}

// belowQoS asks any server reached for identification only (no
// impersonation of the caller); a handle-relative open of a plain folder's
// child reaches only the folder's own volume, this is defence in depth.
var belowQoS = windows.SECURITY_QUALITY_OF_SERVICE{
	Length:              uint32(unsafe.Sizeof(windows.SECURITY_QUALITY_OF_SERVICE{})),
	ImpersonationLevel:  windows.SecurityIdentification,
	ContextTrackingMode: windows.SECURITY_STATIC_TRACKING,
}

// openBelowChild opens name relative to parent with OBJ_DONT_REPARSE and
// FILE_OPEN_REPARSE_POINT: a link at name is opened itself (the walk then
// refuses it) and any reparse met while parsing fails the open
// (STATUS_REPARSE_POINT_ENCOUNTERED). A folder above the last element is
// opened as a folder for attributes only; the last element with the access
// its kind needs.
func openBelowChild(parent windows.Handle, name string, last bool, kind BelowKind) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	qos := belowQoS
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityQoS:   &qos,
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.SYNCHRONIZE)
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
	if !last {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		switch kind {
		case BelowFile:
			access |= windows.FILE_READ_DATA | windows.READ_CONTROL
			options |= windows.FILE_NON_DIRECTORY_FILE
		case BelowDirectory:
			access |= windows.FILE_LIST_DIRECTORY | windows.READ_CONTROL
			options |= windows.FILE_DIRECTORY_FILE
		case BelowAny:
			// FILE_READ_DATA is FILE_LIST_DIRECTORY on a folder: one access
			// reads a file or lists a folder.
			access |= windows.FILE_READ_DATA | windows.READ_CONTROL
		case belowInspect:
			access |= windows.READ_CONTROL
		}
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// handleOwnedByAdministratorsOrSystem reports whether the owner of the
// opened object is LocalSystem or the Administrators group: a folder or file
// a standard user created under ProgramData has that user as owner.
func handleOwnedByAdministratorsOrSystem(handle windows.Handle) (bool, error) {
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
