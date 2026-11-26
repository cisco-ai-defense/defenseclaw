// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The hold of HoldUnlinked on Windows (rel-1-0-10:GAP-1264, GAP-1263).
//
// NT checks share access only for an open that asks for data, execute or
// delete access. The hold used to open the component for its attributes
// only, which pins nothing: a rename of the held component passed it
// (native TestGAP1264HeldComponentCannotBeRenamed). A handle with data
// access and no delete sharing refuses every rename and delete of the
// component, and NTFS refuses a rename of any folder above a component that
// has an open handle (native TestGAP1263ProbeFolderAboveAHeldComponent). The
// hold is one open of the whole path that follows no reparse point on the
// way (OBJ_DONT_REPARSE) and none at its end (FILE_OPEN_REPARSE_POINT): when
// it succeeds, no folder of the path was a link at that moment, and while it
// is open none can become one. still() has nothing left to look at.
const (
	holdShare  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	walkAccess = windows.FILE_READ_ATTRIBUTES
	walkShare  = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
)

// holdAccesses are tried in order: a file's contents or a folder's listing,
// then execute or traverse, for an account that may not list a folder it
// may enter. Both are share-checked.
var holdAccesses = [...]uint32{
	windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES,
	windows.FILE_EXECUTE | windows.FILE_READ_ATTRIBUTES,
}

func holdUnlinked(path string) (func() bool, error) {
	if path == "" {
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_PATH_NOT_FOUND}
	}
	nt, err := ntPathName(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	handle, err := holdOpen(nt)
	if err != nil {
		return nil, holdError(path, err)
	}
	linked, err := handleIsLink(handle)
	if err != nil || linked {
		_ = windows.CloseHandle(handle)
		if linked {
			return nil, ErrLinked
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrUnpinned}
	}
	return func() bool {
		_ = windows.CloseHandle(handle)
		return true
	}, nil
}

// holdOpen opens nt as the hold. A reparse point on the way is either a
// link or one that names no other file (a folder a file system filter
// keeps, such as a cloud files placeholder): the path is then opened again
// from its volume root down (holdByComponents), which tells the two apart.
func holdOpen(nt string) (windows.Handle, error) {
	var handle windows.Handle
	var err error
	for _, access := range holdAccesses {
		handle, err = ntOpen(0, nt, access, holdShare, windows.OBJ_DONT_REPARSE)
		if err == windows.STATUS_REPARSE_POINT_ENCOUNTERED {
			return holdByComponents(nt, access)
		}
		if err != windows.STATUS_ACCESS_DENIED {
			break
		}
	}
	return handle, err
}

// holdByComponents opens nt one component at a time, each relative to the
// handle of the folder above it and without following it, from the volume
// root down. A component that is a link is refused (ErrLinked) before
// anything below it is looked up. Each handle is closed only once the one
// below it is open, so no folder on the way can be renamed in between; the
// last component is opened as the hold.
func holdByComponents(nt string, access uint32) (windows.Handle, error) {
	root, rest, ok := ntSplitRoot(nt)
	if !ok {
		return 0, windows.STATUS_REPARSE_POINT_ENCOUNTERED
	}
	names := strings.FieldsFunc(rest, func(r rune) bool { return r == '\\' })
	if len(names) == 0 {
		return ntOpen(0, root, access, holdShare, windows.OBJ_DONT_REPARSE)
	}
	parent, err := ntOpen(0, root, walkAccess, walkShare, windows.OBJ_DONT_REPARSE)
	if err != nil {
		return 0, err
	}
	for i, name := range names {
		last := i == len(names)-1
		childAccess, childShare := uint32(walkAccess), uint32(walkShare)
		if last {
			childAccess, childShare = access, holdShare
		}
		child, err := ntOpen(parent, name, childAccess, childShare, 0)
		_ = windows.CloseHandle(parent)
		if err != nil {
			return 0, err
		}
		if !last {
			linked, err := handleIsLink(child)
			if err != nil || linked {
				_ = windows.CloseHandle(child)
				if linked {
					return 0, ErrLinked
				}
				return 0, err
			}
		}
		parent = child
	}
	return parent, nil
}

// holdError is the error of a hold that could not be taken. A name that is
// not there or cannot name a file is that error, as the read would fail;
// any other failure (another handle denies read sharing or has delete
// access, as a registry hive or the paging file does; the account may
// neither read nor enter it) is ErrUnpinned: what a read would show is
// unknown, and it is not made unpinned.
func holdError(path string, err error) error {
	if errors.Is(err, ErrLinked) {
		return ErrLinked
	}
	var status windows.NTStatus
	if errors.As(err, &status) {
		switch errno := status.Errno(); errno {
		case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_INVALID_NAME,
			windows.ERROR_BAD_PATHNAME, windows.ERROR_DIRECTORY, windows.ERROR_FILENAME_EXCED_RANGE,
			windows.ERROR_BAD_NETPATH, windows.ERROR_BAD_NET_NAME:
			return &os.PathError{Op: "open", Path: path, Err: errno}
		}
	}
	return &os.PathError{Op: "open", Path: path, Err: ErrUnpinned}
}

// ntOpen is NtCreateFile of name (relative to root when root is not 0) for
// access, the last component itself, a link as the link.
func ntOpen(root windows.Handle, name string, access, share, attributes uint32) (windows.Handle, error) {
	object, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{RootDirectory: root, ObjectName: object, Attributes: windows.OBJ_CASE_INSENSITIVE | attributes}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access|windows.SYNCHRONIZE, &attrs, &iosb, nil, 0, share, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

// ntPathName is the NT name CreateFile opens for path: the Win32 full path
// (GetFullPathName applies the same normalization CreateFile does: the
// working folder, "." and "..", trailing dots and spaces), in the \??\
// namespace.
func ntPathName(path string) (string, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetFullPathName(name, uint32(len(buf)), &buf[0], nil)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			full := windows.UTF16ToString(buf[:n])
			switch {
			case strings.HasPrefix(full, `\\?\`), strings.HasPrefix(full, `\\.\`):
				return `\??\` + full[4:], nil
			case strings.HasPrefix(full, `\\`):
				return `\??\UNC\` + full[2:], nil
			}
			return `\??\` + full, nil
		}
		buf = make([]uint16, n)
	}
}

// ntSplitRoot splits an NT path into the root of its volume or share and the
// rest: \??\C:\, \??\UNC\server\share\ or \??\Volume{...}\.
func ntSplitRoot(nt string) (root, rest string, ok bool) {
	body := strings.TrimPrefix(nt, `\??\`)
	if body == nt {
		return "", "", false
	}
	parts := 1
	if len(body) >= 4 && strings.EqualFold(body[:4], `UNC\`) {
		parts = 3
	}
	end := 0
	for i := 0; i < parts; i++ {
		next := strings.IndexByte(body[end:], '\\')
		if next < 0 {
			return "", "", false
		}
		end += next + 1
	}
	if parts == 1 && !(end == 3 && body[1] == ':') && !strings.HasPrefix(body, "Volume{") {
		return "", "", false
	}
	return `\??\` + body[:end], body[end:], true
}
