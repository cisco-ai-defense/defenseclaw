// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookguard

import (
	"errors"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winowner"
	"golang.org/x/sys/windows"
)

// coworkMarkerTrusted reads the security of the removal marker and of the
// folder that holds it, each on a handle opened without following a reparse
// point, refuses a reparse point in any folder above them, and applies
// coworkMarkerSecurityTrusted. Any error keeps the installed path.
func coworkMarkerTrusted(marker string) bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false
	}
	markerSecurity, links, err := coworkPathSecurity(marker, false)
	if err != nil {
		return false
	}
	folder := filepath.Dir(marker)
	folderSecurity, _, err := coworkPathSecurity(folder, true)
	if err != nil || coworkAncestorIsReparsePoint(folder) {
		return false
	}
	return coworkMarkerSecurityTrusted(markerSecurity, folderSecurity, links, user.User.Sid.String())
}

// coworkMarkerSecurityTrusted honours a removal marker only when (cowork-1-0-8
// GAP-0085, review S1):
//   - the marker and its folder have an owner in the Windows owner trust set;
//   - the folder has a DACL, and no allow ACE in it gives a principal outside
//     the set, or OWNER RIGHTS, a right in winowner.CustodyWriteMask (an
//     inherit-only CREATOR OWNER ACE applies to children only, as in the
//     CLI's custody rule, which refuses such a folder before writing the
//     marker);
//   - the marker has one link.
//
// An owner check alone is not enough: another account that may add or rename
// entries in the folder could hard-link a file SYSTEM owns, or rename in a
// file Administrators own, to the marker path, and a rename keeps the owner.
func coworkMarkerSecurityTrusted(marker, folder *windows.SECURITY_DESCRIPTOR, markerLinks uint32, current string) bool {
	if marker == nil || folder == nil || markerLinks != 1 {
		return false
	}
	markerOwner, _, err := marker.Owner()
	if err != nil || markerOwner == nil {
		return false
	}
	folderOwner, _, err := folder.Owner()
	if err != nil || folderOwner == nil {
		return false
	}
	if !coworkOwnersTrusted(markerOwner.String(), folderOwner.String(), current) {
		return false
	}
	dacl, _, err := folder.DACL()
	if err != nil || dacl == nil {
		return false // no DACL, or a NULL DACL that lets everyone write
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return false
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return false // object, callback and conditional ACEs carry other layouts
		}
		if uint32(ace.Mask)&winowner.CustodyWriteMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if winowner.TrustedWriter(sid, current) ||
			(sid == winowner.CreatorOwnerSID && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0) {
			continue
		}
		return false
	}
	return true
}

// coworkPathSecurity returns the owner and DACL of path and its link count.
// path must be a directory when directory is set and a file otherwise, and
// never a reparse point.
func coworkPathSecurity(path string, directory bool) (*windows.SECURITY_DESCRIPTOR, uint32, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, 0, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return nil, 0, err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return nil, 0, err
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || isDirectory != directory {
		return nil, 0, errors.New("unexpected file type")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return nil, 0, err
	}
	return descriptor, info.NumberOfLinks, nil
}

// coworkAncestorIsReparsePoint reports whether a folder above folder, up to
// the volume root, is a reparse point or cannot be read, as
// safefile.RejectReparseChain does for DefenseClaw's own writes, which
// refuse such a data folder too.
func coworkAncestorIsReparsePoint(folder string) bool {
	current := filepath.Dir(folder)
	for {
		name, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return true
		}
		attributes, err := windows.GetFileAttributes(name)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false
		}
		current = parent
	}
}
