// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// evalLinks opens path with no data access, following every link, and reads
// the final path of the handle. The open needs no right on the file and
// conflicts with no other open of it.
func evalLinks(path string) (string, error) {
	final, err := finalPath(path)
	if err != nil || path == "" {
		return final, err
	}
	return keepDriveSpelling(path, final), nil
}

// finalPath is the final path of the opened file or folder, without the
// \\?\ prefix and with no drive letter kept.
func finalPath(path string) (string, error) {
	if path == "" {
		return filepath.EvalSymlinks(path)
	}
	handle, err := openForFinalPath(path, 0, 0)
	if errors.Is(err, windows.ERROR_CANT_ACCESS_FILE) {
		// The system does not open some reparse points (an app execution
		// alias): such a point is its own place unless it names another.
		handle, err = ownFinalPathHandle(path)
	}
	if err != nil {
		return "", &os.PathError{Op: "evallinks", Path: path, Err: err}
	}
	defer windows.CloseHandle(handle)
	final, err := finalPathByHandle(handle)
	if err != nil {
		return "", &os.PathError{Op: "evallinks", Path: path, Err: err}
	}
	return plainWindowsPath(final), nil
}

// keepDriveSpelling spells final with the drive letter path was named
// through when that letter is a subst drive or a mapped network drive and
// final lies at or below the folder or share it maps to. The handle's final
// path names the real folder (C:\...\target) or share (\\server\share\...),
// where filepath.EvalSymlinks kept the drive letter, and the hook path share
// gate reads a \\server\share spelling as a share (review RV-2182 F2). A path
// whose links lead out of what the drive maps to keeps its real final path.
// The respelling is kept only when it opens the same file as final
// (pathidentity.Same): the containment test compares names, and a name NTFS
// tells apart from final (a Kelvin sign for k, rel-1-0-10:GAP-2211) or a
// drive letter this session defined to another place names another file.
func keepDriveSpelling(path, final string) string {
	respelled := driveSpelling(path, final)
	if respelled != final && !pathidentity.Same(respelled, final) {
		return final
	}
	return respelled
}

// driveSpelling is final spelled through the drive letter of path when final
// lies at or below what that drive maps to, else final.
func driveSpelling(path, final string) string {
	abs := path
	if !filepath.IsAbs(abs) {
		var err error
		if abs, err = filepath.Abs(path); err != nil {
			return final
		}
	}
	volume := filepath.VolumeName(abs)
	if len(volume) != 2 || volume[1] != ':' || !isASCIIDriveLetter(volume[0]) {
		return final
	}
	if len(final) >= 2 && strings.EqualFold(final[:2], volume) {
		return final
	}
	root := strings.ToUpper(volume) + `\`
	handle, err := openForFinalPath(root, 0, 0)
	if err != nil {
		return final
	}
	mapped, err := finalPathByHandle(handle)
	windows.CloseHandle(handle)
	if err != nil {
		return final
	}
	mapped = plainWindowsPath(mapped)
	if SameWindowsPath(mapped, root) {
		return final
	}
	if SameWindowsPath(mapped, final) {
		return root
	}
	rest, err := windowsRelativeBelow(mapped, final)
	if err != nil {
		return final
	}
	return root + strings.Join(rest, `\`)
}

func openForFinalPath(path string, access, flags uint32) (windows.Handle, error) {
	name, err := UTF16Ptr(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|flags, 0)
}

// ownFinalPathHandle opens the reparse point at path itself and keeps the
// handle only when the point names no other file system place (it is not a
// junction, a mount point or a symbolic link).
func ownFinalPathHandle(path string) (windows.Handle, error) {
	handle, err := openForFinalPath(path, windows.FILE_READ_ATTRIBUTES, windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if err != nil {
		return windows.InvalidHandle, err
	}
	var info struct {
		FileAttributes uint32
		ReparseTag     uint32
	}
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 || info.ReparseTag&reparseTagNameSurrogate != 0 {
		windows.CloseHandle(handle)
		return windows.InvalidHandle, windows.ERROR_CANT_ACCESS_FILE
	}
	return handle, nil
}
