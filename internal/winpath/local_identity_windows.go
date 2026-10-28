// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LocalFileIdentity names one file or directory on a local disk volume, as
// os.SameFile compares them.
type LocalFileIdentity struct {
	Volume    uint32
	Index     uint64
	Directory bool
}

// maxLocalPathLinks bounds the links one lookup follows (Windows itself
// stops at 63).
const maxLocalPathLinks = 32

// LocalPathIdentity identifies the file or directory path names without
// letting Windows follow a link it has not checked. It opens path one
// element at a time from its drive root, each element relative to its
// parent and never through a reparse point. A symbolic link or junction is
// followed only when its target is a drive-letter path on a local disk
// volume; a UNC, device or volume-GUID target, a mapped or substituted
// drive, and an unknown link type are ErrPathNotLocal. A privileged caller
// can therefore resolve a path another account chose (a HOME or APPDATA
// from a user's process) without contacting a server that account names,
// and without a race between checking an element and opening it.
//
// A missing element returns an error wrapping fs.ErrNotExist.
func LocalPathIdentity(path string) (LocalFileIdentity, error) {
	current := path
	for links := 0; links <= maxLocalPathLinks; links++ {
		identity, next, err := walkLocalPath(current)
		if err != nil || next == "" {
			return identity, err
		}
		current = next
	}
	return LocalFileIdentity{}, fmt.Errorf("%w: more than %d links", ErrPathNotLocal, maxLocalPathLinks)
}

// walkLocalPath opens path element by element. It returns the identity of
// the last element, or next: the path to look up instead when an element is
// a link to a local target.
func walkLocalPath(path string) (identity LocalFileIdentity, next string, err error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return identity, "", fmt.Errorf("%w: empty path", ErrPathNotLocal)
	}
	// filepath.Abs applies Win32 normalization (GetFullPathName) without
	// touching the file system: the spelling the agent's own process opens.
	abs, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil || !isLocalDriveLetterSyntax(abs) {
		return identity, "", fmt.Errorf("%w: %s", ErrPathNotLocal, path)
	}
	drive := strings.ToUpper(abs[:1]) + ":"
	if target, err := singleDOSDeviceTarget(drive); err != nil || !localDiskDevice(target) {
		return identity, "", fmt.Errorf("%w: drive %s is not a local disk volume", ErrPathNotLocal, drive)
	}
	handle, err := openLocalDriveRoot(drive + `\`)
	if err != nil {
		return identity, "", err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var parts []string
	if rest := strings.Trim(abs[3:], `\`); rest != "" {
		parts = strings.Split(rest, `\`)
	}
	walked := drive + `\`
	info, err := handleInformation(handle)
	if err != nil {
		return identity, "", err
	}
	for index, part := range parts {
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return identity, "", fmt.Errorf("%s is not a directory: %w", walked, fs.ErrNotExist)
		}
		child, err := openChildNoFollow(handle, part)
		if err != nil {
			if errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
				return identity, "", fmt.Errorf("%s: %w", filepath.Join(walked, part), fs.ErrNotExist)
			}
			return identity, "", fmt.Errorf("open %s: %w", filepath.Join(walked, part), err)
		}
		_ = windows.CloseHandle(handle)
		handle = child
		walked = filepath.Join(walked, part)
		if info, err = handleInformation(handle); err != nil {
			return identity, "", err
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
			continue
		}
		link, surrogate, err := readReparseLink(handle)
		if err != nil {
			return identity, "", fmt.Errorf("%s: %w", walked, err)
		}
		if !surrogate {
			continue // opened in place, as Windows opens it
		}
		target, err := localLinkTarget(walked, link)
		if err != nil {
			return identity, "", err
		}
		return identity, filepath.Join(append([]string{target}, parts[index+1:]...)...), nil
	}
	return LocalFileIdentity{
		Volume:    info.VolumeSerialNumber,
		Index:     uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		Directory: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0,
	}, "", nil
}

// localLinkTarget is the path Windows opens for link at linkPath: a relative
// symbolic link resolves against the link's directory (or, rooted, its
// drive); an absolute target must be a drive-letter path.
func localLinkTarget(linkPath string, link reparseLink) (string, error) {
	if link.relative {
		if strings.HasPrefix(link.target, `\`) {
			return filepath.Clean(filepath.VolumeName(linkPath) + link.target), nil
		}
		if filepath.VolumeName(link.target) != "" {
			return "", fmt.Errorf("%w: link %s names %s", ErrPathNotLocal, linkPath, link.target)
		}
		return filepath.Join(filepath.Dir(linkPath), link.target), nil
	}
	target, ok := ntDriveTarget(link.target)
	if !ok {
		return "", fmt.Errorf("%w: link %s does not name a local drive path", ErrPathNotLocal, linkPath)
	}
	return target, nil
}

func openLocalDriveRoot(root string) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(`\\?\` + root)
	if err != nil {
		return 0, err
	}
	return windows.CreateFile(ptr, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

// openChildNoFollow opens name inside parent itself: a link is opened, not
// followed.
func openChildNoFollow(parent windows.Handle, name string) (windows.Handle, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return 0, fmt.Errorf("%w: path element %q", ErrPathNotLocal, name)
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, &attributes, &status, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN,
		windows.FILE_OPEN_REPARSE_POINT|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if err != nil {
		return 0, err
	}
	return handle, nil
}

func handleInformation(handle windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	err := windows.GetFileInformationByHandle(handle, &info)
	return info, err
}

func readReparseLink(handle windows.Handle) (reparseLink, bool, error) {
	buffer := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_GET_REPARSE_POINT, nil, 0,
		&buffer[0], uint32(len(buffer)), &returned, nil); err != nil {
		return reparseLink{}, false, fmt.Errorf("read link: %w", err)
	}
	return parseReparseLink(buffer[:returned])
}
