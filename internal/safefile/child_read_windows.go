// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// OpenDirectoryNoFollow opens a plain directory through handle-relative
// lookups from its volume/share anchor, refusing reparse points on the way.
// The returned handle anchors all subsequent child operations.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	file, err := winpath.OpenDirectoryNoFollow(path)
	return file, childReadError(err)
}

// OpenDirectoryChildNoFollow opens one plain child directory from parent.
func OpenDirectoryChildNoFollow(parent *os.File, name string) (*os.File, error) {
	file, err := winpath.OpenChildNoFollow(parent, name, winpath.BelowDirectory)
	return file, childReadError(err)
}

// OpenRegularChildNoFollow opens one regular child without following a link
// and denies write sharing for the lifetime of the returned handle.
func OpenRegularChildNoFollow(parent *os.File, name string) (*os.File, error) {
	file, err := winpath.OpenChildNoFollow(parent, name, winpath.BelowFile)
	return file, childReadError(err)
}

// ReadChildLink reads link metadata through parent without opening its target.
func ReadChildLink(parent *os.File, name string) (string, error) {
	target, err := winpath.ReadChildLink(parent, name)
	return target, childReadError(err)
}

func childReadError(err error) error {
	if errors.Is(err, winpath.ErrLinkBelowRoot) {
		return fmt.Errorf("%w: %w", ErrSymlinkRefused, err)
	}
	return err
}

// OpenDirectoryResolved opens the directory at path as OpenDirectoryNoFollow
// does. When a reparse point on the way refuses that, it resolves path once
// to its final path and opens that reparse-free spelling no-follow instead,
// accepting it only when trusted approves every folder on it, from the
// volume root down; a refusal is ErrSymlinkRefused. trusted gets the opened
// handle for the resolved folder and nil for each folder above it, whose
// owner is read by name after the open pinned a chain with no reparse point.
// It returns the spelling it opened.
func OpenDirectoryResolved(path string, trusted func(dir *os.File, path string) bool) (*os.File, string, error) {
	dir, err := OpenDirectoryNoFollow(path)
	if !errors.Is(err, ErrSymlinkRefused) || trusted == nil {
		return dir, path, err
	}
	resolved, err := finalDirectoryPath(path)
	if err != nil {
		return nil, "", err
	}
	dir, err = OpenDirectoryNoFollow(resolved)
	if err != nil {
		return nil, "", err
	}
	for folder, opened := resolved, dir; ; opened = nil {
		if !trusted(opened, folder) {
			_ = dir.Close()
			return nil, "", fmt.Errorf("%w: %s has an untrusted owner", ErrSymlinkRefused, folder)
		}
		parent := filepath.Dir(folder)
		if parent == folder {
			return dir, resolved, nil
		}
		folder = parent
	}
}

// finalDirectoryPath is the path the system reaches the folder at path by,
// through every junction and symbolic link on the way, in its plain spelling.
// A path on a local disk is resolved one element at a time without letting
// Windows follow a link (winpath.LocalPathResolved), so a link to a share or
// a device is refused (winpath.ErrPathNotLocal) before anything opens it: a
// scan never connects to a server the scanned account named (GAP-2008). A
// path that is not on a local disk to begin with, a profile on a share, is
// opened as named.
func finalDirectoryPath(path string) (string, error) {
	var file *os.File
	local, err := winpath.LocalPathResolved(path)
	switch {
	case err == nil:
		file, err = OpenDirectoryNoFollow(local)
	case errors.Is(err, winpath.ErrPathNotLocal) && !winpath.LocalVolumePath(path):
		file, err = os.Open(path)
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	size := uint32(windows.MAX_PATH)
	for {
		buffer := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if n >= size {
			size = n + 1
			continue
		}
		final := windows.UTF16ToString(buffer[:n])
		switch {
		case strings.HasPrefix(final, `\\?\UNC\`):
			return `\\` + final[len(`\\?\UNC\`):], nil
		case strings.HasPrefix(final, `\\?\`):
			return final[len(`\\?\`):], nil
		}
		return final, nil
	}
}

// RegularChildSize is the size of name inside parent, read relative to the
// held parent with attribute access only: never by a path that could be
// resolved again, and without a share conflict with a writer holding the
// file. regular is false for a folder, a link or a device.
func RegularChildSize(parent *os.File, name string) (size int64, regular bool, err error) {
	attributes, size, err := winpath.StatChildNoFollow(parent, name)
	if err != nil {
		return 0, false, childReadError(err)
	}
	const notRegular = windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT | windows.FILE_ATTRIBUTE_DEVICE
	return size, attributes&notRegular == 0, nil
}
