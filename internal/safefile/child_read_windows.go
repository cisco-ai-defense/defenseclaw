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
// volume root down; a refusal is ErrSymlinkRefused. Owners are read by name
// after the open pinned a chain with no reparse point. It returns the
// spelling it opened.
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
	for folder := resolved; ; {
		if !trusted(dir, folder) {
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
func finalDirectoryPath(path string) (string, error) {
	file, err := os.Open(path)
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
