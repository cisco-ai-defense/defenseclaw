// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"os"

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
