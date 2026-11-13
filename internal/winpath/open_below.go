// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package winpath

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
)

// A file below a root that another account controls (an account's file read
// by LocalSystem) is opened from the root's handle, one element at a time,
// never by its full name: an open by name resolves every folder of the path
// with the caller's rights, so a folder swapped for a junction (to
// \RPC Control and an object manager link to a UNC or WebDAV path, a pipe or
// a device) between a check and the open would make LocalSystem connect and
// authenticate there before any check on the opened handle runs. Each element
// is opened relative to its parent's handle without following a link
// (OBJ_DONT_REPARSE, FILE_OPEN_REPARSE_POINT) and must be a plain folder (the
// last one: what BelowKind asks for), so a link fails inside the open. The
// walk is OS-independent (walkBelow) so its decisions run on every CI runner;
// OpenBelow, InspectBelow and RejectReparseBelow are the Windows openers.

// BelowKind is what the last element of a path opened below a root must be.
type BelowKind int

const (
	// BelowFile is a regular file: a folder, a device or a link is refused.
	BelowFile BelowKind = iota + 1
	// BelowDirectory is a plain folder (opened for listing).
	BelowDirectory
	// BelowAny is a regular file or a plain folder (opened to read or list).
	BelowAny
	// belowCheck is BelowAny with attribute access only (RejectReparseBelow).
	belowCheck
	// belowInspect opens the last element whatever it is, a link itself
	// included (it is reported, not followed): InspectBelow.
	belowInspect
)

// ErrNotRegularBelow is a path opened as a file (BelowFile) whose last
// element is a folder, a device or another object that is not a regular file.
var ErrNotRegularBelow = errors.New("not a regular file")

// ErrNotDirectoryBelow is a path opened as a folder (BelowDirectory) whose
// last element is not a folder.
var ErrNotDirectoryBelow = errors.New("not a folder")

// BelowInfo is what InspectBelow found at the last element of a path.
type BelowInfo struct {
	// Link is set when the last element is a reparse point (a junction, a
	// symbolic link, a mount point): it was opened itself, not followed.
	Link bool
	// Directory is set for a folder (or a link to one).
	Directory bool
	// AdminOwned is set when LocalSystem or the Administrators group owns the
	// element itself.
	AdminOwned bool
}

// NTSTATUS codes and file attributes walkBelow decides on. They are the
// golang.org/x/sys/windows values (checked at compile time in
// open_below_windows.go) and are spelled here so the decisions build and run
// on every OS.
const (
	statusStoppedOnSymlink        uint32 = 0x8000002D
	statusObjectNameNotFound      uint32 = 0xC0000034
	statusObjectPathNotFound      uint32 = 0xC000003A
	statusDeletePending           uint32 = 0xC0000056
	statusFileIsADirectory        uint32 = 0xC00000BA
	statusNotADirectory           uint32 = 0xC0000103
	statusIOReparseTagNotHandled  uint32 = 0xC0000279
	statusReparsePointEncountered uint32 = 0xC000050B

	fileAttributeDirectory    uint32 = 0x10
	fileAttributeDevice       uint32 = 0x40
	fileAttributeReparsePoint uint32 = 0x400
)

// belowOps are the primitives walkBelow uses: on Windows a no-follow CreateFile
// of the root and handle-relative NtCreateFile calls; in tests a fake.
type belowOps[H any] struct {
	// openRoot opens root itself without following a link.
	openRoot func(root string) (H, error)
	// openChild opens name relative to parent without following a link; last
	// marks the path's last element (opened for kind).
	openChild func(parent H, name string, last bool, kind BelowKind) (H, error)
	// attributes are the opened element's own file attributes.
	attributes func(H) (uint32, error)
	// status is the NTSTATUS code of an open error, if it carries one.
	status func(error) (uint32, bool)
	close  func(H)
}

// walkBelow opens root without following a link, checks it is a plain
// folder, then opens each element of path below root relative to the
// previous handle and checks it: a reparse point anywhere (root included) is
// ErrLinkBelowRoot naming the element (for belowInspect the last element may
// be one), an element above the last that is not a folder means the path does
// not exist (fs.ErrNotExist, as Windows reports a path through a file), and
// the last element must be what kind asks for (ErrNotRegularBelow,
// ErrNotDirectoryBelow). Every handle but the returned one is closed. The
// folders above root are not checked: they belong to whoever placed root (a
// redirected profile folder may be a junction).
func walkBelow[H any](root, path string, kind BelowKind, ops belowOps[H]) (H, uint32, error) {
	var zero H
	plainRoot := plainWindowsPath(root)
	if plainRoot == "" {
		return zero, 0, fmt.Errorf("%w: empty root", errNotBelowRoot)
	}
	rest, err := windowsRelativeBelow(plainRoot, plainWindowsPath(path))
	if err != nil {
		return zero, 0, err
	}
	for _, name := range rest {
		// A colon names a stream or a device; NUL ends the name early.
		if strings.ContainsAny(name, ":\x00") {
			return zero, 0, fmt.Errorf("%w: %s has an element with a colon", errNotBelowRoot, path)
		}
	}
	handle, err := ops.openRoot(plainRoot)
	if err != nil {
		return zero, 0, belowOpenError(err, plainRoot, false, kind, ops.status)
	}
	attributes, err := ops.attributes(handle)
	if err == nil {
		switch {
		case attributes&fileAttributeReparsePoint != 0:
			err = fmt.Errorf("%w: %s", ErrLinkBelowRoot, plainRoot)
		case attributes&fileAttributeDirectory == 0:
			err = fmt.Errorf("%s: %w", plainRoot, ErrNotDirectoryBelow)
		}
	} else {
		err = fmt.Errorf("inspect %s: %w", plainRoot, err)
	}
	if err != nil {
		ops.close(handle)
		return zero, 0, err
	}
	current := plainRoot
	for index, name := range rest {
		last := index == len(rest)-1
		current = joinWindowsElement(current, name)
		child, err := ops.openChild(handle, name, last, kind)
		ops.close(handle)
		if err != nil {
			return zero, 0, belowOpenError(err, current, last, kind, ops.status)
		}
		handle = child
		attributes, err = ops.attributes(handle)
		if err != nil {
			err = fmt.Errorf("inspect %s: %w", current, err)
		} else {
			err = checkBelowAttributes(attributes, current, last, kind)
		}
		if err != nil {
			ops.close(handle)
			return zero, 0, err
		}
	}
	return handle, attributes, nil
}

// belowOpenError maps the error of opening element (the path's last element
// when last) to the walk's errors.
func belowOpenError(err error, element string, last bool, kind BelowKind, status func(error) (uint32, bool)) error {
	if code, ok := status(err); ok {
		switch code {
		case statusReparsePointEncountered, statusStoppedOnSymlink, statusIOReparseTagNotHandled:
			return fmt.Errorf("%w: %s", ErrLinkBelowRoot, element)
		case statusObjectNameNotFound, statusObjectPathNotFound, statusDeletePending:
			return fmt.Errorf("%s: %w", element, fs.ErrNotExist)
		case statusNotADirectory:
			if last && kind == BelowDirectory {
				return fmt.Errorf("%s: %w", element, ErrNotDirectoryBelow)
			}
			return fmt.Errorf("%s: %w", element, fs.ErrNotExist)
		case statusFileIsADirectory:
			return fmt.Errorf("%s: %w", element, ErrNotRegularBelow)
		}
	}
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s: %w", element, fs.ErrNotExist)
	}
	return fmt.Errorf("open %s: %w", element, err)
}

// checkBelowAttributes decides on the attributes of an opened element.
func checkBelowAttributes(attributes uint32, element string, last bool, kind BelowKind) error {
	reparse := attributes&fileAttributeReparsePoint != 0
	directory := attributes&fileAttributeDirectory != 0
	if !last {
		if reparse {
			return fmt.Errorf("%w: %s", ErrLinkBelowRoot, element)
		}
		if !directory {
			return fmt.Errorf("%s: %w", element, fs.ErrNotExist)
		}
		return nil
	}
	if kind == belowInspect {
		return nil
	}
	if reparse {
		return fmt.Errorf("%w: %s", ErrLinkBelowRoot, element)
	}
	switch {
	case attributes&fileAttributeDevice != 0 && kind != BelowDirectory:
		return fmt.Errorf("%s: %w", element, ErrNotRegularBelow)
	case kind == BelowFile && directory:
		return fmt.Errorf("%s: %w", element, ErrNotRegularBelow)
	case kind == BelowDirectory && !directory:
		return fmt.Errorf("%s: %w", element, ErrNotDirectoryBelow)
	}
	return nil
}
