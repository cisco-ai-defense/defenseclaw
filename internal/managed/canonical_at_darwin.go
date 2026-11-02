//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// EnsureCanonicalAt is EnsureCanonical for an object inside a folder a
// non-root user can write, such as a user's ~/.defenseclaw. The object is
// opened relative to parentFD, a descriptor the caller opened without
// following links, so a component swapped for a symlink above the object
// can never redirect the repair. The ACL is stripped through the object's
// own descriptor. parentPath names parentFD for logging and for the ACL
// read. A missing object is reported, not created.
func EnsureCanonicalAt(parentFD int, parentPath, name string, kind ObjectKind, opts CanonicalOptions) (CanonicalResult, error) {
	path := filepath.Join(parentPath, name)
	result := CanonicalResult{Path: path, Kind: kind}
	form, ok := darwinCanonicalFormFor(kind, opts)
	if !ok || name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		result.Outcome = CanonicalStructural
		result.Err = fmt.Errorf("invalid managed object %q of kind %q", path, kind)
		reportCanonicalResult(result, opts)
		return result, result.Err
	}
	object, err := openDarwinObjectAt(parentFD, path, name, kind)
	return canonicalizeOpenedDarwin(result, form, object, err, opts, true)
}

// IsStructuralCanonicalError reports whether err is a structural finding
// from EnsureCanonical or EnsureCanonicalAt: a symlink, the wrong object
// type, a hard-linked file, a non-local volume, or an object swapped during
// inspection.
func IsStructuralCanonicalError(err error) bool {
	var structural darwinStructuralError
	return errors.As(err, &structural)
}

func openDarwinObjectAt(parentFD int, path, name string, kind ObjectKind) (*darwinObject, error) {
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if kind.Directory() {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Openat(parentFD, name, flags, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, structuralf("%s is a symlink; managed objects are never followed", path)
	case errors.Is(err, unix.ENOTDIR):
		return nil, structuralf("%s is not a directory", path)
	case err != nil:
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	object := &darwinObject{path: path, kind: kind, fd: fd, parentFD: parentFD, name: name}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		object.close()
		return nil, fmt.Errorf("fstat %s: %w", path, err)
	}
	if err := checkDarwinStructure(path, kind, &st, fd); err != nil {
		object.close()
		return nil, err
	}
	object.dev, object.ino = st.Dev, st.Ino
	return object, nil
}

// kauthNone is KAUTH_UID_NONE and KAUTH_GID_NONE: leave the owner or group
// unchanged.
const kauthNone = ^uint32(0) - 100

// stripDarwinACLFD removes every ACL entry from the object fd names. It is
// fchmodx_np with _FILESEC_REMOVE_ACL: fchmod_extended with the owner,
// group and mode left unchanged and a filesec of 1.
var stripDarwinACLFD = func(fd int) error {
	_, _, errno := unix.Syscall6(
		unix.SYS_FCHMOD_EXTENDED,
		uintptr(fd),
		uintptr(kauthNone),
		uintptr(kauthNone),
		^uintptr(0),
		1,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
