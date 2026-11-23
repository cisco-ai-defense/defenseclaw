// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenDirectoryNoFollow opens a directory without following its final component.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&fs.ModeSymlink != 0 {
			return nil, ErrSymlinkRefused
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

// OpenDirectoryChildNoFollow opens one directory relative to its held parent.
func OpenDirectoryChildNoFollow(parent *os.File, name string) (*os.File, error) {
	return openChildNoFollow(parent, name, unix.O_DIRECTORY)
}

// OpenRegularChildNoFollow opens one child for inspection without following a
// symlink or blocking on a FIFO. The reader checks the opened file type.
func OpenRegularChildNoFollow(parent *os.File, name string) (*os.File, error) {
	return openChildNoFollow(parent, name, unix.O_NONBLOCK)
}

func openChildNoFollow(parent *os.File, name string, flags int) (*os.File, error) {
	if !validChildName(name) {
		return nil, fs.ErrInvalid
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), filepath.Join(parent.Name(), name)), nil
}

// ReadChildLink reads one link's stored target relative to its held parent.
func ReadChildLink(parent *os.File, name string) (string, error) {
	if !validChildName(name) {
		return "", fs.ErrInvalid
	}
	buffer := make([]byte, 4096)
	n, err := unix.Readlinkat(int(parent.Fd()), name, buffer)
	if err != nil {
		return "", err
	}
	if n == len(buffer) {
		return "", errors.New("safefile: link target exceeds the read limit")
	}
	return string(buffer[:n]), nil
}

func validChildName(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\x00")
}
