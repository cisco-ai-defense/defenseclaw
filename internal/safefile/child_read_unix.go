// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

// OpenDirectoryNoFollow pins a directory through no-follow lookups from /.
// No user-controlled ancestor is resolved through a symlink.
func OpenDirectoryNoFollow(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// macOS spells these fixed, system-owned roots through /private. Use the
	// physical spelling rather than following even those symlinks. Never resolve
	// arbitrary descendants with EvalSymlinks.
	if runtime.GOOS == "darwin" {
		for _, alias := range []string{"/var", "/tmp", "/etc"} {
			if abs == alias || strings.HasPrefix(abs, alias+"/") {
				abs = "/private" + abs
				break
			}
		}
	}
	flags := unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	rootMode := directorySearchMode
	if abs == "/" {
		rootMode = unix.O_RDONLY
	}
	fd, err := unix.Open("/", rootMode|flags, 0)
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	for i, name := range components {
		if name == "" {
			continue
		}
		mode := directorySearchMode
		if i == len(components)-1 {
			mode = unix.O_RDONLY
		}
		next, openErr := unix.Openat(fd, name, mode|flags, 0)
		if openErr != nil {
			var info unix.Stat_t
			if statErr := unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW); statErr == nil && info.Mode&unix.S_IFMT == unix.S_IFLNK {
				openErr = ErrSymlinkRefused
			}
			_ = unix.Close(fd)
			return nil, openErr
		}
		_ = unix.Close(fd)
		fd = next
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
