// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// errLongPathTooLong is the answer of the file system that does not fit the
// buffer asked with.
var errLongPathTooLong = errors.New("long path name does not fit the buffer")

// osExpandWindowsShortNames asks the file system for the long form of a
// drive-letter path. When the whole path does not exist (a file about to be
// created), its longest existing folder is expanded and the rest is kept. Any
// other failure (a folder that cannot be listed) is returned, with the path
// as written, because the file system did not say what the names stand for.
func osExpandWindowsShortNames(path string, verbatim bool) (string, error) {
	rest := ""
	for current := path; ; {
		long, err := longPathName(current, verbatim)
		if err == nil {
			return long + rest, nil
		}
		if !windowsPathDoesNotExist(err) {
			return path, err
		}
		parent := current[:strings.LastIndex(current, "/")+1]
		if len(parent) <= 3 || len(parent) >= len(current) {
			return path, nil
		}
		rest = current[len(parent)-1:] + rest
		current = parent[:len(parent)-1]
	}
}

// windowsPathDoesNotExist reports the answers of the file system that say a
// name is not there, as opposed to one that cannot be looked at. The portable
// "does not exist" answer (fs.ErrNotExist, which os.ErrNotExist is) counts as
// well as the Win32 codes: a caller that reaches the file system through the
// os package is answered with it.
func windowsPathDoesNotExist(err error) bool {
	if errors.Is(err, fs.ErrNotExist) {
		return true
	}
	for _, missing := range []error{
		windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND, windows.ERROR_INVALID_NAME,
		windows.ERROR_BAD_PATHNAME, windows.ERROR_DIRECTORY, windows.ERROR_INVALID_DRIVE,
		windows.ERROR_BAD_NETPATH, windows.ERROR_BAD_NET_NAME,
	} {
		if errors.Is(err, missing) {
			return true
		}
	}
	return false
}

// longPathName is GetLongPathName of a drive-letter path in forward-slash
// spelling. A verbatim path is asked with the extended-length prefix and
// answered without it: without the prefix the call normalizes the name, and a
// name with trailing dots or spaces would be answered as the file without them.
func longPathName(path string, verbatim bool) (string, error) {
	spelled := filepath.FromSlash(path)
	if verbatim {
		spelled = `\\?\` + spelled
	}
	native, err := windows.UTF16PtrFromString(spelled)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetLongPathName(native, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", err
	}
	if length == 0 || int(length) > len(buffer) {
		return "", errLongPathTooLong
	}
	return filepath.ToSlash(strings.TrimPrefix(windows.UTF16ToString(buffer[:length]), `\\?\`)), nil
}

// osWindowsProfileFolder reports a folder (drive-letter path in forward-slash
// spelling) that holds the entries of a user profile (holdsProfileEntries). A
// folder the file system cannot answer for (access denied, an I/O error)
// reports false with the error.
func osWindowsProfileFolder(dir string) (bool, error) {
	return holdsProfileEntries(dir, func(path string) (os.FileInfo, error) {
		return os.Stat(filepath.FromSlash(path))
	})
}
