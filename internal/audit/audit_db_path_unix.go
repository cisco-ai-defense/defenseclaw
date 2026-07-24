//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openAuditDBFileNoFollow(path string, create bool) (*os.File, error) {
	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if create {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	fd, err := syscall.Open(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("audit: create file handle")
	}
	return file, nil
}

func validateAuditDBPlatformTrust(_ string, info os.FileInfo, directory, _ bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("audit: database path ownership is unavailable")
	}
	owner := int(stat.Uid)
	effectiveUser := os.Geteuid()
	if owner != effectiveUser && !(directory && owner == 0) {
		return errors.New("audit: database path has an untrusted owner")
	}
	if info.Mode().Perm()&0o022 != 0 {
		if directory && owner == 0 && info.Mode()&os.ModeSticky != 0 {
			return nil
		}
		kind := "file"
		if directory {
			kind = "directory"
		}
		return fmt.Errorf("audit: database %s is group- or other-writable", kind)
	}
	return nil
}

// macOS and some Unix installations expose a root-level system directory as a
// root-owned symlink (for example /tmp -> /private/tmp). Permit only that
// narrow system alias; operator-controlled symlinks at any lower level fail.
func trustedAuditDBSystemDirectoryAlias(path string, info os.FileInfo) bool {
	if filepath.Dir(path) != string(os.PathSeparator) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) == filepath.Clean(path) {
		return false
	}
	target, err := os.Stat(resolved)
	return err == nil && target.IsDir() && validateAuditDBPlatformTrust(resolved, target, true, false) == nil
}

func secureAuditDBPlatformPath(string, bool) error { return nil }

func secureAuditDBPlatformFile(*os.File, bool) error { return nil }

func auditDBModeMatches(info os.FileInfo, want os.FileMode) bool {
	return info.Mode().Perm() == want.Perm()
}

func auditDBImmediateDirectoryModeTrusted(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0
}
