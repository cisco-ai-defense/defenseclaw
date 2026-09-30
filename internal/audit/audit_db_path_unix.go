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

	"github.com/defenseclaw/defenseclaw/internal/runtimeowner"
	"golang.org/x/sys/unix"
)

func openAuditDBFileNoFollow(path string, create, _ bool) (*os.File, error) {
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

// auditDBPinnedFileDeleted reports that a pinned file is no longer linked
// anywhere, as after SQLite deletes a WAL or SHM file on its last close.
func auditDBPinnedFileDeleted(file *os.File) (bool, error) {
	links, err := auditDBPinnedLinkCount(file)
	return links == 0, err
}

// validateAuditDBSidecarLinkCount refuses a sidecar that is a hard link to
// another file. SQLite never creates one.
func validateAuditDBSidecarLinkCount(file *os.File) error {
	links, err := auditDBPinnedLinkCount(file)
	if err != nil {
		return err
	}
	if links != 1 {
		return fmt.Errorf("audit: database file has %d hard links, expected exactly 1", links)
	}
	return nil
}

func auditDBPinnedLinkCount(file *os.File) (uint64, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("audit: database file link count is unavailable")
	}
	return uint64(stat.Nlink), nil
}

func auditDBPlatformFileNeedsHardening(*os.File) (bool, error) { return false, nil }

// Preserve the Unix sidecar repair seam: chmod/permission hardening remains
// handle-bound and is intentionally repeated during sidecar discovery.
func auditDBPlatformSidecarNeedsHardening(*os.File) (bool, error) { return true, nil }

func auditDBPlatformHardeningNeedsCapabilityReopen() bool { return false }

func validateAuditDBPlatformTrust(_ string, info os.FileInfo, directory, _ bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("audit: database path ownership is unavailable")
	}
	owner := int(stat.Uid)
	if !runtimeowner.Trusted(stat.Uid) {
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

// auditDBOpenElsewhere reports another process that holds a SQLite lock on the
// database: its PENDING, RESERVED and SHARED lock bytes start at 1 GiB. The
// caller holds no connection, so closing this probe drops no lock of its own.
func auditDBOpenElsewhere(path string) error {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	probe := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0x40000000, Len: 512}
	if err := unix.FcntlFlock(file.Fd(), unix.F_GETLK, &probe); err != nil {
		return fmt.Errorf("audit: check whether the database is in use: %w", err)
	}
	if probe.Type != unix.F_UNLCK {
		return fmt.Errorf("audit: the database is still open in process %d; stop it and start the gateway again", probe.Pid)
	}
	return nil
}
