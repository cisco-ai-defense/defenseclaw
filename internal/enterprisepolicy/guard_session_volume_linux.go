//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"

	"golang.org/x/sys/unix"
)

// publishedSessionVolumeIsReadOnly reports a path on a mount that is
// read-only (statfs ST_RDONLY, which covers a read-only bind mount too).
func publishedSessionVolumeIsReadOnly(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.ST_RDONLY != 0, nil
}

// publishedSessionFolderIsLocked reports a folder with the immutable or
// append-only attribute (chattr +i, +a), which keeps even root from adding
// or removing a file in it. statx reports both on every file system that
// can carry them; where it reports neither, FS_IOC_GETFLAGS is asked, and a
// file system that has no flags at all (ENOTTY) cannot carry them.
func publishedSessionFolderIsLocked(path string) (bool, error) {
	const attributes = unix.STATX_ATTR_IMMUTABLE | unix.STATX_ATTR_APPEND
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS, &st); err != nil {
		return false, err
	}
	if st.Attributes_mask&attributes == attributes {
		return st.Attributes&attributes != 0, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = unix.Close(fd) }()
	flags, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	if errors.Is(err, unix.ENOTTY) || errors.Is(err, unix.EOPNOTSUPP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return flags&(publishedSessionFSImmutable|publishedSessionFSAppend) != 0, nil
}

// publishedSessionFSImmutable and publishedSessionFSAppend are
// FS_IMMUTABLE_FL and FS_APPEND_FL (linux/fs.h).
const (
	publishedSessionFSImmutable = 0x10
	publishedSessionFSAppend    = 0x20
)
