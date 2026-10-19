// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// This ordinary private file is deliberately not a memfd: Bubblewrap reopens
// its fixed locator in each cloned mount namespace and compares the held object.
// The host driver proved its creator-mount reachability/no-IDMAP before cloning.
// Here the inherited root and loader must still refer to the same original mount.
func verifyDriverVersionLoader(root, file *os.File, closeOnExec bool) error {
	if root == nil || file == nil || privateDirectory(root) != nil {
		return errors.New("fixed loader root absent")
	}
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0500 || before.Uid != uint32(os.Geteuid()) || before.Nlink != 1 || before.Size != claudeLoaderSize {
		return errors.New("fixed loader metadata differs")
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	fdflags, fdErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil || fdErr != nil || !versionLoaderFlags(flags, fdflags, closeOnExec) {
		return errors.New("fixed loader descriptor rights differ")
	}
	var sourceFS, rootFS unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &sourceFS) != nil || unix.Fstatfs(int(root.Fd()), &rootFS) != nil || sourceFS.Type != rootFS.Type || sourceFS.Fsid != rootFS.Fsid || sourceFS.Flags&unix.ST_NOEXEC != 0 {
		return errors.New("fixed loader filesystem differs")
	}
	switch sourceFS.Type {
	case unix.EXT4_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
	default:
		return errors.New("fixed loader local filesystem unsupported")
	}
	var a, b unix.Statx_t
	if unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &a) != nil || unix.Statx(int(root.Fd()), "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_MNT_ID, &b) != nil || a.Mask&unix.STATX_MNT_ID == 0 || b.Mask&unix.STATX_MNT_ID == 0 || a.Mnt_id != b.Mnt_id {
		return errors.New("fixed loader held mount differs")
	}
	current, err := openRelative(root, claudeLoaderLeaf, unix.O_RDONLY)
	if err != nil {
		return errors.New("fixed loader entry missing")
	}
	defer current.Close()
	var named unix.Stat_t
	if unix.Fstat(int(current.Fd()), &named) != nil || named.Dev != before.Dev || named.Ino != before.Ino || named.Mode != before.Mode || named.Nlink != 1 || named.Size != before.Size {
		return errors.New("fixed loader entry identity differs")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(file, 0, claudeLoaderSize+1))
	if err != nil || n != claudeLoaderSize || hex.EncodeToString(hash.Sum(nil)) != claudeLoaderSHA || unix.Fstat(int(file.Fd()), &after) != nil || !sameLoaderMetadata(before, after) {
		return errors.New("fixed loader bytes or metadata changed")
	}
	return nil
}

func sameLoaderMetadata(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Only the exact independently reviewed input is copied. Both source and fresh
// destination are held throughout; names are never used as image authority.
func copyVersionLoader(artifacts *os.File, fixture *fixtureCapabilities) (resultErr error) {
	if artifacts == nil || fixture == nil || fixture.root == nil || fixture.loader != nil {
		return errors.New("fixed loader copy owner refused")
	}
	source, data, err := boundedFile(artifacts, "images/musl-loader", claudeLoaderSize, claudeLoaderSHA)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()
	var sourceBefore, sourceAfter unix.Stat_t
	if unix.Fstat(int(source.Fd()), &sourceBefore) != nil || int64(len(data)) != claudeLoaderSize {
		return errors.New("fixed reviewed loader size differs")
	}
	fd, err := unix.Openat(int(fixture.root.Fd()), claudeLoaderLeaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0500)
	if err != nil {
		return err
	}
	writer := os.NewFile(uintptr(fd), "fixed-exclusive-loader-writer")
	// Keep the allocated descriptor under the existing fixture owner even if
	// writing, syncing or closing fails; no clone or grant follows such failure.
	fixture.loader = writer
	var copied unix.Stat_t
	if unix.Fstat(fd, &copied) != nil {
		return errors.New("fixed new loader identity unavailable")
	}
	n, writeErr := writer.Write(data)
	syncErr := writer.Sync()
	closeErr := writer.Close()
	if closeErr == nil {
		fixture.loader = nil
	}
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil || n != len(data) {
		return errors.Join(errors.New("fixed loader copy incomplete"), err)
	}
	reader, err := openRelative(fixture.root, claudeLoaderLeaf, unix.O_RDONLY)
	if err != nil {
		return err
	}
	fixture.loader = reader
	var reopened unix.Stat_t
	if unix.Fstat(int(reader.Fd()), &reopened) != nil || copied.Dev != reopened.Dev || copied.Ino != reopened.Ino || !sameLoaderMetadataExceptSize(copied, reopened) {
		return errors.New("fixed loader copy replaced")
	}
	if unix.Fstat(int(source.Fd()), &sourceAfter) != nil || !sameLoaderMetadata(sourceBefore, sourceAfter) {
		return errors.New("fixed reviewed loader source changed")
	}
	// Sample the source again after copying, with its original FD still held.
	hash := sha256.New()
	if n, err := io.Copy(hash, io.NewSectionReader(source, 0, claudeLoaderSize+1)); err != nil || n != claudeLoaderSize || hex.EncodeToString(hash.Sum(nil)) != claudeLoaderSHA {
		return errors.New("fixed reviewed loader source bytes changed")
	}
	mount, err := verifyCreatorMount(reader)
	rootMount, rootErr := verifyCreatorMount(fixture.root)
	if err != nil || rootErr != nil || mount != rootMount {
		return errors.Join(errors.New("fixed copied loader creator mount differs"), err, rootErr)
	}
	return verifyDriverVersionLoader(fixture.root, reader, true)
}

func sameLoaderMetadataExceptSize(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Uid == b.Uid && a.Gid == b.Gid
}

func versionLoaderFlags(flags, descriptorFlags int, closeOnExec bool) bool {
	return flags&unix.O_ACCMODE == unix.O_RDONLY && (descriptorFlags&unix.FD_CLOEXEC != 0) == closeOnExec
}
