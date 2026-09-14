//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// ReclaimToDirectoryOwner gives a root-created private file back to the
// operator who owns the already-trusted parent directory.
func ReclaimToDirectoryOwner(path string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) {
		return fmt.Errorf("safefile: private file path has no basename: %s", path)
	}
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("safefile: open private directory without following links %s: %w", dir, err)
	}
	directory := os.NewFile(uintptr(dirFD), dir)
	if directory == nil {
		_ = unix.Close(dirFD)
		return fmt.Errorf("safefile: bind private directory descriptor %s", dir)
	}
	defer directory.Close()
	dirInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("safefile: stat opened private directory %s: %w", dir, err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private directory is not a trusted directory: %s", dir)
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("safefile: private directory ownership is unavailable: %s", dir)
	}
	ownerUID := int(dirStat.Uid)
	ownerGID := int(dirStat.Gid)
	if ownerUID == 0 {
		return nil
	}
	if err := verifyOpenedPath(dir, dirInfo); err != nil {
		return err
	}
	fd, err := unix.Openat(int(directory.Fd()), base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("safefile: open private file without following links %s: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("safefile: bind private file descriptor %s", path)
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("safefile: stat opened private file %s: %w", path, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return fmt.Errorf("safefile: private file is not regular: %s", path)
	}
	if fileInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("safefile: private file permissions are too broad: %s", path)
	}
	fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("safefile: private file ownership is unavailable: %s", path)
	}
	if fileStat.Nlink != 1 {
		return fmt.Errorf("safefile: private file has multiple links: %s", path)
	}
	if int(fileStat.Uid) == ownerUID && int(fileStat.Gid) == ownerGID {
		return nil
	}
	if int(fileStat.Uid) != 0 && int(fileStat.Uid) != ownerUID {
		return fmt.Errorf("safefile: private file has an unrelated owner: %s", path)
	}
	if err := verifyOpenedPath(dir, dirInfo); err != nil {
		return err
	}
	if err := file.Chown(ownerUID, ownerGID); err != nil {
		return fmt.Errorf("safefile: chown private file %s to %d:%d: %w", path, ownerUID, ownerGID, err)
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("safefile: re-stat private file %s: %w", path, err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || int(afterStat.Uid) != ownerUID || int(afterStat.Gid) != ownerGID {
		return fmt.Errorf("safefile: private file ownership reclaim did not persist: %s", path)
	}
	var pathAfter unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), base, &pathAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
		pathAfter.Mode&unix.S_IFMT != unix.S_IFREG ||
		uint64(pathAfter.Dev) != uint64(afterStat.Dev) || uint64(pathAfter.Ino) != uint64(afterStat.Ino) {
		return fmt.Errorf("safefile: private file path changed during ownership reclaim: %s", path)
	}
	if err := verifyOpenedPath(dir, dirInfo); err != nil {
		return err
	}
	return nil
}

func verifyOpenedPath(path string, opened os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return fmt.Errorf("safefile: private directory path changed during ownership reclaim: %s", path)
	}
	return nil
}
