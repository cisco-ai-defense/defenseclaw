// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func validateAtomicTransformBoundDirectoryPlatform(file *os.File, requirePrivate bool) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("bound compare-and-swap directory is not a directory")
	}
	if !requirePrivate {
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("bound compare-and-swap state directory is not owned by current user")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("bound compare-and-swap state directory is not private")
	}
	return nil
}

func validateAtomicTransformBoundFilePrivatePlatform(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("bound compare-and-swap receipt is not owned by current user")
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("bound compare-and-swap receipt is not private regular data")
	}
	return nil
}

func validateAtomicTransformBoundDirectoryDurabilityPlatform(*os.File) error { return nil }

func openAtomicTransformBoundDirectoryPlatform(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func createAtomicTransformBoundFilePlatform(parent *os.File, name string, perm os.FileMode) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		uint32(perm.Perm()),
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if statErr == nil {
			statErr = fmt.Errorf("bound compare-and-swap artifact is not regular")
		}
		return nil, statErr
	}
	return file, nil
}

func openAtomicTransformBoundFilePlatform(parent *os.File, name string, _ bool) (*os.File, error) {
	fd, err := unix.Openat(
		int(parent.Fd()), name,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if statErr == nil {
			statErr = fmt.Errorf("bound compare-and-swap artifact is not regular")
		}
		return nil, statErr
	}
	return file, nil
}

func renameAtomicTransformBoundFilePlatform(
	parent, source *os.File, targetName string, replace bool,
) error {
	// The source file name is supplied through source.Name(), which is the
	// constrained basename used in the bound directory.
	sourceName := source.Name()
	var err error
	if replace {
		err = unix.Renameat(int(parent.Fd()), sourceName, int(parent.Fd()), targetName)
	} else {
		err = moveAtomicTransformPathNoReplaceAt(int(parent.Fd()), sourceName, targetName)
	}
	if errors.Is(err, os.ErrExist) {
		return errAtomicTransformConflict
	}
	return err
}

func syncAtomicTransformBoundDirectoryPlatform(parent *os.File) error {
	return parent.Sync()
}

func deleteAtomicTransformBoundFilePlatform(parent, file *os.File, name string) error {
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	// Dev/Ino are the portable identity fields used by the serialized POSIX
	// artifact identity. Compare them immediately before unlinkat.
	openedStat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || uint64(openedStat.Dev) != uint64(named.Dev) || uint64(openedStat.Ino) != uint64(named.Ino) {
		return fmt.Errorf("bound artifact name changed before unlink: %s", name)
	}
	return unix.Unlinkat(int(parent.Fd()), name, 0)
}

func createAtomicTransformBoundDeleteOnCloseFilePlatform(*os.File, string, os.FileMode) (*os.File, error) {
	return nil, fmt.Errorf("delete-on-close bootstrap receipts are unsupported on this platform")
}

func linkAtomicTransformBoundFilePlatform(*os.File, *os.File, string, func() error) error {
	return fmt.Errorf("bootstrap receipt hard links are unsupported on this platform")
}

func atomicTransformBoundLinkCountPlatform(file *os.File) (uint32, error) {
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("bootstrap receipt link count is unavailable")
	}
	return uint32(stat.Nlink), nil
}
