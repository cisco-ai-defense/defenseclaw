//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func secureOpenAppend(path string) (*os.File, os.FileInfo, int64, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, nil, 0, err
	}
	before, beforeErr := os.Lstat(path)
	created := os.IsNotExist(beforeErr)
	if beforeErr != nil && !created {
		return nil, nil, 0, ioFailure()
	}
	if beforeErr == nil && (before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular()) {
		return nil, nil, 0, unsafeFailure()
	}
	flags := unix.O_WRONLY | unix.O_APPEND | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if created {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	descriptor, err := unix.Open(path, flags, 0o600)
	if err == unix.EEXIST && created {
		// A same-name race never acquires the right to chmod the winner. Reopen
		// it as an existing file and apply the full owner/mode/link checks.
		created = false
		descriptor, err = unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return nil, nil, 0, ioFailure()
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, nil, 0, ioFailure()
	}
	failed := true
	defer func() {
		if failed {
			_ = file.Close()
		}
	}()
	if created {
		if err := file.Chmod(0o600); err != nil {
			return nil, nil, 0, ioFailure()
		}
	}
	opened, err := file.Stat()
	if err != nil {
		return nil, nil, 0, ioFailure()
	}
	if err := validateSecureFileInfo(opened); err != nil {
		return nil, nil, 0, err
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, nil, 0, ioFailure()
	}
	if after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return nil, nil, 0, unsafeFailure()
	}
	failed = false
	return file, opened, opened.Size(), nil
}

func secureOpenRead(path string) (*os.File, os.FileInfo, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, nil, err
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, ioFailure()
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, nil, ioFailure()
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, ioFailure()
	}
	if err := validateSecureFileInfo(info); err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) {
		_ = file.Close()
		if err != nil {
			return nil, nil, ioFailure()
		}
		return nil, nil, unsafeFailure()
	}
	return file, info, nil
}

func secureCreateExclusive(path string) (*os.File, error) {
	if err := prepareSecureParent(path); err != nil {
		return nil, err
	}
	descriptor, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, ioFailure()
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ioFailure()
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, ioFailure()
	}
	return file, nil
}

// secureMoveNoReplace uses a same-directory hard-link+unlink move. Link is
// exclusive, so a raced backup pathname is never overwritten. If unlinking the
// source fails, the new link is rolled back and the active file remains.
func secureMoveNoReplace(source, destination string) error {
	if err := os.Link(source, destination); err != nil {
		return ioFailure()
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(destination)
		return ioFailure()
	}
	return nil
}

func validateSecureFileInfo(info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return unsafeFailure()
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != uint32(os.Geteuid()) || status.Nlink != 1 {
		return unsafeFailure()
	}
	return nil
}

func validateSecureOpenFile(file *os.File) error {
	if file == nil {
		return unsafeFailure()
	}
	info, err := file.Stat()
	if err != nil {
		return ioFailure()
	}
	return validateSecureFileInfo(info)
}

func validateSecureDirectory(_ string, info os.FileInfo) error {
	if info == nil || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return unsafeFailure()
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (status.Uid != 0 && status.Uid != uint32(os.Geteuid())) {
		return unsafeFailure()
	}
	return nil
}
