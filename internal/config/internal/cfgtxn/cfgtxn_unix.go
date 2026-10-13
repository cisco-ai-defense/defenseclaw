// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cfgtxn

import (
	"errors"
	"os"
	"syscall"
)

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
}

// tryLock takes flock(LOCK_EX) without blocking; busy reports a held lock.
// Python's file_lock.locked_file_update uses the same call.
func tryLock(f *os.File) (busy bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		return false, nil
	}
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return true, nil
	}
	return false, err
}

func unlock(f *os.File) { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

// keepOwner gives the temp file the target's owner when running as root,
// so a root writer (the enterprise lifecycle) never hands a user's config
// to root. Other callers already own what they create.
func keepOwner(tmp *os.File, target string) {
	if os.Geteuid() != 0 {
		return
	}
	info, err := os.Lstat(target)
	if err != nil {
		return
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = tmp.Chown(int(st.Uid), int(st.Gid))
	}
}

func replaceDurable(source, target string) error { return os.Rename(source, target) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
