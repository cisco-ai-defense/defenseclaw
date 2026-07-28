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

func openJudgeBodyFileNoFollow(path string, create bool) (*os.File, error) {
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
		return nil, errors.New("judge_body: create file handle")
	}
	return file, nil
}

func validateJudgeBodyPlatformTrust(_ string, info os.FileInfo, directory, _ bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("judge_body: database path ownership is unavailable")
	}
	owner := int(stat.Uid)
	effectiveUser := os.Geteuid()
	trustedOwner := owner == effectiveUser || directory && owner == 0
	if !trustedOwner {
		return errors.New("judge_body: database path has an untrusted owner")
	}
	if info.Mode().Perm()&0o022 != 0 {
		// Root-owned sticky directories such as /tmp are safe ancestors: the
		// sticky bit prevents another user from replacing this user's entries.
		if directory && owner == 0 && info.Mode()&os.ModeSticky != 0 {
			return nil
		}
		kind := "file"
		if directory {
			kind = "directory"
		}
		return fmt.Errorf("judge_body: database %s is group- or other-writable", kind)
	}
	return nil
}

func trustedJudgeBodySystemDirectoryAlias(path string, info os.FileInfo) bool {
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
	return err == nil && target.IsDir() && validateJudgeBodyPlatformTrust(resolved, target, true, false) == nil
}

func secureJudgeBodyPlatformPath(string, bool) error { return nil }

func judgeBodyModeMatches(info os.FileInfo, want os.FileMode) bool {
	return info.Mode().Perm() == want.Perm()
}

func judgeBodyImmediateDirectoryModeTrusted(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0
}
