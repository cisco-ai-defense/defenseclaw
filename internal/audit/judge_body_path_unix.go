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

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// validateJudgeBodyPlatformTrust mirrors validateAuditDBPlatformTrust in
// audit_db_path_unix.go — same AIFW-34262 ancestor-advisory downgrade so a
// group/other-writable /opt/cisco (0775 root-owned, no sticky) doesn't fail
// the managed_enterprise gateway on startup. Structural failures (untrusted
// owner, ownership lookup) stay fatal in either mode; strict=true (the leaf,
// or managed.TrustStrictAncestorsEnv=1) keeps every verdict fatal too.
func validateJudgeBodyPlatformTrust(path string, info os.FileInfo, directory, strict bool) error {
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
		verdict := managed.NewTrustVerdict("judge_body: database %s is group- or other-writable", kind)
		advisory := !strict && managed.PlatformInstallerOwnedPath(path)
		label := fmt.Sprintf("judge body database %s", kind)
		return managed.RelaxAncestorTrustVerdict(advisory, path, label, verdict)
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

func judgeBodyPlatformPathNeedsHardening(string) (bool, error) { return false, nil }

func judgeBodyModeMatches(info os.FileInfo, want os.FileMode) bool {
	return info.Mode().Perm() == want.Perm()
}

func judgeBodyImmediateDirectoryModeTrusted(info os.FileInfo) bool {
	return info.Mode().Perm()&0o022 == 0
}
