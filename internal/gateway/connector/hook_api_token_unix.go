// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

func hookAPIValidateOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if hookAPITrustedOwner(stat.Uid) {
		return nil
	}
	return fmt.Errorf("hook API token %s uid %d is not root, current uid %d, or the defenseclaw service uid", path, stat.Uid, os.Getuid())
}

func hookAPIValidateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	if err := hookAPIValidateDirectoryChain(clean); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return err
	}
	if resolved != clean {
		return hookAPIValidateDirectoryChain(resolved)
	}
	return nil
}

func hookAPIValidateDirectoryElement(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	info, err := os.Lstat(filepath.Clean(path))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlinks are not allowed: %s", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	return hookAPIValidateDirectoryMetadata(path, info, false)
}

func hookAPIValidateDirectoryChain(clean string) error {
	for cur := clean; ; cur = filepath.Dir(cur) {
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if cur == clean || (!hookAPITrustedDarwinRootAlias(cur) && !hookAPITrustedSystemSymlink(cur, info)) {
				return fmt.Errorf("symlinks are not allowed: %s", cur)
			}
			targetInfo, err := os.Stat(cur)
			if err != nil {
				return err
			}
			if !targetInfo.IsDir() {
				return fmt.Errorf("expected directory: %s", cur)
			}
			if cur == filepath.Dir(cur) {
				break
			}
			continue
		}
		if !info.IsDir() {
			return fmt.Errorf("expected directory: %s", cur)
		}
		if err := hookAPIValidateDirectoryMetadata(cur, info, cur != clean); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func hookAPITrustedDarwinRootAlias(path string) bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	switch filepath.Clean(path) {
	case "/etc", "/tmp", "/var":
		return true
	default:
		return false
	}
}

func hookAPITrustedSystemSymlink(path string, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	parentInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o022 != 0 {
		return false
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	return ok && parentStat.Uid == 0
}

func hookAPIValidateDirectoryMetadata(path string, info os.FileInfo, allowStickyAncestor bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect directory owner: %s", path)
	}
	if mode := info.Mode().Perm(); mode&0o022 != 0 &&
		!(allowStickyAncestor && info.Mode()&os.ModeSticky != 0 && stat.Uid == 0) {
		return fmt.Errorf("%s has group/other writable mode %04o", path, mode)
	}
	if !hookAPITrustedOwner(stat.Uid) {
		return fmt.Errorf("%s uid %d is not root, current uid %d, or the defenseclaw service uid", path, stat.Uid, os.Getuid())
	}
	if err := hookAPIValidateDirectoryACL(path); err != nil {
		return err
	}
	return nil
}

func hookAPITrustedOwner(uid uint32) bool {
	if uid == 0 || int(uid) == os.Getuid() {
		return true
	}
	serviceUser, err := user.Lookup("defenseclaw")
	if err != nil {
		return false
	}
	serviceUID, err := strconv.ParseUint(serviceUser.Uid, 10, 32)
	return err == nil && uid == uint32(serviceUID)
}
