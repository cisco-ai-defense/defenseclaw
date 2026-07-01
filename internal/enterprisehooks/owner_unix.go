//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func resolveOwner(home string, uid, gid int) (int, int, error) {
	if uid < 0 || gid < 0 {
		info, err := os.Stat(home)
		if err != nil {
			return 0, 0, fmt.Errorf("enterprise hooks: stat user home owner: %w", err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("enterprise hooks: cannot inspect user home owner")
		}
		if uid < 0 {
			uid = int(st.Uid)
		}
		if gid < 0 {
			gid = int(st.Gid)
		}
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("enterprise hooks: refusing to target uid 0")
	}
	return uid, gid, nil
}

func validateHomeOwner(home string, uid int) error {
	ok, actual := fileOwnerMatches(home, uid)
	if !ok {
		return fmt.Errorf("enterprise hooks: user home %s owner uid=%d does not match target uid=%d", home, actual, uid)
	}
	return nil
}

func fileOwnerMatches(path string, uid int) (bool, int) {
	if uid < 0 {
		return true, uid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, -1
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, -1
	}
	return int(st.Uid) == uid, int(st.Uid)
}

func withOwnerCredentials(uid, gid int, fn func() error) (err error) {
	if uid < 0 || gid < 0 {
		return fn()
	}
	euid := os.Geteuid()
	egid := os.Getegid()
	if euid != 0 {
		if euid != uid || egid != gid {
			return fmt.Errorf("enterprise hooks: cannot drop to uid=%d gid=%d from unprivileged euid=%d egid=%d", uid, gid, euid, egid)
		}
		oldUmask := syscall.Umask(0o077)
		defer syscall.Umask(oldUmask)
		return fn()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origGroups, groupsErr := syscall.Getgroups()
	if groupsErr != nil {
		return fmt.Errorf("enterprise hooks: inspect supplementary groups: %w", groupsErr)
	}
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)

	restore := func() error {
		var errs []error
		if setErr := syscall.Seteuid(euid); setErr != nil {
			errs = append(errs, fmt.Errorf("restore euid %d: %w", euid, setErr))
		}
		if setErr := syscall.Setegid(egid); setErr != nil {
			errs = append(errs, fmt.Errorf("restore egid %d: %w", egid, setErr))
		}
		if setErr := syscall.Setgroups(origGroups); setErr != nil {
			errs = append(errs, fmt.Errorf("restore supplementary groups: %w", setErr))
		}
		if len(errs) > 0 {
			return fmt.Errorf("enterprise hooks: restore credentials: %v", errs)
		}
		return nil
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil && err == nil {
			err = restoreErr
		}
	}()

	if err := syscall.Setgroups([]int{gid}); err != nil {
		return fmt.Errorf("enterprise hooks: narrow supplementary groups to gid=%d: %w", gid, err)
	}
	if err := syscall.Setegid(gid); err != nil {
		return fmt.Errorf("enterprise hooks: drop egid to %d: %w", gid, err)
	}
	if err := syscall.Seteuid(uid); err != nil {
		return fmt.Errorf("enterprise hooks: drop euid to %d: %w", uid, err)
	}
	return fn()
}

func chmodOwnedPath(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s before chmod: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing chmod of symlink %s", path)
	}
	const relevantMode = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if info.Mode()&relevantMode == mode&relevantMode {
		return nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("enterprise hooks: chmod %s: %w", path, err)
	}
	return nil
}

func lchownInstallFootprint(uid, gid int, dataDir string, footprint connector.AgentPaths, hookConfigPaths []string) error {
	if uid < 0 || gid < 0 {
		return nil
	}
	if os.Geteuid() != 0 {
		return nil
	}
	if err := chownTree(dataDir, uid, gid); err != nil {
		return err
	}
	for _, path := range append(append([]string{}, footprint.PatchedFiles...), hookConfigPaths...) {
		if path == "" {
			continue
		}
		if err := lchownIfNeeded(path, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown %s: %w", path, err)
		}
	}
	for _, path := range append(append([]string{}, footprint.GeneratedFiles...), footprint.GeneratedExecutables...) {
		if path == "" {
			continue
		}
		if err := lchownIfNeeded(path, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: lchown %s: %w", path, err)
		}
	}
	for _, path := range footprint.CreatedDirs {
		if path == "" {
			continue
		}
		if err := chownTree(path, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func chownTree(root string, uid, gid int) error {
	if _, err := os.Lstat(root); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("enterprise hooks: inspect %s: %w", root, err)
	}
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("enterprise hooks: walk %s: %w", path, err)
		}
		if err := lchownIfNeeded(path, uid, gid); err != nil {
			return fmt.Errorf("enterprise hooks: chown %s: %w", path, err)
		}
		return nil
	})
}

func lchownIfNeeded(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot inspect owner")
	}
	if int(st.Uid) == uid && int(st.Gid) == gid {
		return nil
	}
	return os.Lchown(path, uid, gid)
}
