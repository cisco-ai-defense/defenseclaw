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

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// HomeState classifies a standalone Unix target home before any mutation.
type HomeState int

const (
	// HomeAvailable is a real, trusted home the worker may reconcile.
	HomeAvailable HomeState = iota
	// HomePending is a home that does not exist yet or cannot be read
	// right now (pam_mkhomedir not run, systemd-homed or ecryptfs locked,
	// automount or NFS unavailable). The target waits; it is not a trust
	// failure and does not make the host unready.
	HomePending
	// HomeUntrusted is a trust violation: symlinked home, wrong owner,
	// group/other-writable home, or a world-writable ancestor such as /tmp.
	HomeUntrusted
)

// HomeCheck is the classification result.
type HomeCheck struct {
	State  HomeState
	Reason string
	Inode  uint64
	// AccessDenied marks a pending home whose root the caller was refused
	// (EACCES/EPERM). That can be infrastructure (an NFS parent the
	// squashed root cannot search), so it stays pending for a home that
	// was never available; callers that know the home was available
	// before treat it as untrusted.
	AccessDenied bool
	// LooseMode marks an untrusted home whose only problem is group or
	// other write permission: a real directory the target uid owns under
	// trusted ancestors. Its owner can tighten it (the per-user worker
	// does, for an enrolled target) without any root write in the home.
	LooseMode bool
}

// ecryptfsLockedMarkers are the files ecryptfs-utils leaves in a locked
// (unmounted) private home.
var ecryptfsLockedMarkers = []string{"Access-Your-Private-Data.desktop", ".ecryptfs"}

var (
	// ecryptfsPrivateRoot is where ecryptfs-setup-private keeps every
	// user's encrypted tree; a user cannot create entries in it.
	ecryptfsPrivateRoot = "/home/.ecryptfs"
	// ecryptfsRootOwnerOK accepts the owner of ecryptfsPrivateRoot;
	// unprivileged tests replace it.
	ecryptfsRootOwnerOK = func(uid uint32) bool { return uid == 0 }
	// unixMountAt returns the mount whose mount point is exactly path, if
	// any; replaced in tests.
	unixMountAt = platformMountAt
	// unixLiveSession reports whether uid has a live login session (or a
	// lingering user manager); replaced in tests.
	unixLiveSession = platformLiveSession
)

// unixMount is one mount-table entry.
type unixMount struct {
	FSType string
	// Owner is the uid that mounted a user-mountable filesystem (FUSE's
	// user_id, macOS f_owner); -1 when the table does not say.
	Owner int
}

// userMounted reports a filesystem a non-root user mounted. Its server
// answers the guardian's own stat calls, so it can refuse, fail or hang
// them at will.
func (m unixMount) userMounted() bool {
	if m.Owner > 0 {
		return true
	}
	fstype := strings.ToLower(m.FSType)
	isFUSE := fstype == "fuse" || fstype == "fuseblk" || strings.HasPrefix(fstype, "fuse.")
	return isFUSE && m.Owner != 0
}

// CheckUnixTargetHome classifies home for uid without writing anything.
//
// Nothing the user controls can make a home pending: a user-mounted
// filesystem over the home is untrusted before the home is even stat'ed,
// and a locked ecryptfs home is recognized only from the root-owned
// ecryptfs layout with no filesystem mounted over the home, and only while
// the user has no live session (a user who is logged in has an unlocked
// home, or runs agents from the lower directory, which must then be
// protected).
func CheckUnixTargetHome(home string, uid int) HomeCheck {
	clean := filepath.Clean(home)
	if home == "" || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %q is not an absolute non-root path", home)}
	}
	if reason := worldWritableAncestor(clean); reason != "" {
		return HomeCheck{State: HomeUntrusted, Reason: reason}
	}
	mount, mounted, mountErr := unixMountAt(clean)
	if mountErr == nil && mounted && mount.userMounted() {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is covered by a %s filesystem mounted by a user", clean, mount.FSType)}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return HomeCheck{State: HomePending, AccessDenied: true, Reason: fmt.Sprintf("user home %s refused inspection: %v", clean, err)}
		}
		if pendingErrno(err) {
			return HomeCheck{State: HomePending, Reason: fmt.Sprintf("user home %s is not available yet: %v", clean, err)}
		}
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("inspect user home %s: %v", clean, err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is a symlink", clean)}
	}
	if !info.IsDir() {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is not a directory", clean)}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("cannot inspect user home %s owner", clean)}
	}
	if int(st.Uid) != uid {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s owner uid=%d does not match target uid=%d", clean, st.Uid, uid)}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return HomeCheck{State: HomeUntrusted, LooseMode: true, Inode: uint64(st.Ino), Reason: fmt.Sprintf("user home %s is group/other writable", clean)}
	}
	// A mounted home shows the mounted filesystem (an unlocked ecryptfs
	// home, NFS, systemd-homed); lock markers inside it are user files.
	if ecryptfsSupported && mountErr == nil && !mounted && lockedEcryptfsHome(clean, uid) {
		if unixLiveSession(uid) {
			return HomeCheck{State: HomeUntrusted, Inode: uint64(st.Ino), Reason: fmt.Sprintf("user home %s is a locked ecryptfs home while the user has a live session", clean)}
		}
		return HomeCheck{State: HomePending, Reason: fmt.Sprintf("user home %s is a locked ecryptfs home", clean), Inode: uint64(st.Ino)}
	}
	return HomeCheck{State: HomeAvailable, Inode: uint64(st.Ino)}
}

// pendingErrno reports errors that mean "not now" rather than "unsafe":
// a missing home, a locked or unmounted filesystem, or an unreachable
// network home. A root caller seeing EACCES on an NFS root_squash home is
// also "not now" — the worker reads it with the user's credentials.
func pendingErrno(err error) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ENOENT, syscall.EACCES, syscall.EPERM, syscall.EIO, syscall.ESTALE,
		syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.EHOSTUNREACH, syscall.ENOTCONN:
		return true
	}
	return errno == enokey
}

// PendingTargetError reports whether a worker or reconcile error came from
// a home that is merely unavailable (see pendingErrno).
func PendingTargetError(err error) bool {
	return err != nil && pendingErrno(err)
}

// worldWritableAncestor returns a reason when any ancestor of home is
// writable by everyone (e.g. /tmp), where another local user could swap
// the home out from under the guardian.
func worldWritableAncestor(home string) string {
	for dir := filepath.Dir(home); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Sprintf("inspect user home ancestor %s: %v", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Sprintf("user home ancestor %s is a symlink", dir)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Sprintf("user home ancestor %s is world-writable", dir)
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// lockedEcryptfsHome recognizes the lower directory of a locked
// ecryptfs-utils private home. The markers alone are files the user can
// create, so the home's .Private link must lead to this uid's own
// directory inside the root-owned ecryptfs root, which only an
// administrator's ecryptfs-setup-private creates.
func lockedEcryptfsHome(home string, uid int) bool {
	target, err := os.Readlink(filepath.Join(home, ".Private"))
	if err != nil || !filepath.IsAbs(target) {
		return false
	}
	target = filepath.Clean(target)
	userDir := filepath.Dir(target)
	if filepath.Base(target) != ".Private" || filepath.Dir(userDir) != filepath.Clean(ecryptfsPrivateRoot) {
		return false
	}
	root, err := os.Lstat(ecryptfsPrivateRoot)
	if err != nil || !root.IsDir() || root.Mode()&os.ModeSymlink != 0 || root.Mode().Perm()&0o022 != 0 {
		return false
	}
	if st, ok := root.Sys().(*syscall.Stat_t); !ok || !ecryptfsRootOwnerOK(st.Uid) {
		return false
	}
	owned, err := os.Lstat(userDir)
	if err != nil || !owned.IsDir() || owned.Mode()&os.ModeSymlink != 0 || owned.Mode().Perm()&0o022 != 0 {
		return false
	}
	if st, ok := owned.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != uid {
		return false
	}
	if private, err := os.Lstat(target); err != nil || !private.IsDir() || private.Mode()&os.ModeSymlink != 0 {
		return false
	}
	for _, marker := range ecryptfsLockedMarkers {
		if _, err := os.Lstat(filepath.Join(home, marker)); err != nil {
			return false
		}
	}
	return true
}
