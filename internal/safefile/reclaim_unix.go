//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/runtimeowner"
	"golang.org/x/sys/unix"
)

// effectiveUID is the uid ownership decisions are made for. A variable so a
// test can stand in for the root run it cannot be.
var effectiveUID = os.Geteuid

// ReclaimToDirectoryOwner gives a root-created private file back to the
// operator who owns the already-trusted parent directory.
func ReclaimToDirectoryOwner(path string) error {
	if effectiveUID() != 0 {
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
	directory, dirInfo, ownerUID, ownerGID, err := openReclaimDirectory(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
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
		if err := relaxModeVerdict(path, fileInfo.Mode().Perm(), fmt.Errorf("safefile: private file permissions are too broad: %s", path)); err != nil {
			return err
		}
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

// openReclaimDirectory opens dir without following links and proves it is a
// directory this process may give files to: private enough and owned by a
// trusted uid. ReclaimToDirectoryOwner and PreflightReclaimDirectory share it,
// so the check that runs before a root start's first write is the one that
// would refuse after it.
func openReclaimDirectory(dir string) (directory *os.File, dirInfo os.FileInfo, ownerUID, ownerGID int, err error) {
	dirFD, err := unix.Open(dir, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, nil, 0, 0, fmt.Errorf("safefile: open private directory without following links %s: %w", dir, err)
	}
	directory = os.NewFile(uintptr(dirFD), dir)
	if directory == nil {
		_ = unix.Close(dirFD)
		return nil, nil, 0, 0, fmt.Errorf("safefile: bind private directory descriptor %s", dir)
	}
	fail := func(err error) (*os.File, os.FileInfo, int, int, error) {
		_ = directory.Close()
		return nil, nil, 0, 0, err
	}
	dirInfo, err = directory.Stat()
	if err != nil {
		return fail(fmt.Errorf("safefile: stat opened private directory %s: %w", dir, err))
	}
	if !dirInfo.IsDir() {
		return fail(fmt.Errorf("safefile: private directory is not a trusted directory: %s", dir))
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		if err := relaxModeVerdict(dir, dirInfo.Mode().Perm(), fmt.Errorf("safefile: private directory is not a trusted directory: %s", dir)); err != nil {
			return fail(err)
		}
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fail(fmt.Errorf("safefile: private directory ownership is unavailable: %s", dir))
	}
	if !runtimeowner.Trusted(dirStat.Uid) {
		return fail(fmt.Errorf("safefile: private directory has an untrusted owner: %s", dir))
	}
	return directory, dirInfo, int(dirStat.Uid), int(dirStat.Gid), nil
}

// PreflightReclaimDirectory is the check a root run makes before its first
// write into dir: the same one ReclaimToDirectoryOwner would refuse on after
// the write. A refused root start otherwise leaves root-owned files the
// account's own start cannot open (GAP-0714). It does nothing for a non-root
// process.
//
// A directory that does not exist yet has no owner to prove, and a root run
// would create it (and the log and PID record in it) owned by root. That is
// right only where root is the owner: below a root-owned folder. Below a folder
// another account owns, the root run would strand that account behind a
// root-owned 0700 home, so it is refused before anything is created and no
// state needs rolling back.
func PreflightReclaimDirectory(dir string) error {
	if effectiveUID() != 0 {
		return nil
	}
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return preflightMissingDirectory(dir)
	}
	directory, _, _, _, err := openReclaimDirectory(dir)
	if err != nil {
		return err
	}
	return directory.Close()
}

// preflightMissingDirectory refuses a missing dir unless its nearest existing
// ancestor is owned by root and no other account can write it. Root creates
// the directory owned by root, so it is right only where nobody else has a
// claim on the folder: below a folder another account owns, or one any account
// can write into (/tmp is root-owned and open to everyone), the account the
// home is for is left behind a root-owned private directory.
func preflightMissingDirectory(dir string) error {
	for ancestor := filepath.Dir(dir); ; ancestor = filepath.Dir(ancestor) {
		uid, perm, err := pathOwnerAndMode(ancestor)
		if err == nil {
			switch {
			case uid != 0:
				return fmt.Errorf("safefile: private directory %s does not exist and root would create it inside a folder owned by uid %d: start the gateway as that account, or create the directory as that account first", dir, uid)
			case perm&0o022 != 0:
				return fmt.Errorf("safefile: private directory %s does not exist and root would create it inside %s, which other accounts can write (mode %04o): start the gateway as the account the directory is for, or create the directory as that account first", dir, ancestor, perm)
			}
			return preflightRootOwnsNewDirectory(dir, ancestor)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("safefile: inspect the folder that would hold private directory %s: %w", dir, err)
		}
		if next := filepath.Dir(ancestor); next == ancestor {
			return nil
		}
	}
}

// preflightRootOwnsNewDirectory is the intended-owner proof for a missing
// directory below a root-owned folder nobody else can write (/home is one).
// The root-owned folder is no proof that the new directory belongs to root: a
// root run creates it owned by root and mode 0700, and a whole missing account
// home (with the log and PID record in it) then strands the account it is for,
// whether root got there through sudo or was started with no sudo account in
// the environment (SUDO_UID empty or 0 names nobody, it does not name root as
// the owner). The target is the proof: root's own home is root's whoever ran
// sudo; anywhere else the directory is refused before anything is created
// (GAP-0714).
func preflightRootOwnsNewDirectory(dir, ancestor string) error {
	if home := rootHomeDir(); home != "" && insideDirectory(dir, ancestor, home) {
		return nil
	}
	if raw := strings.TrimSpace(os.Getenv("SUDO_UID")); raw == "" || raw == "0" {
		return fmt.Errorf("safefile: private directory %s does not exist and root would create it owned by root outside root's own home, where it would belong to no account that can use it: create the directory as the account it is for first", dir)
	}
	return fmt.Errorf("safefile: private directory %s does not exist and root would create it owned by root for the account that ran sudo: start the gateway as that account, or create the directory as that account first", dir)
}

// rootHomeDir is root's login directory from the account database, never from
// the environment a sudo run inherits. A variable so a test can stand in for it.
var rootHomeDir = func() string {
	account, err := user.LookupId("0")
	if err != nil || account == nil {
		return ""
	}
	return account.HomeDir
}

// insideDirectory reports whether dir, a missing path whose nearest existing
// folder is ancestor, lies inside base once links are resolved.
func insideDirectory(dir, ancestor, base string) bool {
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		return false
	}
	resolvedAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return false
	}
	missing, err := filepath.Rel(ancestor, dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(resolvedBase, filepath.Join(resolvedAncestor, missing))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// pathOwnerAndMode is the owner and the permission bits of the
// existing path (links followed, as a create would). A variable so a test can
// stand in for a root-owned folder it cannot make.
var pathOwnerAndMode = func(path string) (uint32, os.FileMode, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("ownership is unavailable: %s", path)
	}
	return stat.Uid, info.Mode().Perm(), nil
}

func verifyOpenedPath(path string, opened os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, current) {
		return fmt.Errorf("safefile: private directory path changed during ownership reclaim: %s", path)
	}
	return nil
}
