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

package enterprisepolicy

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// trustedOwner reports whether uid may own machine policy files and their
// ancestors. Tests replace it to model root ownership inside a temp tree.
var trustedOwner = func(uid uint32) bool { return uid == 0 }

// platformPath maps macOS's /etc, /var and /tmp compatibility symlinks to
// their /private targets so the no-symlink ancestor walk sees real
// directories. Other platforms and rooted test trees are unchanged.
func platformPath(opts Options, path string) string {
	if opts.goos() != "darwin" || opts.Root != "" {
		return path
	}
	for _, prefix := range []string{"/etc/", "/var/", "/tmp/"} {
		if strings.HasPrefix(path, prefix) {
			return "/private" + path
		}
	}
	return path
}

func validateTrustedElement(path string, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in machine policy paths", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected a directory", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/other-writable mode %04o is not trusted for machine policy", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot inspect owner", path)
	}
	if !trustedOwner(st.Uid) {
		return fmt.Errorf("%s: owner uid %d is not an administrator", path, st.Uid)
	}
	return nil
}

// validateTrustedAncestors checks every existing ancestor of path.
func validateTrustedAncestors(opts Options, path string) error {
	stop := "/"
	if opts.Root != "" {
		stop = filepath.Clean(opts.Root)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			if err := validateTrustedElement(dir, true); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if dir == stop || dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func validateTrustedPolicyFile(opts Options, path string) error {
	if err := validateTrustedElement(path, false); err != nil {
		return err
	}
	return validateTrustedAncestors(opts, path)
}

// The managed OpenCode plugin is an ordinary public policy file here:
// OpenCode reads it with a read-only open.
func validateOpenCodePluginFile(opts Options, path string) error {
	return validateTrustedPolicyFile(opts, path)
}

func atomicWriteOpenCodePlugin(opts Options, path string, data []byte) error {
	return atomicWrite(opts, path, data, true)
}

func openCodePluginLoadable(Options, string) (bool, error) { return true, nil }

// The read-only attribute is a Windows file attribute.
func openCodePluginReadOnly(string) bool { return false }

// Standard accounts hold no write right on the plugin here.
func releaseOpenCodePluginName(Options, string) error { return nil }

// The Amp machine folder is held on Windows only; /etc/ampcode and
// /Library/Application Support/ampcode are already administrator-only.
func reserveWindowsAmpMachineDir(Options) (State, error) { return State{}, nil }

// InspectWindowsAmpMachineFolder reports nothing off Windows.
func InspectWindowsAmpMachineFolder(Options) []string { return nil }

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// ensurePolicyDir creates missing directories 0755 and administrator-owned.
func ensurePolicyDir(opts Options, dir string) ([]string, error) {
	var missing []string
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append([]string{cur}, missing...)
		if cur == filepath.Dir(cur) || (opts.Root != "" && cur == filepath.Clean(opts.Root)) {
			break
		}
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(dir, "x")); err != nil {
			return nil, err
		}
	}
	created := []string{}
	for _, cur := range missing {
		if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return created, err
		}
		if err := os.Chmod(cur, 0o755); err != nil {
			return created, err
		}
		if os.Geteuid() == 0 {
			if err := os.Lchown(cur, 0, 0); err != nil {
				return created, err
			}
		}
		created = append(created, cur)
	}
	return created, nil
}

// reclaimPolicyDirs, clearPolicyFileName, displaceUntrustedPolicyFiles and
// displaceUntrustedPolicyFile are Windows-only: every unix ancestor must already be root-owned and not
// group/other-writable, so no unprivileged user can create or occupy a
// vendor path and there is nothing to take back.
func reclaimPolicyDirs(Options, string) (policyTakeBack, error) { return policyTakeBack{}, nil }

func clearPolicyFileName(Options, string) (string, error) { return "", nil }

func displaceUntrustedPolicyFiles(Options, string, string, *State) {}

func displaceUntrustedPolicyFile(Options, string, *State) bool { return false }

func displaceUntrustedEntries(Options, string, *State) {}

// validatePolicyLeafDir is covered on unix by the ancestor walk, which
// already applies the strict rules to every directory.
func validatePolicyLeafDir(Options, string) error { return nil }

// atomicWrite writes data to a same-directory temporary file and renames
// it over path. public selects 0644 (vendor policy) versus 0600 (records).
func atomicWrite(_ Options, path string, data []byte, public bool) error {
	dir := filepath.Dir(path)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".defenseclaw-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	mode := os.FileMode(0o600)
	if public {
		mode = 0o644
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if os.Geteuid() == 0 {
		if err := file.Chown(0, 0); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
	}
	if err := file.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

// ensurePrivateDir creates the root-only ownership-record directory.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return os.Chmod(dir, 0o700)
}

// openGuardFile opens a user or project file for the foreign-hook guard.
// It never follows a final symlink and never blocks: a user can swap a
// FIFO in after the guard's Lstat, and a blocking open would stall the
// hook until the agent's timeout (which several agents treat as allow).
func openGuardFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// openGuardDir opens a user or project directory for listing with the same
// rules; a non-directory fails instead of blocking.
func openGuardDir(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_DIRECTORY, 0)
}

// openGuardFileFollow opens a file a hook command names, following links
// as the agent would, without blocking on a FIFO.
func openGuardFileFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

// adminOwnedFile reports a root-owned file no group or other account can
// write: a user cannot change what it holds.
// guardPathCannotExist reports a stat error that means nothing can be at
// the path (a component is a file, or the name is too long).
func guardPathCannotExist(err error) bool {
	return errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ENAMETOOLONG)
}

func adminOwnedFile(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

// systemBoundFile reports an administrator-owned file (adminOwnedFile) the
// guard may bind by kind only. Where the kernel lets a user hard-link a file
// they do not own (macOS always; Linux with fs.protected_hardlinks off), a
// user can hard-link root-owned programs into their own folder and swap one
// for another under the same name, so the file must also be named from a
// folder chain root owns that no one else can write; otherwise it is bound
// by content.
func systemBoundFile(path string, info os.FileInfo) bool {
	if !adminOwnedFile(info) {
		return false
	}
	if !userHardLinksAllowed() {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	for dir := filepath.Dir(resolved); ; dir = filepath.Dir(dir) {
		folder, err := os.Lstat(dir)
		if err != nil || !folder.IsDir() {
			return false
		}
		stat, ok := folder.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || folder.Mode().Perm()&0o022 != 0 {
			return false
		}
		if dir == filepath.Dir(dir) {
			return true
		}
	}
}

// userHardLinksAllowed reports whether a user may hard-link a file another
// account owns. A seam for tests.
var userHardLinksAllowed = func() bool {
	if runtimeGOOS() == "darwin" {
		return true
	}
	data, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
	return err == nil && strings.TrimSpace(string(data)) == "0"
}

// publishedFileProblem describes how a policy file DefenseClaw published
// differs from the mode and owner atomicWrite gives it: 0644 (every user's
// agent must read machine policy), and root-owned when DefenseClaw runs as
// root. It returns "" when it does not, or when path is not a regular file.
func publishedFileProblem(opts Options, path string) string {
	info, err := os.Lstat(platformPath(opts, path))
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	var problems []string
	if perm := info.Mode().Perm(); perm != 0o644 {
		problems = append(problems, fmt.Sprintf("mode %04o", perm))
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 && stat.Uid != 0 {
		problems = append(problems, fmt.Sprintf("owned by uid %d", stat.Uid))
	}
	return strings.Join(problems, ", ")
}

// publishedDirs are the directories above a policy file, nearest first, up
// to the root of the host or of a rooted test tree.
func publishedDirs(opts Options, path string) []string {
	stop := "/"
	if opts.Root != "" {
		stop = filepath.Clean(opts.Root)
	}
	var dirs []string
	for dir := filepath.Dir(platformPath(opts, path)); dir != stop && dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		dirs = append(dirs, dir)
	}
	return dirs
}

// publishedDirAccess is the access every user needs on the n-th directory
// above a published file: to list the file's own directory (Claude Code
// reads every file in managed-settings.d) and to pass the ones above it.
func publishedDirAccess(index int) os.FileMode {
	if index == 0 {
		return 0o005
	}
	return 0o001
}

// The macOS ACL is independent of POSIX mode. Keep the reader and clearer
// replaceable so rooted tests on Linux can model a macOS deny entry.
var publishedDirACLEntries = func(path string) ([]managed.DarwinACLEntry, error) {
	if runtime.GOOS != "darwin" {
		return nil, nil
	}
	cmd := exec.Command("/bin/ls", "-lde", "--", path)
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("inspect macOS ACL of %s: %w", path, err)
	}
	entries, err := managed.ParseDarwinACLListing(string(output), []string{path})
	return entries[path], err
}

// linuxAccessACLXattr holds a Linux file's POSIX access ACL.
const linuxAccessACLXattr = "system.posix_acl_access"

// publishedDirLinuxACL reads a directory's POSIX access ACL; nil when it has
// none (mode bits alone apply) or the file system has no ACLs.
var publishedDirLinuxACL = func(path string) ([]byte, error) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	for {
		size, err := unix.Getxattr(path, linuxAccessACLXattr, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		data := make([]byte, size)
		n, err := unix.Getxattr(path, linuxAccessACLXattr, data)
		if errors.Is(err, unix.ERANGE) {
			continue // the ACL grew between the two calls
		}
		if errors.Is(err, unix.ENODATA) {
			return nil, nil
		}
		return data[:n], err
	}
}

var clearPublishedDirACL = func(path string) error {
	if runtime.GOOS == "linux" {
		if err := unix.Removexattr(path, linuxAccessACLXattr); err != nil && !errors.Is(err, unix.ENODATA) {
			return err
		}
		return nil
	}
	return exec.Command("/bin/chmod", "-h", "-N", path).Run()
}

// linuxACLDenial names the named-user and named-group entries of a Linux
// POSIX access ACL (the xattr format: a version 2 header, then 8-byte tag,
// permission, id entries) whose effective permission, after the mask, lacks
// want. Mode bits cover the owner, the owning group and other users; these
// entries override "other" for the users they name (GAP-1350).
func linuxACLDenial(data []byte, want os.FileMode) (string, error) {
	const (
		aclUser  = 0x02
		aclGroup = 0x08
		aclMask  = 0x10
	)
	if len(data) < 4 || (len(data)-4)%8 != 0 || binary.LittleEndian.Uint32(data) != 2 {
		return "", fmt.Errorf("unrecognised POSIX ACL (%d bytes)", len(data))
	}
	type entry struct {
		tag, perm uint16
		id        uint32
	}
	mask := uint16(7)
	var named []entry
	for off := 4; off < len(data); off += 8 {
		e := entry{binary.LittleEndian.Uint16(data[off:]), binary.LittleEndian.Uint16(data[off+2:]), binary.LittleEndian.Uint32(data[off+4:])}
		switch e.tag {
		case aclMask:
			mask = e.perm
		case aclUser, aclGroup:
			named = append(named, e)
		}
	}
	var denied []string
	for _, e := range named {
		effective := e.perm & mask
		if os.FileMode(effective)&want == want {
			continue
		}
		id := strconv.FormatUint(uint64(e.id), 10)
		kind, name := "user", id
		if e.tag == aclGroup {
			kind = "group"
			if g, err := user.LookupGroupId(id); err == nil {
				name = g.Name
			}
		} else if u, err := user.LookupId(id); err == nil {
			name = u.Username
		}
		denied = append(denied, fmt.Sprintf("%s:%s:%s", kind, name, rwx(effective)))
	}
	return strings.Join(denied, ", "), nil
}

func rwx(perm uint16) string {
	out := []byte("---")
	for i, c := range "rwx" {
		if perm&(4>>i) != 0 {
			out[i] = byte(c)
		}
	}
	return string(out)
}

func publishedDirACLProblem(opts Options, dir string, index int) (string, error) {
	if opts.goos() == "linux" {
		data, err := publishedDirLinuxACL(dir)
		if err != nil || data == nil {
			return "", err
		}
		denied, err := linuxACLDenial(data, publishedDirAccess(index))
		if err != nil || denied == "" {
			return "", err
		}
		return fmt.Sprintf("%s has POSIX ACL entries without access (effective) %s", dir, denied), nil
	}
	if opts.goos() != "darwin" {
		return "", nil
	}
	entries, err := publishedDirACLEntries(dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.DeniesDirectoryAccess(index == 0) {
			return fmt.Sprintf("%s has macOS ACL entry %q", dir, entry.Text), nil
		}
	}
	return "", nil
}

// publishedDirProblem names the directories above a policy file DefenseClaw
// published that users cannot pass because of mode, a macOS deny ACL or a
// Linux POSIX ACL entry without access. After an administrator hardened
// /etc/claude-code/managed-settings.d to 0700, Claude Code skipped every
// managed setting (and offered to continue without them) while verify and
// status said the deployment was healthy (GAP-0913). "" when users can.
func publishedDirProblem(opts Options, path string) string {
	var problems []string
	for index, dir := range publishedDirs(opts, path) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		if want := publishedDirAccess(index); info.Mode().Perm()&want != want {
			problems = append(problems, fmt.Sprintf("%s has mode %04o", dir, info.Mode().Perm()))
		}
		if problem, err := publishedDirACLProblem(opts, dir, index); err != nil {
			problems = append(problems, fmt.Sprintf("cannot inspect the ACL of %s: %v", dir, err))
		} else if problem != "" {
			problems = append(problems, problem)
		}
	}
	return strings.Join(problems, ", ")
}

// restorePublishedDirs gives the administrator-owned directories above a
// published policy file to the access DefenseClaw creates: mode 0755 and no
// macOS ACL or Linux POSIX access ACL denying list or search. It returns the directories it changed.
func restorePublishedDirs(opts Options, path string) ([]string, error) {
	var restored []string
	for index, dir := range publishedDirs(opts, path) {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		perm := info.Mode().Perm()
		needMode := perm&publishedDirAccess(index) != publishedDirAccess(index)
		aclProblem, err := publishedDirACLProblem(opts, dir, index)
		if err != nil {
			return restored, err
		}
		if !needMode && aclProblem == "" {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !opts.SkipTrustChecks && (!ok || !trustedOwner(stat.Uid)) {
			continue
		}
		if aclProblem != "" {
			if err := clearPublishedDirACL(dir); err != nil {
				return restored, fmt.Errorf("remove the ACL of %s: %w", dir, err)
			}
		}
		if needMode {
			if err := os.Chmod(dir, (perm|0o755)&^0o022); err != nil {
				return restored, err
			}
		}
		restored = append(restored, dir)
	}
	return restored, nil
}

// adminOwnedLink reports a root-owned symbolic link (a link's own mode
// bits do not matter): a user can replace it only with a link of their own.
func adminOwnedLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0
}

// openGuardAppend opens a user-owned record file for appending without
// following a final symlink or blocking.
func openGuardAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}
