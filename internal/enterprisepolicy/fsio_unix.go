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
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
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

// restoreRecordedPolicyFileMode repairs a mode-only drift on a file whose
// published bytes are still exactly the bytes in the root-owned record. It
// atomically replaces the writable inode with those verified bytes, so an
// account that opened the old inode for writing cannot change the repaired
// policy afterward. Verify does not call this: it must report the drift.
func restoreRecordedPolicyFileMode(opts Options, path, postimageSHA256 string) (bool, error) {
	if opts.SkipTrustChecks || postimageSHA256 == "" {
		return false, nil
	}
	path = platformPath(opts, path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 == 0 {
		return false, nil
	}
	if err := validateTrustedAncestors(opts, path); err != nil {
		return false, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !trustedOwner(owner.Uid) {
		return false, fmt.Errorf("%s: writable policy file is not administrator-owned", path)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return false, fmt.Errorf("%s changed while opening it: %v", path, err)
	}
	openedOwner, ok := opened.Sys().(*syscall.Stat_t)
	if !ok || !trustedOwner(openedOwner.Uid) {
		return false, fmt.Errorf("%s: writable policy file is not administrator-owned", path)
	}
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return false, err
	}
	if sha256Hex(data) != postimageSHA256 {
		return false, fmt.Errorf("%s: %w; restore a trusted copy before repair", path, errRecordedPolicyBytesChanged)
	}
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return false, fmt.Errorf("%s changed while inspecting it: %v", path, err)
	}
	if _, err := writePolicyFile(opts, path, data); err != nil {
		return false, fmt.Errorf("republish %s with mode 0644: %w", path, err)
	}
	return true, nil
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
func atomicWrite(opts Options, path string, data []byte, public bool) error {
	return atomicWriteChecked(opts, path, data, public, nil)
}

// atomicWriteChecked is atomicWrite with check run just before the rename;
// its error stops the write with path as it is.
func atomicWriteChecked(_ Options, path string, data []byte, public bool, check func() error) error {
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
	if check != nil {
		if err := check(); err != nil {
			cleanup()
			return err
		}
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
	if opts.goos() == "linux" {
		acl, err := publishedACLReader.Read(platformPath(opts, path), info.Mode())
		if err != nil {
			problems = append(problems, fmt.Sprintf("cannot inspect POSIX ACL: %v", err))
		} else if denied := acl.Denied(0o4); denied != "" {
			problems = append(problems, "POSIX ACL entries without read (effective) "+denied)
		}
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

// publishedDirAccess is the access every user needs on a directory above a
// published file: list, on the drop-in directory an agent reads every file
// of (listed), and search on every other one. A file the agent opens by
// name (Codex requirements.toml, Cursor hooks.json) needs no list on its
// own directory, which may hold an administrator's unrelated files
// (GAP-0924).
func publishedDirAccess(listed bool) os.FileMode {
	if listed {
		return 0o005
	}
	return 0o001
}

// listedPolicyDir reports whether the n-th directory above the published
// file path is one its agent lists: the file's own directory, when it is a
// drop-in of Claude Code managed-settings.d or Copilot CLI policy.d.
func listedPolicyDir(path string, index int) bool {
	if index != 0 {
		return false
	}
	switch filepath.Base(path) {
	case DefenseClawDropInName, ClaudeVersionFloorDropInName:
		return true
	}
	return false
}

// publishedDirModeAccess is publishedDirAccess in the mode bits of both the
// owning group and other: a member of the directory's group gets the group
// bits and never the other bits, so root:staff 0705 kept every staff member
// from loading the hooks while verify reported coverage (GAP-1407).
func publishedDirModeAccess(listed bool) os.FileMode {
	access := publishedDirAccess(listed)
	return access | access<<3
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

var publishedACLReader posixacl.Reader = posixacl.System

// removeDarwinACLEntry removes the macOS ACL entry at index from path.
var removeDarwinACLEntry = func(path string, index int) error {
	return exec.Command("/bin/chmod", "-h", "-a#", strconv.Itoa(index), path).Run()
}

// writeLinuxAccessACL replaces the POSIX access ACL of path with acl.
var writeLinuxAccessACL = func(path string, acl posixacl.View) error {
	return unix.Setxattr(path, linuxAccessACLXattr, linuxAccessACLData(acl), 0)
}

// clearPublishedDirACL takes away only what keeps users from passing dir,
// the publishedDirs entry at index, and keeps every other ACL entry: an
// administrator's unrelated entries on a vendor directory survived no
// repair, since the whole ACL went (`chmod -N`, or the Linux access ACL
// removed; GAP-1323). On macOS it removes each entry that denies search
// (or list, on the drop-in directory), and each entry that grants write,
// highest index first so the lower indexes stay valid: write on a folder is
// usable only with search, so an allow-write entry the deny kept unusable
// would let its account add or replace machine policy once the deny is
// gone (status and verify name such an entry, and ensure clears it). On
// Linux it rewrites the access ACL with the missing access added to each
// entry without it and to the mask, and no group-class write
// (grantPublishedDirAccess).
var clearPublishedDirACL = func(opts Options, dir string, listed bool) error {
	want := uint16(publishedDirAccess(listed))
	if opts.goos() == "linux" {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		// A directory without an access ACL reads as none (the mode bits
		// are the whole ACL): the chmod of the repair gives the access.
		acl, err := publishedACLReader.Read(dir, info.Mode())
		if err != nil {
			return err
		}
		if acl.Denied(want) == "" {
			return nil
		}
		return writeLinuxAccessACL(dir, grantPublishedDirAccess(acl, want))
	}
	entries, err := publishedDirACLEntries(dir)
	if err != nil {
		return err
	}
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].Index > entries[j].Index })
	for _, entry := range entries {
		if entry.DeniesDirectoryAccess(listed) || entry.GrantsWrite() {
			if err := removeDarwinACLEntry(dir, entry.Index); err != nil {
				return fmt.Errorf("remove ACL entry %d (%s): %w", entry.Index, entry.Text, err)
			}
		}
	}
	return nil
}

// grantPublishedDirAccess is acl with want added to the owning group entry,
// each named entry and the mask; the owner, other and the rest of each
// entry's permissions stay. The group class comes out without write: the
// mask is written without it (and the owning group entry, when there is no
// mask), the way the mode repair drops group and other write (&^0o022) and
// validateTrustedElement refuses a group-writable folder. Write on a
// folder is usable only with search, so raising search on an entry that had
// write without it (user:x:rw-, group:g:-w-) under a mask with write let
// that account add or replace machine policy in the root-owned drop-in
// folder, and verify still reported the connector covered.
func grantPublishedDirAccess(acl posixacl.View, want uint16) posixacl.View {
	const write = 0o2
	out := acl
	out.Present = true
	out.Group |= want
	out.Mask = (acl.Mask | want) &^ write
	out.Users = append([]posixacl.Entry(nil), acl.Users...)
	out.Groups = append([]posixacl.Entry(nil), acl.Groups...)
	for i := range out.Users {
		out.Users[i].Perm |= want
	}
	for i := range out.Groups {
		out.Groups[i].Perm |= want
	}
	if len(out.Users)+len(out.Groups) == 0 {
		// linuxAccessACLData writes no mask here: the owning group entry is
		// the whole group class.
		out.Group &^= write
	}
	return out
}

// linuxAccessACLData encodes acl as the system.posix_acl_access value: the
// version, then the entries in the order the kernel requires (owner, named
// users by id, owning group, named groups by id, mask, other). A mask is
// written only with named entries; without them the kernel keeps the ACL
// as the mode bits.
func linuxAccessACLData(acl posixacl.View) []byte {
	const undefinedID = 0xffffffff
	data := binary.LittleEndian.AppendUint32(nil, 2)
	add := func(tag, perm uint16, id uint32) {
		data = binary.LittleEndian.AppendUint16(data, tag)
		data = binary.LittleEndian.AppendUint16(data, perm&7)
		data = binary.LittleEndian.AppendUint32(data, id)
	}
	byID := func(entries []posixacl.Entry) []posixacl.Entry {
		sorted := append([]posixacl.Entry(nil), entries...)
		sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
		return sorted
	}
	add(0x01, acl.Owner, undefinedID)
	for _, entry := range byID(acl.Users) {
		add(0x02, entry.Perm, uint32(entry.ID))
	}
	add(0x04, acl.Group, undefinedID)
	for _, entry := range byID(acl.Groups) {
		add(0x08, entry.Perm, uint32(entry.ID))
	}
	if len(acl.Users)+len(acl.Groups) > 0 {
		add(0x10, acl.Mask, undefinedID)
	}
	add(0x20, acl.Other, undefinedID)
	return data
}

func publishedDirACLProblem(opts Options, dir string, listed bool) (string, error) {
	if opts.goos() == "linux" {
		info, err := os.Lstat(dir)
		if err != nil {
			return "", err
		}
		acl, err := publishedACLReader.Read(dir, info.Mode())
		if err != nil {
			return "", err
		}
		denied := acl.Denied(uint16(publishedDirAccess(listed)))
		if denied == "" {
			return "", nil
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
		if entry.DeniesDirectoryAccess(listed) {
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
		listed := listedPolicyDir(path, index)
		if want := publishedDirModeAccess(listed); info.Mode().Perm()&want != want {
			problems = append(problems, fmt.Sprintf("%s has mode %04o", dir, info.Mode().Perm()))
		}
		if problem, err := publishedDirACLProblem(opts, dir, listed); err != nil {
			problems = append(problems, fmt.Sprintf("cannot inspect the ACL of %s: %v", dir, err))
		} else if problem != "" {
			problems = append(problems, problem)
		}
	}
	return strings.Join(problems, ", ")
}

// restorePublishedDirs gives the administrator-owned directories above a
// published policy file the access users need, and nothing more: the mode
// bits publishedDirModeAccess names, and no macOS ACL entry or Linux POSIX
// access ACL entry denying list or search. The repair made every one 0755,
// so a vendor folder an administrator kept at 0700 listed its unrelated
// files to every account, where users need only search, also on the
// directory of a file the agent opens by name (GAP-0924). Even search lets
// any account open a file it can name, so a directory whose other files
// grant access to the accounts it would let in is left as it is, and the
// error (errPublishedDirExposes) names those files. It returns the
// directories it changed.
func restorePublishedDirs(opts Options, path string) ([]string, error) {
	var restored []string
	dirs := publishedDirs(opts, path)
	for index, dir := range dirs {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		listed := listedPolicyDir(path, index)
		need := publishedDirModeAccess(listed)
		perm := info.Mode().Perm()
		needMode := perm&need != need || perm&0o022 != 0
		aclProblem, err := publishedDirACLProblem(opts, dir, listed)
		if err != nil {
			return restored, err
		}
		if !needMode && aclProblem == "" {
			continue
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !opts.SkipTrustChecks && (!ok || !trustedOwner(stat.Uid)) {
			continue
		}
		next := platformPath(opts, path)
		if index > 0 {
			next = dirs[index-1]
		}
		keep := map[string]bool{filepath.Base(next): true}
		if listed {
			keep[DefenseClawDropInName], keep[ClaudeVersionFloorDropInName] = true, true
		}
		// An ACL repair can let in named accounts and other: count both.
		exposed, err := exposedByBroadening(dir, keep, aclProblem != "" || perm&0o010 == 0, aclProblem != "" || perm&0o001 == 0)
		if err != nil {
			return restored, err
		}
		if len(exposed) > 0 {
			return restored, fmt.Errorf("%w: users cannot pass %s, and giving them access would also let them open %s; take the access of other accounts away from those files (chmod go-rwx) or move them out of %s, then run ensure",
				errPublishedDirExposes, dir, strings.Join(exposed, ", "), dir)
		}
		if aclProblem != "" {
			if err := clearPublishedDirACL(opts, dir, listed); err != nil {
				return restored, fmt.Errorf("remove the ACL entries denying access to %s: %w", dir, err)
			}
			// A Linux ACL rewrite changes the group bits (the mask).
			if info, err = os.Lstat(dir); err != nil {
				return restored, err
			}
			perm = info.Mode().Perm()
			needMode = perm&need != need || perm&0o022 != 0
		}
		if needMode {
			if err := os.Chmod(dir, (perm|need)&^0o022); err != nil {
				return restored, err
			}
		}
		restored = append(restored, dir)
	}
	return restored, nil
}

// restoreWritablePublishedDirs is restorePublishedDirs for a published file
// with a group- or other-writable directory above it, the one fault that
// makes reading the file fail (validateTrustedElement). It changes nothing
// while no directory above path is writable by other accounts or path does
// not exist.
func restoreWritablePublishedDirs(opts Options, path string) ([]string, error) {
	if _, err := os.Lstat(platformPath(opts, path)); err != nil {
		return nil, nil
	}
	for _, dir := range publishedDirs(opts, path) {
		if info, err := os.Lstat(dir); err == nil && info.IsDir() && info.Mode().Perm()&0o022 != 0 {
			return restorePublishedDirs(opts, path)
		}
	}
	return nil, nil
}

// exposedByBroadening lists the entries of dir, other than the names in
// keep, that an account could open once dir gives search to a class that has
// none now: an entry with any permission bit for that class. group is the
// owning group, the named POSIX ACL entries and the mask (the group bits of
// an entry with an ACL); other is every other account. A symbolic link is
// not counted: the directories above its target decide who reaches it.
func exposedByBroadening(dir string, keep map[string]bool, group, other bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var exposed []string
	for _, entry := range entries {
		if keep[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		perm := info.Mode().Perm()
		if (other && perm&0o007 != 0) || (group && perm&0o070 != 0) {
			exposed = append(exposed, filepath.Join(dir, entry.Name()))
		}
	}
	return exposed, nil
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
