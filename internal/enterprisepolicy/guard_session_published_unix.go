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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// publishedSessionFileMode makes a record readable through the per-user
// folder's access-list entry: the folder (0700 plus one read entry for the
// account) is what keeps other accounts out.
func publishedSessionFileMode(file *os.File) error { return file.Chmod(0o644) }

// createPublishedSessionKeyFile creates the key file at path, which must
// not exist: 0644, owned by this process (root, the only account whose key
// the gateway and the hook accept). Its name is the key; it has no content.
func createPublishedSessionKeyFile(path string, _ PublishedSessionTrust) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	return errors.Join(file.Chmod(0o644), file.Sync(), file.Close())
}

// publishedSessionKeyOwnerCheck reports a key file root owns: a regular
// file, not a symbolic link. A file that is gone is not a key.
func publishedSessionKeyOwnerCheck(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("%s: cannot read its owner", path)
	}
	return st.Uid == 0, nil
}

// publishedSessionSyncDir flushes the folder dir, so that a key file it
// removed or created stays so after a crash.
func publishedSessionSyncDir(dir string) error {
	folder, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(folder.Sync(), folder.Close())
}

// publishedSessionGrantReader gives uid read and search on the per-user
// folder dir (replaceable in tests, which cannot change access lists).
var publishedSessionGrantReader = grantPublishedSessionReader

// publishedSessionPrepare makes dir, below the lifecycle's root, a folder
// of this process (the gateway service account) that only the account
// identity (a decimal uid) can also read. A folder that is not this
// process's own is replaced.
func publishedSessionPrepare(root, dir, identity string) error {
	self := uint32(os.Geteuid())
	if err := publishedSessionOwnDir(root, self, true); err != nil {
		return fmt.Errorf("protected session record root %s: %w", root, err)
	}
	uid, err := strconv.ParseUint(identity, 10, 32)
	if err != nil {
		return fmt.Errorf("protected session record: identity %q is not a uid", identity)
	}
	for attempt := 0; attempt < 2; attempt++ {
		_, err := os.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				if errors.Is(err, fs.ErrExist) {
					continue
				}
				return err
			}
			if err := os.Chmod(dir, 0o700); err != nil {
				_ = os.Remove(dir)
				return err
			}
			if err := publishedSessionGrantReader(dir, uint32(uid)); err != nil {
				_ = os.Remove(dir)
				return fmt.Errorf("grant uid %d read access to %s: %w", uid, dir, err)
			}
			return nil
		}
		if err != nil {
			return err
		}
		if publishedSessionOwnDir(dir, self, false) == nil {
			return nil
		}
		// Not a folder this gateway made (or its owner or mode drifted):
		// replace it, so a record never lands where another account could
		// change it.
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	return fmt.Errorf("protected session record folder %s keeps changing", dir)
}

// publishedSessionOwnDir checks a folder this process writes records in: a
// real folder owned by this process's uid (or, for the root folder the
// lifecycle created, by root), that no group or other can write.
func publishedSessionOwnDir(path string, self uint32, rootOwnerOK bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a folder", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or other (%04o)", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", path)
	}
	if st.Uid != self && (!rootOwnerOK || st.Uid != 0) {
		return fmt.Errorf("%s is owned by uid %d", path, st.Uid)
	}
	return nil
}

// ValidatePublishedSessionPath checks a protected session record, or the
// record folder's key file, before the hook reads it: the file and every
// folder above it are real files and folders owned by root or the gateway
// service uid (from the root-owned runtime descriptor, never from the
// environment), writable by no group or other, with no access-list entry
// that grants write. The key file must be root's: only root creates one.
func ValidatePublishedSessionPath(path string, trust PublishedSessionTrust) error {
	clean, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	key := IsPublishedSessionKeyName(filepath.Base(clean))
	for cur, leaf := clean, true; ; cur, leaf = filepath.Dir(cur), false {
		info, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", cur)
		}
		if leaf && !info.Mode().IsRegular() || !leaf && !info.IsDir() {
			return fmt.Errorf("%s is not a regular %s", cur, map[bool]string{true: "file", false: "folder"}[leaf])
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by group or other (%04o)", cur, info.Mode().Perm())
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot read its owner", cur)
		}
		if leaf && key && st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root", cur, st.Uid)
		}
		if st.Uid != 0 && (trust.ServiceUID <= 0 || st.Uid != uint32(trust.ServiceUID)) {
			return fmt.Errorf("%s is owned by uid %d, not root or the gateway service account", cur, st.Uid)
		}
		if err := managed.ValidatePathACL(cur); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			return nil
		}
	}
}

// publishedSessionFolderLocked reports a folder with a flag or access-list
// entry that keeps its owner from adding or removing a file
// (publishedSessionFolderIsLocked; replaceable in tests, which cannot set
// one).
var publishedSessionFolderLocked = publishedSessionFolderIsLocked

// publishedSessionRevocableCheck reports why the gateway that wrote the
// records in the account folder accountDir (its owner: the gateway makes
// that folder as itself) might not be able to revoke them now. The folder
// of the account's key and revocation marks (the key folder of root) must
// be a real folder that this writer owns with write and search for its
// owner (any folder, for root), with no immutable or append-only flag or
// deny entry (publishedSessionFolderLocked), on a volume that is not
// read-only. Then the key's removal or its mark takes, and a block the
// gateway decides ends every earlier allow of the account. Anything that
// cannot be read is an error.
func publishedSessionRevocableCheck(root, accountDir string) error {
	writer, err := publishedSessionFolderOwnerUID(accountDir)
	if err != nil {
		return err
	}
	keyDir, ok := PublishedSessionKeyDir(root)
	if !ok {
		return fmt.Errorf("no key folder for the record folder %q", root)
	}
	dir := publishedSessionMarkDir(filepath.Clean(root), keyDir)
	owner, err := publishedSessionFolderOwnerUID(dir)
	if err != nil {
		return err
	}
	if writer != 0 {
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if owner != writer {
			return fmt.Errorf("%s is owned by uid %d, not by uid %d, which wrote the records", dir, owner, writer)
		}
		if info.Mode().Perm()&0o300 != 0o300 {
			return fmt.Errorf("%s does not let its owner add or remove a file (%04o)", dir, info.Mode().Perm())
		}
	}
	locked, err := publishedSessionFolderLocked(dir)
	if err != nil {
		return fmt.Errorf("%s: its flags or access list cannot be read: %w", dir, err)
	}
	if locked {
		return fmt.Errorf("%s is immutable or append-only, or an access-list entry denies a change", dir)
	}
	readOnly, err := publishedSessionVolumeReadOnly(dir)
	if err != nil {
		return fmt.Errorf("%s: its volume state cannot be read: %w", dir, err)
	}
	if readOnly {
		return fmt.Errorf("%s is on a read-only volume", dir)
	}
	return nil
}

// publishedSessionFolderOwnerUID is the owner of the real folder path.
func publishedSessionFolderOwnerUID(path string) (uint32, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, fmt.Errorf("%s is not a folder", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: cannot read its owner", path)
	}
	return st.Uid, nil
}

// publishedSessionMarkDir is the folder of the revocation marks of the
// record folder root: its key folder (the hook socket folder, which every
// account can list and only root and the gateway service can add a file
// to). The record folder itself is not listable (0711).
func publishedSessionMarkDir(_, keyDir string) string { return keyDir }
