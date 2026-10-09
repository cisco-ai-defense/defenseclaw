// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// maxInputBytes bounds every file the lifecycle reads into memory (config,
// records, secrets). Binaries are streamed.
const maxInputBytes = 8 << 20

// fileOwner is a resolved uid/gid pair.
type fileOwner struct {
	UID int
	GID int
}

func sha256Bytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sha256File streams a regular, non-symlink file.
func sha256File(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// readBounded reads a regular, non-symlink file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ensureDir creates path (and missing parents with 0755 root-style modes)
// and forces its exact mode and owner. An existing symlink or non-directory
// is refused rather than replaced.
func (e *Env) ensureDir(path string, mode os.FileMode, owner fileOwner) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to use it as a managed directory", path)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
	case errors.Is(err, os.ErrNotExist):
		if err := mkdirParents(filepath.Dir(path)); err != nil {
			return err
		}
		if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create %s: %w", path, err)
		}
	default:
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := e.Lchown(path, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	return nil
}

// mkdirParents creates path and its missing ancestors as 0755 directories.
// os.MkdirAll would give every created ancestor the leaf's mode (0700 for
// the lifecycle directory) and the caller's umask (the MDM wrapper and
// the rpm scriptlets run under 077); shared parents such as /opt and /opt/cisco are never re-moded
// once they exist, so a closed ancestor would stay closed and keep the
// service account and agent users out of the install tree.
func mkdirParents(path string) error {
	path = filepath.Clean(path)
	// Existing ancestors may be system links (/etc, /var on macOS); follow
	// them as MkdirAll does. Only directories this function creates get 0755.
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect %s: %w", path, err)
	}
	if parent := filepath.Dir(path); parent != path {
		if err := mkdirParents(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return fmt.Errorf("create %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// writeFileAtomic replaces path with data: a same-directory temporary file
// is written, synced, given its final mode and owner, and renamed over the
// destination, then the directory is synced. Readers see either the old or
// the new bytes, never a partial file.
func (e *Env) writeFileAtomic(path string, data []byte, mode os.FileMode, owner fileOwner) error {
	return e.installAtomic(path, mode, owner, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

// copyFileAtomic streams src into path with the same guarantees.
func (e *Env) copyFileAtomic(src, path string, mode os.FileMode, owner fileOwner) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return e.installAtomic(path, mode, owner, func(w io.Writer) error {
		_, err := io.Copy(w, in)
		return err
	})
}

func (e *Env) installAtomic(path string, mode os.FileMode, owner fileOwner, fill func(io.Writer) error) error {
	dir := filepath.Dir(path)
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to replace it", path)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".dc-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("stage %s: %w", path, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = os.Remove(tmp)
		}
	}()
	if err := fill(file); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err := file.Chmod(mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err := e.Lchown(tmp, owner.UID, owner.GID); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	committed = true
	syncDir(dir)
	return nil
}

func syncDir(dir string) {
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
}

// removeFile deletes a file or symlink if present.
func removeFile(path string) error {
	err := os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// removeDirIfEmpty deletes path only when it has no entries.
func removeDirIfEmpty(path string) error {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return nil
	}
	return os.Remove(path)
}

// inputPathACL rejects an ACL entry that lets another account write path
// (replaceable by tests).
var inputPathACL = managed.ValidatePathACL

// aclRemoveCommand is the command that removes the ACL of path.
func aclRemoveCommand(path string) string {
	if runtime.GOOS == "darwin" {
		return "chmod -N " + path
	}
	return "setfacl -b " + path
}

// trustedInputFile refuses an administrator input (--config) that another
// account could have changed before the run read it, as the MDM wrapper
// does (mdm_untrusted_input): the file must be owned by root (or the
// account running the lifecycle) and not writable by group or other, and
// so must each of its folders, except a sticky one such as /tmp. An ACL
// entry that grants another account write counts as writable: macOS keeps
// the mode bits when one is added, and ensure --config applied a file a
// standard user had appended to (GAP-0937).
func trustedInputFile(path, label string) error {
	uid, _, mode, err := statOwnerMode(path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s %s does not exist; check the path given to %s (the absolute path of the administrator config), then rerun", label, path, label)
	}
	if err != nil {
		return fmt.Errorf("%s %s cannot be read: %w", label, path, err)
	}
	owned := func(uid int) bool { return uid == 0 || uid == os.Geteuid() }
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s is a symlink, so its target could be swapped after the check; pass the real file path instead (root-owned, chmod 0600, in a folder only root can write), then rerun", label, path)
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%s %s is writable by group or other (%04o), so another account could have changed it; make it root-owned and not group- or world-writable (chmod 0600 %s), then rerun", label, path, mode.Perm(), path)
	}
	if !owned(uid) {
		return fmt.Errorf("%s %s is owned by uid %d, so that account could have changed it; make it root-owned (chown 0 %s), then rerun", label, path, uid, path)
	}
	if err := inputPathACL(path); err != nil {
		return fmt.Errorf("%s %s has an ACL entry that lets another account write it (%v), so that account could have changed it although the mode bits do not allow it; remove the ACL (%s), then rerun", label, path, err, aclRemoveCommand(path))
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return err
	}
	for {
		uid, _, mode, err := statOwnerMode(dir)
		if err != nil {
			return err
		}
		if !owned(uid) || (mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0) {
			return fmt.Errorf("%s %s is in %s, which another account can write (uid %d, %04o); stage it in a root-owned folder that only root can write, then rerun", label, path, dir, uid, mode.Perm())
		}
		if err := inputPathACL(dir); err != nil && mode&os.ModeSticky == 0 {
			return fmt.Errorf("%s %s is in %s, which has an ACL entry that lets another account write it (%v), so that account could have swapped the file; remove the ACL (%s), then rerun", label, path, dir, err, aclRemoveCommand(dir))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// statOwnerMode reports a path's uid, gid and permission bits without
// following a symlink.
func statOwnerMode(path string) (int, int, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, 0, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, fmt.Errorf("%s: no unix ownership", path)
	}
	return int(st.Uid), int(st.Gid), info.Mode(), nil
}

// copyPreserved preserves src at dst for a snapshot as a byte copy, when
// no hard link can keep its inode.
func copyPreserved(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
