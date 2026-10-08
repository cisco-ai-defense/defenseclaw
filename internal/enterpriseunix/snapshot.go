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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"
)

const snapshotIndexName = "index.json"

// snapshotEntry records one canonical path before a transaction touched it.
type snapshotEntry struct {
	Path    string      `json:"path"`
	Present bool        `json:"present"`
	Dir     bool        `json:"dir,omitempty"`
	Mode    os.FileMode `json:"mode,omitempty"`
	UID     int         `json:"uid,omitempty"`
	GID     int         `json:"gid,omitempty"`
	Blob    string      `json:"blob,omitempty"`
	// Store is the managed root whose per-filesystem store holds Blob, when
	// the file could not be linked into the snapshot directory itself.
	Store string `json:"store,omitempty"`
}

type snapshot struct {
	Dir     string          `json:"-"`
	Entries []snapshotEntry `json:"entries"`
}

// takeSnapshot preserves every canonical path in files (regular files) and
// dirs (mode and owner only) under a fresh directory in the lifecycle
// state; preserve places a file from another filesystem in a store on its
// own. The returned directory is recorded in the pending intent before the
// first mutation.
func (e *Env) takeSnapshot(id string, files, dirs []string) (_ *snapshot, err error) {
	dir := filepath.Join(e.P(e.Layout.LifecycleDir), snapshotsDirName, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}
	defer func() {
		if err != nil {
			e.discardSnapshot(&snapshot{Dir: dir})
		}
	}()
	snap := &snapshot{Dir: dir}
	seen := map[string]bool{}
	for index, canonical := range files {
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		path := e.P(canonical)
		entry := snapshotEntry{Path: canonical}
		uid, gid, mode, err := statOwnerMode(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
		case mode&os.ModeSymlink != 0:
			return nil, fmt.Errorf("snapshot %s: refusing to snapshot a symlink", canonical)
		case !mode.IsRegular():
			return nil, fmt.Errorf("snapshot %s: not a regular file", canonical)
		default:
			blob := strconv.Itoa(index)
			var store string
			if e.applyTriggerWatches(canonical) {
				// A hard link changes the link count of the live file, which
				// the apply trigger reads as a change (IN_ATTRIB for systemd
				// PathChanged, NOTE_LINK for launchd WatchPaths): its ensure
				// queued behind this run and held the lock for seconds after
				// it, so a verify or status run right after an ensure --config
				// failed lifecycle_busy (GAP-0354). These administrator inputs
				// are small, so they are copied.
				err = copyPreserved(path, filepath.Join(dir, "files", blob))
			} else {
				store, err = e.preserve(dir, path, blob)
			}
			if err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
			}
			entry.Present, entry.Mode, entry.UID, entry.GID, entry.Blob, entry.Store = true, mode.Perm(), uid, gid, blob, store
		}
		snap.Entries = append(snap.Entries, entry)
	}
	for _, canonical := range dirs {
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		entry := snapshotEntry{Path: canonical, Dir: true}
		uid, gid, mode, err := statOwnerMode(e.P(canonical))
		if err == nil && mode.IsDir() {
			entry.Present, entry.Mode, entry.UID, entry.GID = true, mode.Perm(), uid, gid
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
		}
		snap.Entries = append(snap.Entries, entry)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := e.writeFileAtomic(filepath.Join(dir, snapshotIndexName), data, 0o600, rootOwner()); err != nil {
		return nil, err
	}
	return snap, nil
}

// applyTriggerWatches reports a file the apply trigger watches:
// config.yaml and the files directly in the secrets and policies folders.
func (e *Env) applyTriggerWatches(canonical string) bool {
	parent := filepath.Dir(canonical)
	return canonical == e.Layout.ConfigPath || parent == e.Layout.SecretsDir || parent == e.Layout.PolicyDir
}

func (e *Env) loadSnapshot(dir string) (*snapshot, error) {
	data, err := readBounded(filepath.Join(dir, snapshotIndexName), maxInputBytes)
	if err != nil {
		return nil, fmt.Errorf("read snapshot index: %w", err)
	}
	snap := &snapshot{Dir: dir}
	if err := json.Unmarshal(data, snap); err != nil {
		return nil, fmt.Errorf("parse snapshot index: %w", err)
	}
	return snap, nil
}

// sideStoreName is the per-filesystem snapshot store below a managed root.
const sideStoreName = ".lifecycle-snapshots"

// sideStoreRoots are the managed directories that can hold a snapshot's
// preserved links for files on another filesystem than the lifecycle
// state: with /var on its own partition (CIS layouts) the binaries under
// /opt and the config and units under /etc are elsewhere.
func (e *Env) sideStoreRoots() []string {
	return []string{e.Layout.InstallRoot, e.Layout.ConfigDir}
}

func (e *Env) sideStoreDir(root, id string) string {
	return filepath.Join(e.P(root), sideStoreName, id)
}

// preserve keeps the current inode of path as blob for a rollback and
// returns the store root it used ("" for the snapshot directory). A hard
// link is the rule: replacements are renamed in, so the preserved link
// keeps the previous inode and the rollback relinks it without needing
// free space, and a full disk is the usual reason a transaction fails. A
// file on another filesystem than the lifecycle state is linked into a
// store below a managed root on its own filesystem; a byte copy into the
// snapshot directory is the last resort. The files the apply trigger
// watches are always copied (applyTriggerWatches).
func (e *Env) preserve(snapDir, path, blob string) (string, error) {
	err := os.Link(path, filepath.Join(snapDir, "files", blob))
	if err == nil {
		return "", nil
	}
	if errors.Is(err, syscall.EXDEV) {
		id := filepath.Base(snapDir)
		if root := e.sideStoreFor(path, id); root != "" {
			if err := os.Link(path, filepath.Join(e.sideStoreDir(root, id), blob)); err == nil {
				return root, nil
			}
		}
	}
	return "", copyPreserved(path, filepath.Join(snapDir, "files", blob))
}

// sideStoreFor returns the managed root on the filesystem of path, with
// the store of snapshot id created below it, or "" when there is none.
func (e *Env) sideStoreFor(path, id string) string {
	file, err := os.Lstat(path)
	if err != nil {
		return ""
	}
	for _, root := range e.sideStoreRoots() {
		info, err := os.Lstat(e.P(root))
		if err != nil || !info.IsDir() || !sameDevice(info, file) {
			continue
		}
		parent := filepath.Join(e.P(root), sideStoreName)
		if err := os.Mkdir(parent, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			continue
		}
		if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
			continue
		}
		if err := os.Mkdir(e.sideStoreDir(root, id), 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			continue
		}
		return root
	}
	return ""
}

func sameDevice(a, b os.FileInfo) bool {
	sa, okA := a.Sys().(*syscall.Stat_t)
	sb, okB := b.Sys().(*syscall.Stat_t)
	return okA && okB && sa.Dev == sb.Dev
}

// blobPath is where the preserved copy of entry is, or "" when the index
// names a store this lifecycle does not use.
func (e *Env) blobPath(snap *snapshot, entry snapshotEntry) string {
	if entry.Store == "" {
		return filepath.Join(snap.Dir, "files", entry.Blob)
	}
	if !contains(e.sideStoreRoots(), entry.Store) {
		return ""
	}
	return filepath.Join(e.sideStoreDir(entry.Store, filepath.Base(snap.Dir)), entry.Blob)
}

// checkBlobs reports a snapshot whose preserved files are missing, which no
// retry can restore.
func (e *Env) checkBlobs(snap *snapshot) error {
	for _, entry := range snap.Entries {
		if entry.Dir || !entry.Present {
			continue
		}
		blob := e.blobPath(snap, entry)
		if blob == "" {
			return fmt.Errorf("preserved copy of %s is in an unknown store %s", entry.Path, entry.Store)
		}
		info, err := os.Lstat(blob)
		if err != nil {
			return fmt.Errorf("preserved copy of %s: %w", entry.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("preserved copy of %s is not a regular file", entry.Path)
		}
	}
	return nil
}

// restore puts every file back exactly as snapshotted, removes files that
// did not exist before and then the directories the transaction created.
func (e *Env) restore(snap *snapshot) error {
	return errors.Join(e.restoreFiles(snap), e.removeCreatedDirs(snap))
}

// restoreFiles puts every file back exactly as snapshotted and removes
// files that did not exist before. Directories only get their mode and
// owner back. Every step replaces or removes a name atomically, so it is
// safe while the services run, and repeating it is cheap: a file already
// restored is the preserved inode and only gets its metadata checked.
func (e *Env) restoreFiles(snap *snapshot) error {
	var errs []error
	for _, entry := range snap.Entries {
		path := e.P(entry.Path)
		switch {
		case entry.Dir:
			if entry.Present {
				if err := os.Chmod(path, entry.Mode); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
				if err := e.Lchown(path, entry.UID, entry.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		case entry.Present:
			if err := mkdirParents(filepath.Dir(path)); err != nil {
				errs = append(errs, err)
				continue
			}
			blob := e.blobPath(snap, entry)
			if blob == "" {
				errs = append(errs, fmt.Errorf("restore %s: the preserved copy is in an unknown store %s", entry.Path, entry.Store))
				continue
			}
			if err := e.restoreFile(blob, path, entry.Mode, fileOwner{UID: entry.UID, GID: entry.GID}); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", entry.Path, err))
			}
		default:
			if err := removeFile(path); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", entry.Path, err))
			}
		}
	}
	return errors.Join(errs...)
}

// restoreFile puts a preserved blob back at path without copying its bytes
// whenever it can. The snapshot hard-links the previous file, so a file the
// transaction never replaced is still that inode and only needs its mode and
// owner back, and a replaced one is restored by linking the blob to a
// same-directory temporary name and renaming it over the target: neither
// needs free data blocks, which matters because a full disk is a common
// reason the transaction failed. A byte copy is the fallback when no store
// on the file's filesystem could hold the preserved link.
func (e *Env) restoreFile(blob, path string, mode os.FileMode, owner fileOwner) error {
	blobInfo, err := os.Lstat(blob)
	if err != nil {
		return err
	}
	if current, err := os.Lstat(path); err == nil && current.Mode().IsRegular() && os.SameFile(blobInfo, current) {
		return e.fixMetadata(path, mode, owner)
	}
	if err := e.linkAtomic(blob, path, mode, owner); err == nil {
		return nil
	} else if !errors.Is(err, errLinkUnavailable) {
		return err
	}
	return e.copyFileAtomic(blob, path, mode, owner)
}

// errLinkUnavailable marks a hard link the filesystem refused, so the
// caller falls back to copying.
var errLinkUnavailable = errors.New("hard link unavailable")

// linkAtomic makes path a new name of src, atomically replacing path.
func (e *Env) linkAtomic(src, path string, mode os.FileMode, owner fileOwner) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to replace it", path)
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".dc-"+hex.EncodeToString(suffix))
	if err := os.Link(src, tmp); err != nil {
		return fmt.Errorf("%w: %v", errLinkUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmp)
		}
	}()
	if err := os.Chmod(tmp, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
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

// removeCreatedDirs removes the directories the rolled-back transaction
// created, deepest first, so a failed first install leaves nothing that
// the next attempt would mistake for an unmanaged layout. State directories
// the services wrote into during activation are removed with their
// contents; every other directory only when empty.
func (e *Env) removeCreatedDirs(snap *snapshot) error {
	l := e.Layout
	state := map[string]bool{
		l.DataDir: true, l.GuardianAuthDir: true, l.LogDir: true, filepath.Join(l.LogDir, "gateway"): true,
		l.HookSocketDir: true, l.VendorPolicyDir: true,
	}
	created := []string{}
	for _, entry := range snap.Entries {
		if entry.Dir && !entry.Present {
			created = append(created, entry.Path)
		}
	}
	sort.Slice(created, func(i, j int) bool { return len(created[i]) > len(created[j]) })
	var errs []error
	for _, dir := range created {
		if state[dir] {
			if err := os.RemoveAll(e.P(dir)); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", dir, err))
			}
			continue
		}
		_ = removeDirIfEmpty(e.P(dir))
	}
	return errors.Join(errs...)
}

func (e *Env) discardSnapshot(snap *snapshot) {
	if snap != nil && snap.Dir != "" {
		_ = os.RemoveAll(snap.Dir)
		e.removeSideStores(filepath.Base(snap.Dir))
	}
}

// removeSideStores removes the per-filesystem stores of snapshot id, or
// every store when id is "".
func (e *Env) removeSideStores(id string) {
	if id == "." || id == ".." || id == string(filepath.Separator) {
		return
	}
	for _, root := range e.sideStoreRoots() {
		parent := filepath.Join(e.P(root), sideStoreName)
		if info, err := os.Lstat(parent); err != nil || !info.IsDir() {
			continue
		}
		if id == "" {
			_ = os.RemoveAll(parent)
			continue
		}
		_ = os.RemoveAll(filepath.Join(parent, id))
		_ = removeDirIfEmpty(parent)
	}
}
