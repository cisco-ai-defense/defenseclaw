// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

// dataDirSnapshotMaxEntries bounds the per-user data directory a failed
// install records; a larger tree is not recorded and nothing is removed.
const dataDirSnapshotMaxEntries = 20000

var errDataDirSnapshotTooLarge = errors.New("data directory too large to record")

// dataDirSnapshot is what a per-user DefenseClaw data directory held before
// a connector's Setup, so a failed install removes what it added: the hook
// scripts, their token and config files and the connector backups. Its
// teardown takes back only the agent's hook registration, so those stayed,
// and with no manifest row for the account the uninstall --purge, which
// removes the data directory of enrolled accounts only, never removed them
// (GAP-0509). entries is nil when the tree could not be recorded.
type dataDirSnapshot struct {
	dir     string
	existed bool
	entries map[string]bool
}

// snapshotDataDir records the entries below dir, without following links.
func snapshotDataDir(dir string) dataDirSnapshot {
	snap := dataDirSnapshot{dir: dir, entries: map[string]bool{}}
	info, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return snap
	case err != nil || !info.IsDir():
		snap.entries = nil
		return snap
	}
	snap.existed = true
	if err := walkDataDir(dir, func(rel string, _ fs.DirEntry) { snap.entries[rel] = true }); err != nil {
		snap.entries = nil
	}
	return snap
}

// walkDataDir calls visit for every entry below dir (dir itself is "."),
// in lexical order, without following links.
func walkDataDir(dir string, visit func(rel string, d fs.DirEntry)) error {
	count := 0
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if count++; count > dataDirSnapshotMaxEntries {
			return errDataDirSnapshotTooLarge
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		visit(rel, d)
		return nil
	})
}

// removeAdded removes every file below the data directory that was not
// there at the snapshot, then the folders it added once they are empty, and
// the data directory itself when the install created it and nothing is left
// in it. A link is removed, never followed; what was there before stays,
// and so does a folder something else filled meanwhile. It runs with the
// account's credentials, as the install does.
func (s dataDirSnapshot) removeAdded() error {
	if s.entries == nil {
		return nil
	}
	if info, err := os.Lstat(s.dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	} else if !info.IsDir() {
		return fmt.Errorf("%s is no longer a folder", s.dir)
	}
	var files, dirs []string
	if err := walkDataDir(s.dir, func(rel string, d fs.DirEntry) {
		if rel == "." || s.entries[rel] {
			return
		}
		if d.IsDir() {
			dirs = append(dirs, rel)
		} else {
			files = append(files, rel)
		}
	}); err != nil {
		return err
	}
	var errs []error
	for _, rel := range files {
		if err := os.Remove(filepath.Join(s.dir, rel)); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	// Deepest first: the walk lists a folder before what it holds.
	slices.Reverse(dirs)
	if !s.existed {
		dirs = append(dirs, ".")
	}
	for _, rel := range dirs {
		path := filepath.Join(s.dir, rel)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			if left, readErr := os.ReadDir(path); readErr == nil && len(left) > 0 {
				continue
			}
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// hookConfigFileMaxBytes bounds a hook config file a failed install
// compares; a larger one counts as changed.
const hookConfigFileMaxBytes = 16 << 20

// hookConfigSnapshot is what the agent's hook config files and DefenseClaw
// plugin artifacts held before a connector's Setup: nil for a missing file,
// the SHA-256 of its bytes otherwise. A Setup that failed before it wrote
// any of them registered nothing, so the files it added below the data
// directory can go even when its teardown cannot run (GAP-0509: the teardown
// of a Claude Code install fails on the same unparseable settings Setup
// did).
type hookConfigSnapshot struct {
	sums map[string][]byte
	ok   bool
}

func snapshotHookConfigs(paths []string) hookConfigSnapshot {
	snap := hookConfigSnapshot{sums: map[string][]byte{}, ok: true}
	for _, path := range paths {
		sum, err := hookConfigSum(path)
		if err != nil {
			snap.ok = false
			return snap
		}
		snap.sums[path] = sum
	}
	return snap
}

// unchanged reports whether every file holds what it held at the snapshot.
// An unreadable file, then or now, counts as changed.
func (s hookConfigSnapshot) unchanged() bool {
	if !s.ok {
		return false
	}
	for path, before := range s.sums {
		now, err := hookConfigSum(path)
		if err != nil || !bytes.Equal(before, now) {
			return false
		}
	}
	return true
}

// hookConfigSum is the SHA-256 of path's bytes, nil when it does not exist.
// A folder hashes as its type only.
func hookConfigSum(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	switch {
	case info.IsDir():
		sum := sha256.Sum256([]byte("dir"))
		return sum[:], nil
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte("link\x00" + target))
		return sum[:], nil
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", path)
	case info.Size() > hookConfigFileMaxBytes:
		return nil, fmt.Errorf("%s is too large to compare", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	h.Write([]byte("file\x00"))
	if _, err := io.Copy(h, io.LimitReader(f, hookConfigFileMaxBytes+1)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
