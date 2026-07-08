// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package safefile writes secret-bearing or audit-relevant files
// atomically with mode 0600 so they cannot be observed in a
// world-readable state by another local user.
//
// # Background
//
// Multiple call-sites in DefenseClaw (gateway token persistence,
// device pairing, audit exports, OTLP scoped tokens) historically
// used os.Create + later os.Chmod, which leaves a window where the
// file mode follows the process umask (typically 0644). On a shared
// host another user can open the file or pre-create a predictable
// temp path before the chmod fires. safefile.Write fixes the
// pattern in a single place.
package safefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadRegular reads a bounded security-sensitive file without following a
// symlink or accepting a hard link, unexpected owner, or path swap. Root-owned
// files are accepted for managed installations; otherwise the owner must match
// the current process. The final identity check closes the lstat/open race.
func ReadRegular(path string, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("safefile: empty path")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("safefile: managed input must be a regular non-symlink file: %s", path)
	}
	if err := validateReadOwnerAndLinks(before); err != nil {
		return nil, fmt.Errorf("safefile: unsafe managed input %s: %w", path, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return nil, fmt.Errorf("safefile: managed input changed while opening: %s", path)
	}
	limit := maxBytes
	if limit < 0 {
		limit = 1<<63 - 2
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("safefile: managed input exceeds %d bytes: %s", limit, path)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, after) {
		return nil, fmt.Errorf("safefile: managed input changed while reading: %s", path)
	}
	return raw, nil
}

// ErrSymlinkRefused is returned when the target path is a symlink.
// We refuse to follow symlinks for secret writes because that opens
// a same-name swap race against another local user.
var ErrSymlinkRefused = errors.New("safefile: refusing to write through symlink")

// Write atomically writes data to path with mode 0600. The write
// strategy:
//
//  1. Refuse to follow a symlink at path (lstat check).
//  2. Create a uniquely-named temp file in the same directory using
//     os.CreateTemp so the temp pathname cannot be predicted.
//  3. Open the temp with O_CREAT|O_EXCL|O_WRONLY and explicit 0600
//     mode (CreateTemp already does this).
//  4. Write data, fsync the file descriptor, fsync the directory.
//  5. Chmod the temp to 0600 explicitly (defensive in case the
//     CreateTemp default is umask-clipped on some platforms).
//  6. Rename the temp over the destination atomically.
//  7. Best-effort fsync of the parent directory after rename.
//
// On any failure between steps the temp file is removed.
func Write(path string, data []byte) error {
	if path == "" {
		return errors.New("safefile: empty path")
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlinkRefused, path)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("safefile: lstat %s: %w", path, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("safefile: mkdir %s: %w", dir, err)
	}
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, ".safefile-"+base+"-*")
	if err != nil {
		return fmt.Errorf("safefile: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup; if rename succeeded the unlink is a no-op.
		_ = os.Remove(tmpName)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("safefile: chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("safefile: write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("safefile: fsync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("safefile: close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("safefile: rename: %w", err)
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// CreateExclusive opens path for writing with O_CREATE|O_EXCL|O_WRONLY
// and explicit 0600 mode. The file MUST NOT already exist; the
// caller is responsible for closing the returned *os.File.
//
// Use this when the caller needs to stream output (audit exports,
// large JSONL writes) instead of buffering into memory for Write.
func CreateExclusive(path string) (*os.File, error) {
	if path == "" {
		return nil, errors.New("safefile: empty path")
	}
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("safefile: mkdir %s: %w", dir, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("safefile: open exclusive %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("safefile: chmod %s: %w", path, err)
	}
	return f, nil
}
