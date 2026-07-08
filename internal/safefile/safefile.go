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
	"os"
	"path/filepath"
)

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
	return write(path, data)
}

// WritePrivate protects the managed parent directory and holds it against
// replacement while atomically writing a sensitive state file.
func WritePrivate(path string, data []byte) error {
	return writePrivate(path, data, nil)
}

func writePrivate(path string, data []byte, beforeWrite func()) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := ProtectDirectory(dir); err != nil {
		return err
	}
	return withLockedDirectory(dir, func() error {
		if err := protectDirectory(dir); err != nil {
			return fmt.Errorf("safefile: validate private directory %s: %w", dir, err)
		}
		if beforeWrite != nil {
			beforeWrite()
		}
		return write(path, data)
	})
}

func write(path string, data []byte) error {
	if path == "" {
		return errors.New("safefile: empty path")
	}
	if err := rejectReparsePath(path); err != nil {
		return err
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
	if err := rejectReparsePath(dir); err != nil {
		return err
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
	if err := protectFile(tmpName, tmp); err != nil {
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
	if err := rejectReparsePath(path); err != nil {
		return err
	}
	if err := preserveExistingProtection(path, tmpName); err != nil {
		return fmt.Errorf("safefile: preserve existing protection: %w", err)
	}
	if err := replaceFile(tmpName, path); err != nil {
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
	if err := rejectReparseChain(dir); err != nil {
		return nil, err
	}
	if err := rejectReparsePath(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("safefile: mkdir %s: %w", dir, err)
	}
	if err := rejectReparseChain(dir); err != nil {
		return nil, err
	}
	if err := rejectReparsePath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("safefile: open exclusive %s: %w", path, err)
	}
	if err := protectFile(path, f); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("safefile: chmod %s: %w", path, err)
	}
	return f, nil
}

// ProtectDirectory creates and protects a DefenseClaw-owned private state
// directory. Callers must not use it for shared or operator-selected paths.
func ProtectDirectory(path string) error {
	if path == "" {
		return errors.New("safefile: empty directory path")
	}
	if err := rejectReparseChain(path); err != nil {
		return err
	}
	if err := makePrivateDirectories(path); err != nil {
		return fmt.Errorf("safefile: mkdir %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("safefile: private directory path is not a directory: %s", path)
	}
	if err := rejectReparseChain(path); err != nil {
		return err
	}
	return protectDirectory(path)
}

// ProtectFile applies the platform-native owner-only protection contract to an
// existing regular file.
func ProtectFile(path string) error {
	expected, err := validateRegularFilePath(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return fmt.Errorf("safefile: file changed while opening: %s", path)
	}
	current, err := validateRegularFilePath(path)
	if err != nil {
		return err
	}
	if !os.SameFile(opened, current) {
		return fmt.Errorf("safefile: file changed while validating: %s", path)
	}
	return protectFile(path, f)
}

func validateRegularFilePath(path string) (os.FileInfo, error) {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	if err := rejectReparseChain(dir); err != nil {
		return nil, err
	}
	if err := rejectReparsePath(path); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %s", ErrSymlinkRefused, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("safefile: path is not a regular file: %s", path)
	}
	return info, nil
}
