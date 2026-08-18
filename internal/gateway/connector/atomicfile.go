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

package connector

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// atomicWriteFile writes data to a temp file in the same directory and then
// performs a replacement-style rename. This prevents partial writes from
// corrupting the target file if the process crashes mid-write.
//
// If path is a symlink, write through to the linked target instead of renaming
// over the symlink itself. Many operators keep agent dotfiles in a managed
// repo and symlink ~/.codex/config.toml or ~/.claude/settings.json; preserving
// that filesystem shape is part of the teardown contract.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return atomicWriteFileWithPublisher(path, data, perm, atomicFilePublish)
}

// atomicWriteFileWithReplace preserves the injectable replacement seam used by
// durability-failure tests. Production writes use atomicFilePublish so Windows
// can bind private-file validation and publication to the staged file handle.
func atomicWriteFileWithReplace(
	path string,
	data []byte,
	perm os.FileMode,
	replace func(string, string) error,
) error {
	return atomicWriteFileWithPublisher(
		path, data, perm,
		func(source, destination string, _ os.FileInfo, _ os.FileMode) error {
			return replace(source, destination)
		},
	)
}

type atomicFilePublisher func(string, string, os.FileInfo, os.FileMode) error

func atomicWriteFileWithPublisher(
	path string,
	data []byte,
	perm os.FileMode,
	publish atomicFilePublisher,
) error {
	writePath, err := resolveAtomicWritePath(path)
	if err != nil {
		return err
	}

	dir := filepath.Dir(writePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir for %s: %w", writePath, err)
	}
	// Avoid replacing an already-correct config. This is especially important
	// on Windows, where a replacement is a file-identity transition and must not
	// churn NTFS metadata. The platform helper validates the effective owner-only
	// DACL instead of comparing Go's synthetic 0666 FileMode to 0600.
	if atomicFileAlreadyMatches(writePath, data, perm) {
		return nil
	}

	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if runtime.GOOS == "windows" && perm.Perm()&0o077 == 0 {
		if err := safefile.ProtectFile(tmpPath); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("protect temp file: %w", err)
		}
		// ProtectFile must address the file opened by CreateTemp. Verify that
		// exact handle before placing any sensitive bytes into it so a pathname
		// swap cannot redirect the protection operation to a different file.
		if err := atomicFileValidateStagedProtection(tmp, perm); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("validate protected temp file: %w", err)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync temp file: %w", err)
	}
	stagedInfo, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("stat temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := publish(tmpPath, writePath, stagedInfo, perm); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename %s → %s: %w", tmpPath, writePath, err)
	}
	// The staged file was synced before publication. POSIX rename additionally
	// needs an explicit parent-directory fsync.
	if runtime.GOOS != "windows" {
		directory, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("open parent directory for sync: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil {
			return fmt.Errorf("sync parent directory: %w", syncErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close parent directory after sync: %w", closeErr)
		}
	}
	return nil
}

func atomicFileAlreadyMatches(path string, data []byte, perm os.FileMode) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !atomicFileProtectionMatches(file, openedInfo, perm) {
		return false
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return false
	}
	current, err := io.ReadAll(file)
	if err != nil || !bytes.Equal(current, data) {
		return false
	}
	pathInfo, err = os.Lstat(path)
	return err == nil && pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(openedInfo, pathInfo)
}

func resolveAtomicWritePath(path string) (string, error) {
	cur := path
	for i := 0; i < 16; i++ {
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return cur, nil
			}
			return "", fmt.Errorf("lstat %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return cur, nil
		}
		target, err := os.Readlink(cur)
		if err != nil {
			return "", fmt.Errorf("readlink %s: %w", cur, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = filepath.Clean(target)
	}
	return "", fmt.Errorf("resolve symlink %s: too many symlinks", path)
}
