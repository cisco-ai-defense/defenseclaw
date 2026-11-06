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

package watcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// bundledBaselineScanner scans the pinned copy for a first-sight bundled
// baseline. Scanners without this contract still scan the live path, and
// their findings remain active.
type bundledBaselineScanner interface {
	ScanBaseline(context.Context, string, string) (*scanner.ScanResult, error)
}

const (
	baselineCopyMaxEntries   = 20000
	baselineCopyMaxFiles     = 10000
	baselineCopyMaxFileBytes = 16 << 20
	baselineCopyMaxBytes     = 256 << 20
)

var errUnpinnedPlugin = errors.New("bundled plugin input cannot be pinned")

// scanBundledPluginBaseline only permits a baseline marker when the scanner
// reads a copy made from the same physical tree as the first snapshot. An
// unverified scan still emits its ordinary findings from the live target.
func scanBundledPluginBaseline(ctx context.Context, s scanner.Scanner, target string, before *bundledPluginScanState) (*scanner.ScanResult, bool, error) {
	pinnedScanner, ok := s.(bundledBaselineScanner)
	if !ok {
		result, err := s.Scan(ctx, target)
		return result, false, err
	}
	copyPath, cleanup, err := copyBundledPlugin(target, before)
	if err != nil {
		result, scanErr := s.Scan(ctx, target)
		return result, false, scanErr
	}
	defer cleanup()
	result, err := pinnedScanner.ScanBaseline(ctx, target, copyPath)
	if err != nil || result == nil {
		result, scanErr := s.Scan(ctx, target)
		return result, false, scanErr
	}
	result.Target = target
	return result, true, err
}

// copyBundledPlugin opens the plugin before walking it. os.Root keeps every
// subsequent open under that directory even if its original name is moved.
// Refusing links and non-regular files keeps the copied scanner input within
// the physical tree. The size bounds prevent an unexpected bundle from
// turning a startup scan into an unbounded copy.
func copyBundledPlugin(target string, before *bundledPluginScanState) (string, func(), error) {
	root, err := os.OpenRoot(target)
	if err != nil {
		return "", nil, err
	}
	defer root.Close()
	info, err := root.Stat(".")
	if err != nil || len(before.directories) == 0 || !os.SameFile(info, before.directories[0]) {
		return "", nil, errUnpinnedPlugin
	}
	privateDir, err := os.MkdirTemp("", "dc-plugin-baseline-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(privateDir) }
	copyPath := filepath.Join(privateDir, "plugin")
	if err := os.Mkdir(copyPath, 0o700); err != nil {
		cleanup()
		return "", nil, err
	}
	type copiedDir struct {
		path string
		mode os.FileMode
	}
	var dirs []copiedDir
	entries, files, totalBytes := 0, 0, int64(0)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		entries++
		if entries > baselineCopyMaxEntries {
			return errUnpinnedPlugin
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errUnpinnedPlugin
		}
		path := filepath.Join(copyPath, filepath.FromSlash(name))
		if entry.IsDir() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if err := os.Mkdir(path, 0o700); err != nil {
				return err
			}
			dirs = append(dirs, copiedDir{path, info.Mode().Perm()})
			return nil
		}
		if !entry.Type().IsRegular() {
			return errUnpinnedPlugin
		}
		files++
		if files > baselineCopyMaxFiles {
			return errUnpinnedPlugin
		}
		source, err := root.Open(name)
		if err != nil {
			return err
		}
		fileInfo, err := source.Stat()
		if err != nil || !fileInfo.Mode().IsRegular() ||
			fileInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
			fileInfo.Size() > baselineCopyMaxFileBytes ||
			totalBytes+fileInfo.Size() > baselineCopyMaxBytes {
			_ = source.Close()
			return errUnpinnedPlugin
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = source.Close()
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(source, baselineCopyMaxFileBytes+1))
		readCloseErr := source.Close()
		closeErr := out.Close()
		if copyErr != nil {
			return copyErr
		}
		if readCloseErr != nil {
			return readCloseErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > baselineCopyMaxFileBytes || totalBytes+n > baselineCopyMaxBytes {
			return errUnpinnedPlugin
		}
		totalBytes += n
		return os.Chmod(path, fileInfo.Mode().Perm())
	})
	if err == nil {
		for i := len(dirs) - 1; i >= 0; i-- {
			if err = os.Chmod(dirs[i].path, dirs[i].mode); err != nil {
				break
			}
		}
	}
	if err == nil {
		err = os.Chmod(copyPath, info.Mode().Perm())
	}
	if err == nil {
		copiedHash, hashErr := fingerprintBundledTree(copyPath, nil)
		err = hashErr
		if err == nil && copiedHash != before.treeHash {
			err = fmt.Errorf("%w: content changed while copied", errUnpinnedPlugin)
		}
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return copyPath, cleanup, nil
}

// fingerprintBundledTree includes every entry and regular-file byte. The
// ordinary drift snapshot intentionally skips dependency folders; that hash
// cannot establish which complete tree a baseline scanner inspected.
func fingerprintBundledTree(path string, expected os.FileInfo) (string, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if expected != nil {
		info, err := root.Stat(".")
		if err != nil || !os.SameFile(info, expected) {
			return "", errUnpinnedPlugin
		}
	}
	hash := sha256.New()
	entries, files, totalBytes := 0, 0, int64(0)
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if name == "." {
			return nil
		}
		entries++
		if entries > baselineCopyMaxEntries || entry.Type()&os.ModeSymlink != 0 {
			return errUnpinnedPlugin
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(hash, "%s\x00%s\x00", name, info.Mode())
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errUnpinnedPlugin
		}
		files++
		if files > baselineCopyMaxFiles || info.Size() > baselineCopyMaxFileBytes ||
			totalBytes+info.Size() > baselineCopyMaxBytes {
			return errUnpinnedPlugin
		}
		file, err := root.Open(name)
		if err != nil {
			return err
		}
		fileInfo, err := file.Stat()
		if err != nil || !fileInfo.Mode().IsRegular() ||
			fileInfo.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			_ = file.Close()
			return errUnpinnedPlugin
		}
		n, copyErr := io.Copy(hash, io.LimitReader(file, baselineCopyMaxFileBytes+1))
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n > baselineCopyMaxFileBytes || totalBytes+n > baselineCopyMaxBytes {
			return errUnpinnedPlugin
		}
		totalBytes += n
		fmt.Fprintf(hash, "\x00%d\x00", n)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
