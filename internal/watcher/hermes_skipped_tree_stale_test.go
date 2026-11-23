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
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// staleSizeEntry is a directory entry whose size is the one a lazily updated
// parent folder listing still holds (Windows NTFS, while a file is open).
type staleSizeEntry struct {
	fs.DirEntry
	size int64
}

func (e staleSizeEntry) Info() (fs.FileInfo, error) {
	info, err := e.DirEntry.Info()
	if err != nil {
		return nil, err
	}
	return staleSizeInfo{FileInfo: info, size: e.size}, nil
}

type staleSizeInfo struct {
	fs.FileInfo
	size int64
}

func (i staleSizeInfo) Size() int64 { return i.size }

func noManifestLoader(map[string][]byte) ([]string, error) { return nil, nil }

// GAP-1890: skippedTreeHash takes a file's size from the file's own record
// (os.Lstat), not from the directory entry, which on Windows is the parent
// folder listing that NTFS updates lazily. A file whose listing still shows a
// size past the scanner's read limit was left unhashed, so a same-size edit
// of it, or a shrink to a size the scanner reads, did not move the hash.
func TestGAP1890SkippedTreeHashIgnoresStaleListingSize(t *testing.T) {
	dir := t.TempDir()
	writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: a\n")
	main := filepath.Join(dir, "node_modules", "main.js")
	writePluginFile(t, main, "safe()\n")
	plain := skippedTreeHash(dir, noManifestLoader)

	walk := hermesWalkDir
	hermesWalkDir = func(root string, fn fs.WalkDirFunc) error {
		return walk(root, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.Type().IsRegular() {
				entry = staleSizeEntry{DirEntry: entry, size: hermesScannerReadBytes + 1}
			}
			return fn(path, entry, err)
		})
	}
	t.Cleanup(func() { hermesWalkDir = walk })

	stale := skippedTreeHash(dir, noManifestLoader)
	if stale != plain {
		t.Fatal("a stale listing size changed the skipped-tree hash of an unchanged tree")
	}
	writePluginFile(t, main, "eval()\n")
	if after := skippedTreeHash(dir, noManifestLoader); after == stale {
		t.Fatal("a same-size edit of a file with a stale listing size left the skipped-tree hash unchanged")
	}
}

// GAP-1890, on the real file system: a file shrunk to a size the scanner
// reads while a write handle is still open is hashed like the closed file.
// On Windows the parent listing may keep the old size until the handle closes.
func TestGAP1890SkippedTreeHashShrunkFileWithOpenHandle(t *testing.T) {
	shrinks := map[string]func(t *testing.T, path string) *os.File{
		"set-end-of-file": func(t *testing.T, path string) *os.File {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(64); err != nil {
				t.Fatal(err)
			}
			return f
		},
		"truncate-on-open-then-write": func(t *testing.T, path string) *os.File {
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(make([]byte, 64)); err != nil {
				t.Fatal(err)
			}
			return f
		},
		"set-end-of-file-then-write": func(t *testing.T, path string) *os.File {
			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(64); err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt([]byte("x"), 0); err != nil {
				t.Fatal(err)
			}
			return f
		},
	}
	for name, shrink := range shrinks {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writePluginFile(t, filepath.Join(dir, "plugin.yaml"), "name: a\n")
			big := filepath.Join(dir, "node_modules", "big.bin")
			writePluginFile(t, big, "")
			if err := os.Truncate(big, hermesScannerReadBytes+1024); err != nil {
				t.Fatal(err)
			}
			if got := skippedTreeHash(dir, noManifestLoader); got == "" {
				t.Fatal("the large file is not part of the skipped-tree hash")
			}
			f := shrink(t, big)
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = f.Close()
				}
			})
			open := skippedTreeHash(dir, noManifestLoader)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			if after := skippedTreeHash(dir, noManifestLoader); open != after {
				t.Fatal("the skipped-tree hash with the write handle open differs from the hash after it closed: a stale listing size skipped the file's content")
			}
		})
	}
}
