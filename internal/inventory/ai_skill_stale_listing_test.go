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

package inventory

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

// staleListingSizes makes the walk of hashSkillFolder list every regular file
// with the given size, as a stale folder listing does.
func staleListingSizes(t *testing.T, size int64) {
	t.Helper()
	read := skillReadDir
	skillReadDir = func(dir *os.File, n int) ([]fs.DirEntry, error) {
		entries, err := read(dir, n)
		for i, entry := range entries {
			if entry.Type().IsRegular() {
				entries[i] = staleSizeEntry{DirEntry: entry, size: size}
			}
		}
		return entries, err
	}
	t.Cleanup(func() { skillReadDir = read })
}

// GAP-1901: hashSkillFolder takes a file's size from the file's own record
// (os.Lstat), not from the directory entry, which on Windows is the parent
// folder listing that NTFS updates lazily. A file whose listing still shows a
// size past the limit made the folder too large, with no hash.
func TestGAP1901HashSkillFolderIgnoresStaleListingSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pdf")
	writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n", "run.py": "print('a')\n"})
	want, status, _ := hashSkillFolder(dir, maxSkillBytes)
	if status != SkillContentOK {
		t.Fatalf("hashSkillFolder = %q, %q", want, status)
	}
	staleListingSizes(t, maxSkillBytes+1)
	if got, status, _ := hashSkillFolder(dir, maxSkillBytes); status != SkillContentOK || got != want {
		t.Fatalf("a stale listing size changed the hash of an unchanged folder: %q, %q (want %q)", got, status, want)
	}
}

// GAP-1901, through the hash cache: a folder first seen too large is kept as
// too large; after the file shrinks, the scan that sees the changed signature
// must hash it, whatever size the folder listing still shows. Before the fix
// the stale size made the shrunk folder too large again and the cache kept
// that answer for a day.
func TestGAP1901ShrunkFileWithStaleListingIsHashedAndKept(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agents", "skills", "pdf")
	writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(big, maxSkillBytes+1024); err != nil {
		t.Fatal(err)
	}
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, Mode: "enhanced", DataDir: filepath.Join(home, "data"), HomeDir: home,
	}, nil)
	cleanupPreparedDiscoveryService(t, svc)
	svc.skillClock = skillClockAfterTheWrites
	scan := func() AISkillFacts {
		svc.resetSkillFacts()
		return *svc.skillFacts(dir, false)
	}
	if got := scan(); got.ContentStatus != SkillContentTooLarge {
		t.Fatalf("the oversized folder: %+v", got)
	}
	if err := os.Truncate(big, 64); err != nil {
		t.Fatal(err)
	}
	staleListingSizes(t, maxSkillBytes+1024)
	got := scan()
	if got.ContentStatus != SkillContentOK || got.ContentHash == "" {
		t.Fatalf("the shrunk folder is reported %+v: a stale listing size was taken for the file's size", got)
	}
	if entry, kept := svc.skillHashCache[dir]; !kept || entry.status != SkillContentOK {
		t.Fatalf("the hash cache holds %+v (kept=%v), want the shrunk folder's hash", entry, kept)
	}
	if again := scan(); again != got {
		t.Fatalf("the next scan = %+v, want %+v", again, got)
	}
}

// GAP-1901, on the real file system: a file shrunk to a size under the limit
// while a write handle is still open is hashed like the closed file. On
// Windows the parent listing may keep the old size until the handle closes.
func TestGAP1901ShrunkFileWithOpenHandleIsHashed(t *testing.T) {
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
			dir := filepath.Join(t.TempDir(), "pdf")
			writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
			big := filepath.Join(dir, "big.bin")
			if err := os.WriteFile(big, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(big, maxSkillBytes+1024); err != nil {
				t.Fatal(err)
			}
			if _, status, _ := hashSkillFolder(dir, maxSkillBytes); status != SkillContentTooLarge {
				t.Fatalf("the oversized folder is %q, want too large", status)
			}
			f := shrink(t, big)
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = f.Close()
				}
			})
			// What the folder listing and the file's own record say now.
			listed, own := int64(-1), int64(-1)
			if entries, err := os.ReadDir(dir); err == nil {
				for _, entry := range entries {
					if info, err := entry.Info(); err == nil && entry.Name() == "big.bin" {
						listed = info.Size()
					}
				}
			}
			if info, err := os.Lstat(big); err == nil {
				own = info.Size()
			}
			t.Logf("GAP1901DIAG %s listing size=%d, own size=%d (limit %d)", name, listed, own, int64(maxSkillBytes))
			open, openStatus, _ := hashSkillFolder(dir, maxSkillBytes)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			closed = true
			after, afterStatus, _ := hashSkillFolder(dir, maxSkillBytes)
			if afterStatus != SkillContentOK {
				t.Fatalf("the closed folder is %q, want ok", afterStatus)
			}
			// With the writer's handle open the folder is hashed, or (on
			// Windows, where the reader denies write sharing) unreadable and
			// not kept: never too large, and never another hash.
			if openStatus == SkillContentTooLarge || openStatus == SkillContentOK && open != after {
				t.Fatalf("with the write handle open the folder is %q %q, closed %q: a stale listing size made it too large", openStatus, open, after)
			}
		})
	}
}

// GAP-1901: the writer's handle is open before the folder is first read (an
// editor that keeps its file open), and shrinks the file through that handle
// after the read. The folder is then hashed again, or unreadable while the
// handle denies the reader (Windows), but never too large.
func TestGAP1901ShrunkByAHandleHeldAcrossAScan(t *testing.T) {
	steps := map[string]func(f *os.File) error{
		"set-end-of-file": func(f *os.File) error { return f.Truncate(64) },
		"set-end-of-file-then-write-and-sync": func(f *os.File) error {
			if err := f.Truncate(64); err != nil {
				return err
			}
			if _, err := f.WriteAt([]byte("x"), 0); err != nil {
				return err
			}
			return f.Sync()
		},
		"set-end-of-file-zero-then-write": func(f *os.File) error {
			if err := f.Truncate(0); err != nil {
				return err
			}
			_, err := f.WriteAt(make([]byte, 64), 0)
			return err
		},
	}
	for name, shrink := range steps {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "pdf")
			writeSkillFiles(t, dir, map[string]string{"SKILL.md": "---\nname: pdf\n---\n"})
			big := filepath.Join(dir, "big.bin")
			if err := os.WriteFile(big, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Truncate(big, maxSkillBytes+1024); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(big, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if _, status, _ := hashSkillFolder(dir, maxSkillBytes); status != SkillContentTooLarge {
				t.Fatalf("the oversized folder is %q, want too large", status)
			}
			if err := shrink(f); err != nil {
				t.Fatal(err)
			}
			listed, own := int64(-1), int64(-1)
			if entries, err := os.ReadDir(dir); err == nil {
				for _, entry := range entries {
					if info, err := entry.Info(); err == nil && entry.Name() == "big.bin" {
						listed = info.Size()
					}
				}
			}
			if info, err := os.Lstat(big); err == nil {
				own = info.Size()
			}
			t.Logf("GAP1901DIAG held-handle %s listing size=%d, own size=%d (limit %d)", name, listed, own, int64(maxSkillBytes))
			open, openStatus, _ := hashSkillFolder(dir, maxSkillBytes)
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			after, afterStatus, _ := hashSkillFolder(dir, maxSkillBytes)
			if afterStatus != SkillContentOK {
				t.Fatalf("the closed folder is %q, want ok", afterStatus)
			}
			if openStatus == SkillContentTooLarge || openStatus == SkillContentOK && open != after {
				t.Fatalf("with the write handle open the folder is %q %q, closed %q: a stale listing size made it too large", openStatus, open, after)
			}
		})
	}
}
