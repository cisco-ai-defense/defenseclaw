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

package workspace

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// FileID is a (device, inode) pair.
type FileID struct {
	Dev uint64 `json:"dev"`
	Ino uint64 `json:"ino"`
}

// FileState is a compact description of one path at a point in time.
type FileState struct {
	Exists bool `json:"exists"`
	Dir    bool `json:"dir,omitempty"`
	// Empty marks a directory with no entries.
	Empty   bool   `json:"empty,omitempty"`
	Symlink string `json:"symlink,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	Size    int64  `json:"size,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	// Content keeps small files so Undo can restore them byte for byte.
	Content []byte `json:"content,omitempty"`
}

func (s FileState) equal(o FileState) bool {
	return s.Exists == o.Exists && s.Dir == o.Dir && s.Symlink == o.Symlink &&
		s.Mode == o.Mode && s.SHA256 == o.SHA256
}

// captureState records p without following a symlink leaf. Directories
// get a digest over their entries (names, types, modes, content hashes) so
// a hooks directory change is one comparison. Files up to keepBytes keep
// their content.
func captureState(p string, keepBytes int64) (FileState, error) {
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	st := FileState{Exists: true, Mode: uint32(info.Mode().Perm())}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(p)
		if err != nil {
			return FileState{}, err
		}
		st.Symlink = target
		st.Mode = 0
	case info.IsDir():
		st.Dir = true
		sum, err := dirDigest(p)
		if err != nil {
			return FileState{}, err
		}
		st.SHA256 = sum
		if entries, err := os.ReadDir(p); err == nil && len(entries) == 0 {
			st.Empty = true
		}
	case info.Mode().IsRegular():
		st.Size = info.Size()
		data, sum, err := hashFile(p, keepBytes)
		if err != nil {
			return FileState{}, err
		}
		st.SHA256 = sum
		st.Content = data
	default:
		st.SHA256 = "special:" + info.Mode().Type().String()
	}
	return st, nil
}

// hashFile returns the sha256 of p and, when p is at most keep bytes, the
// bytes themselves.
func hashFile(p string, keep int64) ([]byte, string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	h := sha256.New()
	var kept []byte
	if keep > 0 {
		buf, err := io.ReadAll(io.LimitReader(f, keep+1))
		if err != nil {
			return nil, "", err
		}
		h.Write(buf)
		if int64(len(buf)) <= keep {
			kept = buf
		} else if _, err := io.Copy(h, f); err != nil {
			return nil, "", err
		}
	} else if _, err := io.Copy(h, f); err != nil {
		return nil, "", err
	}
	return kept, hex.EncodeToString(h.Sum(nil)), nil
}

func dirDigest(dir string) (string, error) {
	h := sha256.New()
	var entries []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		line := fmt.Sprintf("%s %o", filepath.ToSlash(rel), uint32(info.Mode()))
		switch {
		case d.Type()&os.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			line += " -> " + t
		case d.Type().IsRegular():
			_, sum, err := hashFile(p, 0)
			if err != nil {
				return err
			}
			line += " " + sum
		}
		entries = append(entries, line)
		if len(entries) > 10_000 {
			return fs.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(entries)
	for _, e := range entries {
		h.Write([]byte(e))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyRegular copies src to dst (which must not exist), sharing blocks
// through a reflink/APFS clone when the filesystem allows, then applies
// mode and mtime.
func copyRegular(src, dst string, mode fs.FileMode, mtime time.Time) error {
	if !cloneFile(src, dst) {
		in, err := os.OpenFile(src, os.O_RDONLY|oNoFollow, 0)
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
			_ = os.Remove(dst)
			return err
		}
		if err := out.Close(); err != nil {
			_ = os.Remove(dst)
			return err
		}
	}
	if err := os.Chmod(dst, mode.Perm()); err != nil {
		return err
	}
	if !mtime.IsZero() {
		_ = os.Chtimes(dst, mtime, mtime)
	}
	return nil
}

// removeTree deletes dir; when a plain removal fails it makes every
// directory below it writable first (read-only directories copied from a
// project).
func removeTree(dir string) error {
	if err := os.RemoveAll(dir); err != nil {
		_ = chmodTree(dir)
		return os.RemoveAll(dir)
	}
	return nil
}

func randomSuffix() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// rootFS performs writes below a project root through os.Root, so no path
// the agent planted (a symlinked directory, "..") can make a restore write
// outside the folder. Components that are symlinks or files where a
// directory is needed are removed first, the way git's checkout does.
type rootFS struct {
	root *os.Root
}

func openRootFS(dir string) (*rootFS, error) {
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("workspace: open %s: %w", dir, err)
	}
	return &rootFS{root: r}, nil
}

func (r *rootFS) Close() error { return r.root.Close() }

// ensureDir makes every component of rel a real directory.
func (r *rootFS) ensureDir(rel string) error {
	rel = path.Clean(rel)
	if rel == "." || rel == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(rel, "/") {
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		info, err := r.root.Lstat(cur)
		switch {
		case err == nil && info.IsDir():
			continue
		case err == nil:
			if err := r.root.Remove(cur); err != nil {
				return err
			}
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		if err := r.root.Mkdir(cur, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// clear removes whatever is at rel (file, symlink or directory tree)
// without following symlinks.
func (r *rootFS) clear(rel string) error {
	info, err := r.root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return r.root.RemoveAll(rel)
	}
	return r.root.Remove(rel)
}

// writeFile replaces rel with the bytes from src atomically.
func (r *rootFS) writeFile(rel string, src io.Reader, mode fs.FileMode, mtime time.Time) error {
	if err := r.ensureDir(path.Dir(rel)); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(rel), ".dc-restore-"+randomSuffix())
	f, err := r.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		_ = r.root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if err := r.root.Chmod(tmp, mode.Perm()); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if info, err := r.root.Lstat(rel); err == nil && info.IsDir() {
		if err := r.root.RemoveAll(rel); err != nil {
			_ = r.root.Remove(tmp)
			return err
		}
	}
	if err := r.root.Rename(tmp, rel); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if !mtime.IsZero() {
		_ = r.root.Chtimes(rel, mtime, mtime)
	}
	return nil
}

// sameFile reports whether rel is a regular file with exactly the bytes of
// the regular file other (outside the root).
func (r *rootFS) sameFile(rel, other string) bool {
	info, err := r.root.Lstat(rel)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	oinfo, err := os.Lstat(other)
	if err != nil || !oinfo.Mode().IsRegular() || oinfo.Size() != info.Size() {
		return false
	}
	a, err := r.root.Open(rel)
	if err != nil {
		return false
	}
	defer a.Close()
	b, err := os.OpenFile(other, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return false
	}
	defer b.Close()
	bufA, bufB := make([]byte, 64<<10), make([]byte, 64<<10)
	for {
		na, errA := io.ReadFull(a, bufA)
		nb, errB := io.ReadFull(b, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false
		}
		endA := errors.Is(errA, io.EOF) || errors.Is(errA, io.ErrUnexpectedEOF)
		endB := errors.Is(errB, io.EOF) || errors.Is(errB, io.ErrUnexpectedEOF)
		switch {
		case endA && endB:
			return true
		case errA != nil || errB != nil:
			return false
		}
	}
}

func (r *rootFS) symlink(rel, target string) error {
	if err := r.ensureDir(path.Dir(rel)); err != nil {
		return err
	}
	if err := r.clear(rel); err != nil {
		return err
	}
	return r.root.Symlink(target, rel)
}

// ensureDirMode makes every component of rel a real directory with the given mode.
// It refuses to operate if any component is a symlink (to prevent directory traversal attacks).
func (r *rootFS) ensureDirMode(rel string, mode fs.FileMode) error {
	rel = path.Clean(rel)
	if rel == "." || rel == "" {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(rel, "/") {
		if cur == "" {
			cur = part
		} else {
			cur = cur + "/" + part
		}
		info, err := r.root.Lstat(cur)
		switch {
		case err == nil && info.IsDir():
			continue
		case err == nil && info.Mode()&fs.ModeSymlink != 0:
			// Refuse to replace symlinks - potential directory traversal attack.
			return fmt.Errorf("refusing to create directory at %s: path component is a symlink", cur)
		case err == nil:
			if err := r.root.Remove(cur); err != nil {
				return err
			}
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		if err := r.root.Mkdir(cur, mode); err != nil {
			return err
		}
	}
	return nil
}

// writeFileNoFollow writes a file atomically with O_NOFOLLOW to prevent
// following symlinks and O_EXCL to ensure atomicity. It refuses to write if
// any parent path component is a symlink by checking each component before
// creating directories.
func (r *rootFS) writeFileNoFollow(rel string, src io.Reader, mode fs.FileMode, mtime time.Time) error {
	rel = path.Clean(rel)
	if err := r.ensureDirMode(path.Dir(rel), 0o700); err != nil {
		return err
	}
	tmp := path.Join(path.Dir(rel), ".dc-restore-"+randomSuffix())
	// Use O_NOFOLLOW to refuse writing through symlinks.
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	// Note: os.O_NOFOLLOW is platform-specific but available on Linux and macOS
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		flags |= 0x20000 // O_NOFOLLOW value
	}
	f, err := r.root.OpenFile(tmp, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		_ = r.root.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if err := r.root.Chmod(tmp, mode.Perm()); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if info, err := r.root.Lstat(rel); err == nil && info.IsDir() {
		if err := r.root.RemoveAll(rel); err != nil {
			_ = r.root.Remove(tmp)
			return err
		}
	}
	if err := r.root.Rename(tmp, rel); err != nil {
		_ = r.root.Remove(tmp)
		return err
	}
	if !mtime.IsZero() {
		_ = r.root.Chtimes(rel, mtime, mtime)
	}
	return nil
}
