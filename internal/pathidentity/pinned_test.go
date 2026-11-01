// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pathidentity

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0300: the FileInfo a guard takes before its checks keeps the
// identity of the file that was checked, however the path changes after.
// With os.Lstat on Windows the identity is read at the first os.SameFile,
// so a file renamed over the path compares equal to itself.
func TestLstatPinnedKeepsTheCheckedFileIdentity(t *testing.T) {
	for name, stat := range map[string]func(string) (os.FileInfo, error){
		"LstatPinned": LstatPinned, "StatPinned": StatPinned,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "checked")
			replacement := filepath.Join(dir, "replacement")
			if err := os.WriteFile(path, []byte("checked"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(replacement, []byte("swapped in"), 0o600); err != nil {
				t.Fatal(err)
			}
			pinned, err := stat(path)
			if err != nil {
				t.Fatal(err)
			}
			lazy, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, path); err != nil {
				t.Fatal(err)
			}
			current, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if os.SameFile(pinned, current) {
				t.Fatalf("%s identity followed the path to the swapped file", name)
			}
			if pinned.Size() != int64(len("checked")) || pinned.Name() != "checked" {
				t.Fatalf("%s = %s, %d bytes; want the checked file", name, pinned.Name(), pinned.Size())
			}
			// Context only: os.Lstat compares equal here on Windows.
			t.Logf("os.Lstat taken before the swap compares equal after it: %v", os.SameFile(lazy, current))
		})
	}
}

// The pinned FileInfo describes the path as os.Lstat and os.Stat do.
func TestPinnedStatMatchesOS(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(file, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	// A path past MAX_PATH on Windows needs the extended-length form.
	long := dir
	for len(long) < 300 {
		long = filepath.Join(long, strings.Repeat("d", 40))
	}
	if err := os.MkdirAll(long, 0o700); err != nil {
		t.Fatal(err)
	}
	longFile := filepath.Join(long, "deep.txt")
	if err := os.WriteFile(longFile, []byte("deep"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{file, sub, longFile, dir + string(os.PathSeparator)}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err == nil {
		paths = append(paths, link)
	} else {
		t.Logf("no symbolic link case: %v", err)
	}
	for _, path := range paths {
		for _, c := range []struct {
			name   string
			pinned func(string) (os.FileInfo, error)
			os     func(string) (os.FileInfo, error)
		}{
			{"Lstat", LstatPinned, os.Lstat},
			{"Stat", StatPinned, os.Stat},
		} {
			got, err := c.pinned(path)
			if err != nil {
				t.Fatalf("%sPinned(%s): %v", c.name, path, err)
			}
			want, err := c.os(path)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name() != want.Name() || got.Mode() != want.Mode() || got.IsDir() != want.IsDir() ||
				(!got.IsDir() && got.Size() != want.Size()) || !got.ModTime().Equal(want.ModTime()) {
				t.Fatalf("%sPinned(%s) = %s %v %d %v; os = %s %v %d %v", c.name, path,
					got.Name(), got.Mode(), got.Size(), got.ModTime(), want.Name(), want.Mode(), want.Size(), want.ModTime())
			}
			if !os.SameFile(got, want) {
				t.Fatalf("%sPinned(%s) is not the same file as os.%s", c.name, path, c.name)
			}
		}
	}
	for _, c := range []struct {
		op   string
		stat func(string) (os.FileInfo, error)
	}{{"Lstat", LstatPinned}, {"Stat", StatPinned}} {
		_, err := c.stat(filepath.Join(dir, "missing"))
		var pathErr *os.PathError
		if !errors.Is(err, os.ErrNotExist) || !errors.As(err, &pathErr) || !strings.EqualFold(pathErr.Op, c.op) {
			t.Fatalf("%sPinned(missing) = %v; want a %s *os.PathError that is os.ErrNotExist", c.op, err, c.op)
		}
	}
}

func TestPinnedStatHookRunsAfterASuccessfulStat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var seen []string
	restore := SetPinnedStatHookForTest(func(p string) { seen = append(seen, p) })
	_, _ = LstatPinned(path)
	_, _ = StatPinned(path)
	_, _ = LstatPinned(path + ".missing")
	restore()
	_, _ = LstatPinned(path)
	if len(seen) != 2 || seen[0] != path || seen[1] != path {
		t.Fatalf("hook saw %q, want the two successful stats of %s", seen, path)
	}
}
