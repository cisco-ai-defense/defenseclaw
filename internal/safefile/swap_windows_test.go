// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func writeSwapSourceForTest(t *testing.T, dir string, data string) string {
	t.Helper()
	source := filepath.Join(dir, "source.tmp")
	if err := os.WriteFile(source, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return source
}

func requireSwapDirForTest(t *testing.T, dir string, want map[string]string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got[entry.Name()] = string(data)
	}
	if len(got) != len(want) {
		t.Fatalf("directory = %v, want %v", got, want)
	}
	for name, data := range want {
		if got[name] != data {
			t.Fatalf("directory = %v, want %v", got, want)
		}
	}
}

// A compare-and-swap replaces only the file it expects, and leaves no
// replaced copy behind.
func TestCompareAndSwapFileReplacesOnlyTheExpectedFile(t *testing.T) {
	for _, test := range []struct {
		name     string
		onDisk   *string
		expected SwapExpectation
		swapped  bool
	}{
		{name: "expected bytes", onDisk: swapTestString("old"), expected: SwapExpectation{Exists: true, Data: []byte("old")}, swapped: true},
		{name: "expected absent", expected: SwapExpectation{}, swapped: true},
		{name: "different bytes", onDisk: swapTestString("newer save"), expected: SwapExpectation{Exists: true, Data: []byte("old")}},
		{name: "file appeared", onDisk: swapTestString("newer save"), expected: SwapExpectation{}},
		{name: "file disappeared", expected: SwapExpectation{Exists: true, Data: []byte("old")}},
		{name: "longer than the limit", onDisk: swapTestString("old and more"), expected: SwapExpectation{Exists: true, Data: []byte("old")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if test.onDisk != nil {
				if err := os.WriteFile(destination, []byte(*test.onDisk), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			source := writeSwapSourceForTest(t, dir, "new")
			result, err := CompareAndSwapFile(source, destination, test.expected, 4, nil)
			if test.swapped {
				if err != nil || !result.Swapped || result.Replaced != (test.onDisk != nil) {
					t.Fatalf("swap: %+v err=%v", result, err)
				}
				requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
				return
			}
			if !errors.Is(err, ErrSwapRaced) || result.Swapped {
				t.Fatalf("swap over another file: %+v err=%v", result, err)
			}
			want := map[string]string{"source.tmp": "new"}
			if test.onDisk != nil {
				want["hooks.json"] = *test.onDisk
			}
			requireSwapDirForTest(t, dir, want)
		})
	}
}

// inspect sees the locked file before the comparison, and its error stops the
// swap with the file in place.
func TestCompareAndSwapFileInspectRefuses(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	refused := errors.New("refused")
	inspected := ""
	_, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16,
		func(file *os.File) error {
			inspected = file.Name()
			return refused
		})
	if !errors.Is(err, refused) || inspected != destination {
		t.Fatalf("inspect: name %q err=%v", inspected, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

// While a swap holds the file, another process cannot write it; a writer
// that already has the file open for writing makes the swap wait, then fail
// without changing it.
func TestCompareAndSwapFileWaitsForAnOpenWriter(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(destination, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	source := writeSwapSourceForTest(t, dir, "new")
	if _, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil); err == nil {
		t.Fatal("the swap replaced a file another writer has open for writing")
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

func TestRemoveFileIfUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if _, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove a missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("newer save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove another file: %v", err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "newer save"})
	if err := os.WriteFile(path, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); err != nil || !result.Swapped {
		t.Fatalf("remove our file: %+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{})
}

// A read-only file that holds exactly the expected bytes is removed too, as
// the Codex requirements deletion this replaced did
// (FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE). A read-only file with other
// bytes is still kept.
func TestRemoveFileIfUnchangedRemovesAReadOnlyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requirements.toml")
	if err := os.WriteFile(path, []byte("newer save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
	if _, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove another read-only file: %v", err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"requirements.toml": "newer save"})
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if result, err := RemoveFileIfUnchanged(path, []byte("ours"), 16, nil); err != nil || !result.Swapped {
		t.Fatalf("remove our read-only file: %+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{})
}

func swapTestString(value string) *string { return &value }

func posixRenameForTest(t *testing.T, source, destination string) {
	t.Helper()
	if err := renameReplace(source, destination, windows.FileRenameInfoEx,
		fileRenameReplaceIfExists|fileRenamePOSIXSemantics); err != nil {
		t.Fatalf("POSIX rename %s over %s: %v", source, destination, err)
	}
}

// After the comparison the swap still refuses writers, so the compared bytes
// cannot change. Another process can still replace the file with a POSIX
// rename, delete it or rename it away until the swap's own rename: the swap
// then keeps that newer state and reports a race.
func TestCompareAndSwapFileRefusesAFileChangedBeforeTheReplace(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(t *testing.T, dir, destination string)
		want   map[string]string
	}{
		{
			name: "replaced with a POSIX rename",
			change: func(t *testing.T, dir, destination string) {
				newer := filepath.Join(dir, "newer.tmp")
				if err := os.WriteFile(newer, []byte("newer save"), 0o600); err != nil {
					t.Fatal(err)
				}
				posixRenameForTest(t, newer, destination)
			},
			want: map[string]string{"hooks.json": "newer save", "source.tmp": "new"},
		},
		{
			name: "deleted",
			change: func(t *testing.T, _, destination string) {
				if err := os.Remove(destination); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]string{"source.tmp": "new"},
		},
		{
			name: "renamed away",
			change: func(t *testing.T, _, destination string) {
				if err := os.Rename(destination, destination+".moved"); err != nil {
					t.Fatal(err)
				}
			},
			want: map[string]string{"hooks.json.moved": "old", "source.tmp": "new"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := writeSwapSourceForTest(t, dir, "new")
			previous := swapBeforeReplace
			swapBeforeReplace = func(path string) { test.change(t, dir, path) }
			defer func() { swapBeforeReplace = previous }()
			result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
			if !errors.Is(err, ErrSwapRaced) || result.Swapped {
				t.Fatalf("swap over a changed file: %+v err=%v", result, err)
			}
			requireSwapDirForTest(t, dir, test.want)
		})
	}
}

// Between the comparison and the rename, writes in place and ordinary
// replacements stay refused, so the swap publishes over exactly the file it
// compared.
func TestCompareAndSwapFileRefusesWritersUntilItReplaces(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.tmp")
	if err := os.WriteFile(other, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	previous := swapBeforeReplace
	swapBeforeReplace = func(path string) {
		if writer, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
			_ = writer.Close()
			t.Error("another process opened the file for writing before the replace")
		}
		if err := os.Rename(other, path); err == nil {
			t.Error("another process replaced the file with MoveFileEx before the replace")
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "old" {
			t.Errorf("read before the replace: %q err=%v", data, err)
		}
	}
	defer func() { swapBeforeReplace = previous }()
	result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped || !result.Replaced {
		t.Fatalf("swap: %+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new", "other.tmp": "other"})
}

// On a volume without POSIX renames the swap replaces the file in one
// ordinary rename after releasing its hold, and still refuses a file that
// changed first.
func TestCompareAndSwapFileWithoutPOSIXRenames(t *testing.T) {
	for _, test := range []struct {
		name   string
		change bool
		want   map[string]string
	}{
		{name: "unchanged", want: map[string]string{"hooks.json": "new"}},
		{name: "replaced first", change: true, want: map[string]string{"hooks.json": "newer save", "source.tmp": "new"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := writeSwapSourceForTest(t, dir, "new")
			classic := 0
			previous := swapRenameReplace
			swapRenameReplace = func(from, to string, class uint32, flags uint32) error {
				if class == windows.FileRenameInfoEx {
					if test.change {
						newer := filepath.Join(dir, "newer.tmp")
						if err := os.WriteFile(newer, []byte("newer save"), 0o600); err != nil {
							t.Fatal(err)
						}
						posixRenameForTest(t, newer, to)
					}
					return windows.ERROR_INVALID_PARAMETER
				}
				classic++
				return renameReplace(from, to, class, flags)
			}
			defer func() { swapRenameReplace = previous }()
			result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
			if test.change {
				if !errors.Is(err, ErrSwapRaced) || result.Swapped || classic != 0 {
					t.Fatalf("swap over a changed file: %+v classic=%d err=%v", result, classic, err)
				}
			} else if err != nil || !result.Swapped || classic != 1 {
				t.Fatalf("swap: %+v classic=%d err=%v", result, classic, err)
			}
			requireSwapDirForTest(t, dir, test.want)
		})
	}
}
