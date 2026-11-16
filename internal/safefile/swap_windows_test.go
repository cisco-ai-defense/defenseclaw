// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func compareAndSwapOwnedForTest(source, destination string, expected SwapExpectation, limit int, inspect func(*os.File) error) (SwapResult, error) {
	return CompareAndSwapFile(source, destination, expected, limit, inspect, PublishDefenseClawOwned)
}

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

func TestReplaceFileInDirectoryUsesSourceDirectory(t *testing.T) {
	dir := t.TempDir()
	stagePath := filepath.Join(dir, "stage.tmp")
	if err := os.WriteFile(stagePath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "neighbor.json"), []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	name, err := windows.UTF16PtrFromString(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(name, windows.DELETE|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	stage := os.NewFile(uintptr(handle), stagePath)
	t.Cleanup(func() { _ = stage.Close() })
	if err := ReplaceFileInDirectory(parent, stage, "target.json"); err != nil {
		t.Fatal(err)
	}
	if err := stage.Close(); err != nil {
		t.Fatal(err)
	}
	requireSwapDirForTest(t, dir, map[string]string{
		"target.json": "new", "neighbor.json": "stable",
	})
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
			result, err := compareAndSwapOwnedForTest(source, destination, test.expected, 4, nil)
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
	_, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16,
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
	if _, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil); err == nil {
		t.Fatal("the swap replaced a file another writer has open for writing")
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

func TestRemoveFileIfUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if _, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("ours")}, 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove a missing file: %v", err)
	}
	if err := os.WriteFile(path, []byte("newer save"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("ours")}, 16, nil); !errors.Is(err, ErrSwapRaced) {
		t.Fatalf("remove another file: %v", err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "newer save"})
	if err := os.WriteFile(path, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("ours")}, 16, nil); err != nil || !result.Swapped {
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
	if _, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("ours")}, 16, nil); !errors.Is(err, ErrSwapRaced) {
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
	if result, err := RemoveFileIfUnchanged(path, SwapExpectation{Data: []byte("ours")}, 16, nil); err != nil || !result.Swapped {
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
			result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
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
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped || !result.Replaced {
		t.Fatalf("swap: %+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new", "other.tmp": "other"})
}

// The CAS publication uses exactly the two POSIX replacement flags on the
// staged file. A matched file still receives an ordinary complete body.
func TestCompareAndSwapFileUsesPOSIXReplacementFlags(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	previous, previousTx := swapRenameReplace, swapTransactedRename
	defer func() { swapRenameReplace, swapTransactedRename = previous, previousTx }()
	calls := 0
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		calls++
		if class != windows.FileRenameInfoEx || flags != fileRenameReplaceIfExists|fileRenamePOSIXSemantics {
			t.Errorf("CAS rename class=%d flags=%#x", class, flags)
		}
		return renameReplace(from, to, class, flags)
	}
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		calls++
		if flags != fileRenameReplaceIfExists|fileRenamePOSIXSemantics {
			t.Errorf("CAS transacted rename flags=%#x", flags)
		}
		return renameTransacted(from, to, flags, tx)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped || calls != 1 {
		t.Fatalf("CAS publication: result=%+v calls=%d err=%v", result, calls, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
}

// The staged policy is published inside a transaction on NTFS so a reader
// opening the live name during the replacement can still see the old file.
func TestCompareAndSwapFileTransactsNonImagePublication(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	previous, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previous, previousPlain }()
	transacted, plain := 0, 0
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted++
		if tx == 0 || tx == windows.InvalidHandle {
			t.Error("CAS publication received no file transaction")
		}
		return renameTransacted(from, to, flags, tx)
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped {
		t.Fatalf("CAS publication: result=%+v err=%v", result, err)
	}
	if transacted != 1 || plain != 0 {
		t.Fatalf("policy publication calls: transacted=%d plain=%d", transacted, plain)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
}

func TestCompareAndSwapFileKeepsTransactionAfterNameConflict(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	previousTx, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()
	transacted, plain := 0, 0
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted++
		if transacted == 1 {
			return windows.ERROR_TRANSACTIONAL_CONFLICT
		}
		return renameTransacted(from, to, flags, tx)
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped || transacted != 2 || plain != 0 {
		t.Fatalf("CAS publication: result=%+v transacted=%d plain=%d err=%v", result, transacted, plain, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
}

// A file edited outside DefenseClaw uses the ordinary one-step replacement.
// Its editor may need to retry normal sharing errors, but must not encounter
// a transaction reservation on the destination name.
func TestCompareAndSwapFileSharedClassAllowsAnExternalSave(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "product")
	admin := filepath.Join(dir, "admin.tmp")
	if err := os.WriteFile(admin, []byte("administrator"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousBefore, previousTx, previousPlain := swapBeforeReplace, swapTransactedRename, swapRenameReplace
	defer func() {
		swapBeforeReplace, swapTransactedRename, swapRenameReplace = previousBefore, previousTx, previousPlain
	}()
	var firstSave error
	transacted, plain := 0, 0
	swapBeforeReplace = func(string) { firstSave = os.Rename(admin, destination) }
	swapTransactedRename = func(string, string, uint32, windows.Handle) error {
		transacted++
		return errors.New("a shared file entered a transaction")
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")},
		16, nil, PublishSharedWithExternalWriters)
	if transacted != 0 {
		t.Fatalf("shared publication opened %d transactions", transacted)
	}
	if firstSave == nil {
		if !errors.Is(err, ErrSwapRaced) || result.Swapped || plain != 0 {
			t.Fatalf("administrator save won: swap=%+v plain=%d err=%v", result, plain, err)
		}
	} else {
		if !errors.Is(firstSave, windows.ERROR_SHARING_VIOLATION) &&
			!errors.Is(firstSave, windows.ERROR_ACCESS_DENIED) &&
			!errors.Is(firstSave, windows.ERROR_LOCK_VIOLATION) {
			t.Fatalf("administrator save received %v", firstSave)
		}
		if err != nil || !result.Swapped || plain != 1 {
			t.Fatalf("product publication: swap=%+v plain=%d err=%v", result, plain, err)
		}
		for attempt := 0; ; attempt++ {
			firstSave = os.Rename(admin, destination)
			if firstSave == nil {
				break
			}
			if attempt >= 100 || (!errors.Is(firstSave, windows.ERROR_SHARING_VIOLATION) &&
				!errors.Is(firstSave, windows.ERROR_ACCESS_DENIED) &&
				!errors.Is(firstSave, windows.ERROR_LOCK_VIOLATION)) {
				t.Fatalf("administrator retry: %v", firstSave)
			}
			time.Sleep(time.Millisecond)
		}
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "administrator" {
		t.Fatalf("administrator's saved bytes = %q, err=%v", data, err)
	}
}

func TestCompareAndSwapFileTransactsMZPrefixedRequirementsData(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "requirements.toml")
	old := []byte("MZ = 'retained'\nmode = 'old'\n# " + strings.Repeat("a", 128) + "\n")
	newData := []byte("MZ = 'retained'\nmode = 'new'\n# " + strings.Repeat("b", 128) + "\n")
	if err := os.WriteFile(destination, old, 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, string(newData))
	previousTx, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()
	transacted, plain := 0, 0
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted++
		return renameTransacted(from, to, flags, tx)
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: old}, len(newData), nil)
	if err != nil || !result.Swapped || transacted != 1 || plain != 0 {
		t.Fatalf("requirements publication: result=%+v transacted=%d plain=%d err=%v", result, transacted, plain, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"requirements.toml": string(newData)})
}

func TestCompareAndSwapFileRollsBackUncommittedRename(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	previous := swapTransactedRename
	defer func() { swapTransactedRename = previous }()
	rollback := errors.New("test rollback after rename")
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		if err := renameTransacted(from, to, flags, tx); err != nil {
			return err
		}
		return rollback
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if !errors.Is(err, rollback) || result.Swapped {
		t.Fatalf("CAS rollback: result=%+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
}

func TestCompareAndSwapFileFallsBackWhenTransactionsUnavailable(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "unsupported volume", err: windows.ERROR_NOT_SUPPORTED},
		{name: "encrypted stage", err: windows.ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := writeSwapSourceForTest(t, dir, "new")
			previousTx, previousPlain := swapTransactedRename, swapRenameReplace
			defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()
			transacted, plain := 0, 0
			swapTransactedRename = func(_, _ string, _ uint32, _ windows.Handle) error {
				transacted++
				return test.err
			}
			swapRenameReplace = func(from, to string, class, flags uint32) error {
				plain++
				return renameReplace(from, to, class, flags)
			}
			result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
			if err != nil || !result.Swapped || transacted != 1 || plain != 1 {
				t.Fatalf("CAS fallback: result=%+v transacted=%d plain=%d err=%v", result, transacted, plain, err)
			}
			requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
		})
	}
}

func TestCompareAndSwapFileRechecksIdentityAfterEncryptedStageFallback(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "new")
	newer := filepath.Join(dir, "newer.tmp")
	if err := os.WriteFile(newer, []byte("newer save"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousTx, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()
	transacted, plain := 0, 0
	swapTransactedRename = func(_, to string, _ uint32, _ windows.Handle) error {
		transacted++
		posixRenameForTest(t, newer, to)
		return windows.ERROR_EFS_NOT_ALLOWED_IN_TRANSACTION
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if !errors.Is(err, ErrSwapRaced) || result.Swapped || transacted != 1 || plain != 0 {
		t.Fatalf("CAS fallback race: result=%+v transacted=%d plain=%d err=%v", result, transacted, plain, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "newer save", "source.tmp": "new"})
}

func TestCompareAndSwapFileLeavesProgramImagesOutsideTransactions(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "program.exe")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	imagePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(imagePath)
	if err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, string(image))
	previous, previousTx := swapRenameReplace, swapTransactedRename
	defer func() { swapRenameReplace, swapTransactedRename = previous, previousTx }()
	transacted := false
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted = true
		return renameTransacted(from, to, flags, tx)
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped {
		t.Fatalf("CAS publication: result=%+v err=%v", result, err)
	}
	if transacted {
		t.Fatal("program image replacement ran in a file transaction")
	}
	published, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(published, image) {
		t.Fatalf("published program image differs from source: size=%d err=%v", len(published), err)
	}
	requireNoSwapLeftoversForTest(t, dir, "program.exe")
}

func TestCompareAndSwapFilePublishesEmptyNonImage(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "")
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
	if err != nil || !result.Swapped {
		t.Fatalf("CAS publication: result=%+v err=%v", result, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": ""})
}

func TestSwapPOSIXRenameFlagsKeepReadOnlySupport(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_READONLY); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_NORMAL) }()
	target, err := os.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	flags, err := swapPOSIXRenameFlags(target)
	if err != nil || flags != fileRenameReplaceIfExists|fileRenamePOSIXSemantics|fileRenameIgnoreReadOnlyAttribute {
		t.Fatalf("read-only rename flags=%#x err=%v", flags, err)
	}
}

// GAP-0897: on a volume without POSIX renames, the fallback must run while
// the compared file remains held. If that volume refuses the held replacement,
// the swap leaves the old file and staged source in place.
func TestCompareAndSwapFileWithoutPOSIXRenames(t *testing.T) {
	for _, test := range []struct {
		name    string
		inPlace bool
	}{
		{name: "unchanged"},
		{name: "in-place save stays refused", inPlace: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			source := writeSwapSourceForTest(t, dir, "new")
			previousRename, previousTx, previousMove := swapRenameReplace, swapTransactedRename, swapMoveFileReplace
			defer func() {
				swapRenameReplace, swapTransactedRename, swapMoveFileReplace = previousRename, previousTx, previousMove
			}()
			swapTransactedRename = func(_, _ string, _ uint32, _ windows.Handle) error {
				return windows.ERROR_INVALID_PARAMETER
			}
			swapRenameReplace = func(_, _ string, class, _ uint32) error {
				if class != windows.FileRenameInfoEx {
					t.Error("the fallback used a classic rename")
				}
				return windows.ERROR_INVALID_PARAMETER
			}
			moves := 0
			swapMoveFileReplace = func(from, to string) error {
				moves++
				if from != source || to != destination {
					t.Errorf("fallback paths do not match staged and destination paths")
				}
				if test.inPlace {
					if err := os.WriteFile(destination, []byte("in-place save"), 0o600); err == nil {
						t.Error("the compared file was writable during the fallback")
					}
				} else if writer, err := os.OpenFile(destination, os.O_WRONLY, 0); err == nil {
					_ = writer.Close()
					t.Error("the compared file was released before the fallback")
				}
				return windows.ERROR_SHARING_VIOLATION
			}
			result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
			if !errors.Is(err, ErrSwapUnsupported) || result.Swapped || moves != 1 {
				t.Fatalf("unsupported CAS publication: result=%+v moves=%d err=%v", result, moves, err)
			}
			requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
		})
	}
}
