// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// openForSwapReaderTest opens path for reading with share, as an agent
// loading its policy does: Node (Cursor) and Rust (Codex) share reads, writes
// and deletion; Go shares reads and writes; .NET's File.ReadAllText shares
// only reads.
func openForSwapReaderTest(path string, share uint32) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ, share, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func readForSwapReaderTest(path string, share uint32) ([]byte, error) {
	file, err := openForSwapReaderTest(path, share)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

var swapReaderShares = []struct {
	name  string
	share uint32
	pause time.Duration
}{
	{"reader sharing deletion (Node, Rust)", windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE, 0},
	{"reader sharing writes (Go)", windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE, 50 * time.Microsecond},
	{"reader sharing only reads (.NET)", windows.FILE_SHARE_READ, 50 * time.Microsecond},
}

// An agent that loads its policy while DefenseClaw updates it must always
// find the old policy or the new one at the live name: never no file or a
// partial file. Cursor (Node) and Codex (Rust) share deletion and are never
// refused; a reader that does not is refused only for the instant of the
// rename and gets the file on a prompt retry.
func TestCompareAndSwapFileKeepsAPolicyAtTheNameThroughout(t *testing.T) {
	for _, reader := range swapReaderShares {
		t.Run(reader.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			versions := [][]byte{[]byte(`{"version":1,"policy":"A"}`), []byte(`{"version":1,"policy":"B, longer"}`)}
			if err := os.WriteFile(destination, versions[0], 0o600); err != nil {
				t.Fatal(err)
			}
			var (
				mu      sync.Mutex
				failure string
				reads   int
			)
			stop := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				for {
					select {
					case <-stop:
						return
					default:
					}
					data, err := readForSwapReaderTest(destination, reader.share)
					// Windows refuses a reader that does not share deletion
					// for the instant a rename holds the new file open, as
					// with any atomic replacement (ReplaceFileW included).
					// Such a reader must get the file on a prompt retry.
					for retry := time.Now().Add(200 * time.Millisecond); err != nil &&
						reader.share&windows.FILE_SHARE_DELETE == 0 &&
						errors.Is(err, windows.ERROR_SHARING_VIOLATION) && time.Now().Before(retry); {
						time.Sleep(time.Millisecond)
						data, err = readForSwapReaderTest(destination, reader.share)
					}
					mu.Lock()
					reads++
					if failure == "" && (err != nil || (!bytes.Equal(data, versions[0]) && !bytes.Equal(data, versions[1]))) {
						failure = fmt.Sprintf("read %q, err=%v", data, err)
					}
					mu.Unlock()
					if reader.pause > 0 {
						time.Sleep(reader.pause)
					}
				}
			}()
			swaps := 0
			for deadline := time.Now().Add(4 * time.Second); swaps < 400 && time.Now().Before(deadline); swaps++ {
				source := filepath.Join(dir, fmt.Sprintf("source-%d.tmp", swaps))
				if err := os.WriteFile(source, versions[(swaps+1)%2], 0o600); err != nil {
					t.Fatal(err)
				}
				result, err := CompareAndSwapFile(source, destination,
					SwapExpectation{Exists: true, Data: versions[swaps%2]}, 64, nil)
				if err != nil || !result.Swapped || !result.Replaced {
					close(stop)
					<-done
					t.Fatalf("swap %d: %+v err=%v", swaps, result, err)
				}
				mu.Lock()
				failed := failure != ""
				mu.Unlock()
				if failed {
					break
				}
			}
			close(stop)
			<-done
			if failure != "" {
				t.Fatalf("after %d swaps and %d reads, an agent loading its policy found no policy: %s", swaps, reads, failure)
			}
			if reads == 0 {
				t.Fatal("the reader never ran")
			}
			want := versions[swaps%2]
			if data, err := os.ReadFile(destination); err != nil || !bytes.Equal(data, want) {
				t.Fatalf("final file %q err=%v, want %q", data, err, want)
			}
			requireNoSwapLeftoversForTest(t, dir, "hooks.json")
		})
	}
}

// While a swap compares the file, every agent can still read it, and no
// other process can write, replace, rename or delete it.
func TestCompareAndSwapFileLetsReadersReadWhileItCompares(t *testing.T) {
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
	inspected := false
	result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16,
		func(*os.File) error {
			inspected = true
			for _, reader := range swapReaderShares {
				if data, err := readForSwapReaderTest(destination, reader.share); err != nil || string(data) != "old" {
					t.Errorf("%s during the comparison: %q err=%v", reader.name, data, err)
				}
			}
			if data, err := os.ReadFile(destination); err != nil || string(data) != "old" {
				t.Errorf("os.ReadFile during the comparison: %q err=%v", data, err)
			}
			if writer, err := os.OpenFile(destination, os.O_WRONLY, 0); err == nil {
				_ = writer.Close()
				t.Error("another process opened the file for writing during the comparison")
			}
			if err := os.Rename(other, destination); err == nil {
				t.Error("another process replaced the file during the comparison")
			}
			if err := os.Rename(destination, destination+".moved"); err == nil {
				t.Error("another process renamed the file during the comparison")
			}
			if err := os.Remove(destination); err == nil {
				t.Error("another process deleted the file during the comparison")
			}
			return nil
		})
	if err != nil || !result.Swapped || !inspected {
		t.Fatalf("swap: %+v inspected=%v err=%v", result, inspected, err)
	}
	requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new", "other.tmp": "other"})
}

// A reader that has the file open without sharing deletion makes the swap
// wait with the old file in place; one that stays past the timeout makes it
// fail with the old file still there.
func TestCompareAndSwapFileWaitsForAReaderThatDoesNotShareDeletion(t *testing.T) {
	for _, test := range []struct {
		name    string
		hold    time.Duration
		swapped bool
	}{
		{name: "reader closes", hold: 300 * time.Millisecond, swapped: true},
		{name: "reader stays", hold: swapLockTimeout + time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			reader, err := openForSwapReaderTest(destination, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			if err != nil {
				t.Fatal(err)
			}
			released := make(chan struct{})
			go func() {
				defer close(released)
				time.Sleep(test.hold / 2)
				if data, err := readForSwapReaderTest(destination, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE); err != nil || string(data) != "old" {
					t.Errorf("while the swap waits: %q err=%v", data, err)
				}
				time.Sleep(test.hold / 2)
				_ = reader.Close()
			}()
			source := writeSwapSourceForTest(t, dir, "new")
			result, err := CompareAndSwapFile(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
			<-released
			if test.swapped {
				if err != nil || !result.Swapped {
					t.Fatalf("swap: %+v err=%v", result, err)
				}
				requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "new"})
				return
			}
			if err == nil || result.Swapped {
				t.Fatalf("swap past the timeout: %+v err=%v", result, err)
			}
			requireSwapDirForTest(t, dir, map[string]string{"hooks.json": "old", "source.tmp": "new"})
		})
	}
}

func requireNoSwapLeftoversForTest(t *testing.T, dir string, keep string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != keep {
			t.Fatalf("leftover %s in %s", entry.Name(), dir)
		}
	}
}
