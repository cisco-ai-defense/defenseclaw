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
	"strings"
	"sync"
	"sync/atomic"
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
	data, err, _ := readForSwapReaderWithOpenStatusTest(path, share)
	return data, err
}

func readForSwapReaderWithOpenStatusTest(path string, share uint32) ([]byte, error, bool) {
	file, err := openForSwapReaderTest(path, share)
	if err != nil {
		return nil, err, true
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	return data, err, false
}

// Readers without deletion sharing retry transient open errors under the
// documented Windows reader contract. A deletion-sharing reader must observe
// the old or new name on its first open.
func retrySwapReaderReadForTest(read func() ([]byte, error, bool), retrying *atomic.Bool, window time.Duration) ([]byte, error) {
	data, err, openFailed := read()
	deadline := time.Now().Add(window)
	for openFailed && transientSwapReaderOpenForTest(err) && time.Now().Before(deadline) {
		retrying.Store(true)
		time.Sleep(time.Millisecond)
		data, err, openFailed = read()
	}
	retrying.Store(false)
	return data, err
}

func transientSwapReaderOpenForTest(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_SHARING_VIOLATION)
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
// partial file. As docs/WINDOWS-ENTERPRISE-SETUP.md says, "Third-party readers
// should share deletion and retry transient open failures." The readers
// without deletion sharing use that bounded retry; the deletion-sharing
// reader reports any first-open failure immediately.
// DC_TEST_CAS_TRACE_PLAIN=1 records the same reader while the transaction
// fallback is selected, for native diagnosis of the ordinary rename request.
func TestCompareAndSwapFileKeepsAPolicyAtTheNameThroughout(t *testing.T) {
	for _, reader := range swapReaderShares {
		t.Run(reader.name, func(t *testing.T) {
			forcePlainTrace := os.Getenv("DC_TEST_CAS_TRACE_PLAIN") == "1" && reader.share&windows.FILE_SHARE_DELETE != 0
			trace := (os.Getenv("DC_TEST_CAS_TRACE") == "1" || forcePlainTrace) && reader.share&windows.FILE_SHARE_DELETE != 0
			traceOrigin := time.Now()
			var renameActive atomic.Bool
			var renameStart, renameEnd, transactedRenames, plainRenames atomic.Int64
			var renameClass, renameFlags atomic.Uint32
			if trace {
				previous, previousTx := swapRenameReplace, swapTransactedRename
				record := func(transacted bool, rename func() error) error {
					if transacted {
						transactedRenames.Add(1)
					} else {
						plainRenames.Add(1)
					}
					renameStart.Store(time.Since(traceOrigin).Nanoseconds())
					renameActive.Store(true)
					err := rename()
					renameEnd.Store(time.Since(traceOrigin).Nanoseconds())
					renameActive.Store(false)
					return err
				}
				swapRenameReplace = func(from, to string, class, flags uint32) error {
					renameClass.Store(class)
					renameFlags.Store(flags)
					return record(false, func() error { return renameReplace(from, to, class, flags) })
				}
				swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
					if forcePlainTrace {
						return windows.ERROR_NOT_SUPPORTED
					}
					renameClass.Store(windows.FileRenameInfoEx)
					renameFlags.Store(flags)
					return record(true, func() error { return renameTransacted(from, to, flags, tx) })
				}
				defer func() { swapRenameReplace, swapTransactedRename = previous, previousTx }()
			}
			dir := t.TempDir()
			destination := filepath.Join(dir, "hooks.json")
			versions := [][]byte{[]byte(`{"version":1,"policy":"A"}`), []byte(`{"version":1,"policy":"B, longer"}`)}
			if err := os.WriteFile(destination, versions[0], 0o600); err != nil {
				t.Fatal(err)
			}
			var (
				mu       sync.Mutex
				failure  string
				reads    int
				retrying atomic.Bool
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
					// The retry uses the existing two-second swap lock budget:
					// a rename took 354 ms on a loaded Windows CI host.
					// The writer waits before its next swap while this reader
					// is retrying, so a successful read is from this swap.
					window := swapLockTimeout
					if reader.share&windows.FILE_SHARE_DELETE != 0 {
						window = 0
					}
					var openTrace string
					data, err := retrySwapReaderReadForTest(func() ([]byte, error, bool) {
						openedAt := time.Since(traceOrigin).Nanoseconds()
						data, err, openFailed := readForSwapReaderWithOpenStatusTest(destination, reader.share)
						if trace && openFailed && err != nil {
							openTrace = fmt.Sprintf(" open_ns=[%d,%d] rename_ns=[%d,%d] rename_active=%t class=%d flags=%#x transacted=%d plain=%d",
								openedAt, time.Since(traceOrigin).Nanoseconds(), renameStart.Load(), renameEnd.Load(),
								renameActive.Load(), renameClass.Load(), renameFlags.Load(), transactedRenames.Load(), plainRenames.Load())
						}
						return data, err, openFailed
					}, &retrying, window)
					mu.Lock()
					reads++
					if failure == "" && (err != nil || (!bytes.Equal(data, versions[0]) && !bytes.Equal(data, versions[1]))) {
						failure = fmt.Sprintf("read %q, err=%v%s", data, err, openTrace)
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
				result, err := compareAndSwapOwnedForTest(source, destination,
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
				// A policy changes now and then, not back to back: a reader
				// retrying this swap gets in before the next one.
				for wait := time.Now().Add(swapLockTimeout); retrying.Load() && time.Now().Before(wait); {
					time.Sleep(time.Millisecond)
				}
			}
			close(stop)
			<-done
			if failure != "" {
				t.Fatalf("after %d swaps and %d reads, an agent loading its policy found no policy: %s", swaps, reads, failure)
			}
			if trace {
				t.Logf("CAS trace: class=%d flags=%#x transacted_renames=%d plain_renames=%d",
					renameClass.Load(), renameFlags.Load(), transactedRenames.Load(), plainRenames.Load())
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

// Codex requirements may retain an administrator's MZ key. Its rendered TOML
// is data even when those are the first bytes. A deletion-sharing reader must
// still find the old or new requirements on its first open during publication.
func TestCompareAndSwapFileKeepsMZRequirementsAtTheNameThroughout(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "requirements.toml")
	versions := [][]byte{
		[]byte("MZ = 'retained'\nmode = 'old'\n# " + strings.Repeat("a", 128) + "\n"),
		[]byte("MZ = 'retained'\nmode = 'new'\n# " + strings.Repeat("b", 128) + "\n"),
	}
	if err := os.WriteFile(destination, versions[0], 0o600); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	failure := make(chan error, 1)
	var reads atomic.Int64
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := readForSwapReaderTest(destination, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
			reads.Add(1)
			if err != nil || (!bytes.Equal(data, versions[0]) && !bytes.Equal(data, versions[1])) {
				failure <- fmt.Errorf("requirements read %q: %v", data, err)
				return
			}
		}
	}()
	swaps := 0
	for deadline := time.Now().Add(4 * time.Second); swaps < 400 && time.Now().Before(deadline); swaps++ {
		source := filepath.Join(dir, fmt.Sprintf("source-%d.tmp", swaps))
		if err := os.WriteFile(source, versions[(swaps+1)%2], 0o600); err != nil {
			close(stop)
			<-done
			t.Fatal(err)
		}
		result, err := compareAndSwapOwnedForTest(source, destination,
			SwapExpectation{Exists: true, Data: versions[swaps%2]}, len(versions[0]), nil)
		if err != nil || !result.Swapped || !result.Replaced {
			close(stop)
			<-done
			t.Fatalf("requirements swap %d: %+v err=%v", swaps, result, err)
		}
		select {
		case err := <-failure:
			close(stop)
			<-done
			t.Fatalf("requirements reader after %d swaps: %v", swaps+1, err)
		default:
		}
	}
	close(stop)
	<-done
	select {
	case err := <-failure:
		t.Fatalf("requirements reader after %d swaps: %v", swaps, err)
	default:
	}
	if reads.Load() == 0 {
		t.Fatal("the requirements reader never ran")
	}
	if data, err := os.ReadFile(destination); err != nil || !bytes.Equal(data, versions[swaps%2]) {
		t.Fatalf("final requirements %q err=%v", data, err)
	}
	requireNoSwapLeftoversForTest(t, dir, "requirements.toml")
}

func TestCompareAndSwapFileReaderRetriesTransientOpens(t *testing.T) {
	for _, test := range []struct {
		name     string
		failures []error
	}{
		{name: "missing name", failures: []error{windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND}},
		{name: "sharing refusal", failures: []error{windows.ERROR_SHARING_VIOLATION}},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			var retrying atomic.Bool
			data, err := retrySwapReaderReadForTest(func() ([]byte, error, bool) {
				attempts++
				if attempts <= len(test.failures) {
					return nil, test.failures[attempts-1], true
				}
				if !retrying.Load() {
					t.Error("successful retry was not marked as retrying")
				}
				return []byte(`{"version":1,"policy":"A"}`), nil, false
			}, &retrying, swapLockTimeout)
			if err != nil || string(data) != `{"version":1,"policy":"A"}` || attempts != len(test.failures)+1 || retrying.Load() {
				t.Fatalf("read %q, err=%v, attempts=%d, retrying=%t", data, err, attempts, retrying.Load())
			}
		})
	}
}

func TestCompareAndSwapFileReaderKeepsStableAndPermanentResults(t *testing.T) {
	for _, test := range []struct {
		name       string
		data       []byte
		err        error
		openFailed bool
	}{
		{name: "stable policy", data: []byte(`{"version":1,"policy":"A"}`)},
		{name: "permanent open error", err: windows.ERROR_ACCESS_DENIED, openFailed: true},
		{name: "read error", err: windows.ERROR_FILE_NOT_FOUND},
	} {
		t.Run(test.name, func(t *testing.T) {
			attempts := 0
			var retrying atomic.Bool
			data, err := retrySwapReaderReadForTest(func() ([]byte, error, bool) {
				attempts++
				return test.data, test.err, test.openFailed
			}, &retrying, swapLockTimeout)
			if !bytes.Equal(data, test.data) || !errors.Is(err, test.err) || attempts != 1 || retrying.Load() {
				t.Fatalf("read %q, err=%v, attempts=%d, retrying=%t", data, err, attempts, retrying.Load())
			}
		})
	}
}

func TestCompareAndSwapFileReaderReportsMissingAfterRetryWindow(t *testing.T) {
	const window = 3 * time.Millisecond
	var retrying atomic.Bool
	attempts := 0
	data, err := retrySwapReaderReadForTest(func() ([]byte, error, bool) {
		attempts++
		return nil, windows.ERROR_FILE_NOT_FOUND, true
	}, &retrying, window)
	if data != nil || !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || attempts < 2 || retrying.Load() {
		t.Fatalf("read %q, err=%v, attempts=%d, retrying=%t", data, err, attempts, retrying.Load())
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
	result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16,
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
			result, err := compareAndSwapOwnedForTest(source, destination, SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil)
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
