// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// A transaction-name conflict must leave the owned-file reader's first-open
// contract intact through the next publication attempt.
func TestCompareAndSwapFileOwnedConflictKeepsConcurrentFirstOpens(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "requirements.toml")
	old := []byte("MZ = 'retained'\nmode = 'old'\n")
	newData := []byte("MZ = 'retained'\nmode = 'new'\n")
	if err := os.WriteFile(destination, old, 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, string(newData))
	previousTx, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()

	stop := make(chan struct{})
	done := make(chan struct{})
	firstRead := make(chan struct{})
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
			data, err := readForSwapReaderTest(destination,
				windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
			if reads.Add(1) == 1 {
				close(firstRead)
			}
			if err != nil || (!bytes.Equal(data, old) && !bytes.Equal(data, newData)) {
				failure <- fmt.Errorf("first-open read %q: %v", data, err)
				return
			}
		}
	}()
	<-firstRead

	transacted, plain := 0, 0
	var readsDuringTransaction int64
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted++
		if transacted == 1 {
			return windows.ERROR_TRANSACTIONAL_CONFLICT
		}
		before := reads.Load()
		err := renameTransacted(from, to, flags, tx)
		deadline := time.Now().Add(250 * time.Millisecond)
		for reads.Load() == before && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		readsDuringTransaction = reads.Load() - before
		return err
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		return renameReplace(from, to, class, flags)
	}
	result, err := compareAndSwapOwnedForTest(source, destination,
		SwapExpectation{Exists: true, Data: old}, len(newData), nil)
	close(stop)
	<-done
	select {
	case readErr := <-failure:
		t.Fatalf("owned reader after %d opens: %v", reads.Load(), readErr)
	default:
	}
	if err != nil || !result.Swapped || transacted != 2 || plain != 0 || readsDuringTransaction == 0 {
		t.Fatalf("owned publication: result=%+v err=%v transactions=%d plain=%d reads_during_transaction=%d",
			result, err, transacted, plain, readsDuringTransaction)
	}
	if data, err := os.ReadFile(destination); err != nil || !bytes.Equal(data, newData) {
		t.Fatalf("owned file = %q, err=%v", data, err)
	}
}

// A plain external save stays active while a shared-file CAS publishes. The
// editor may see ordinary sharing refusals, but never a transaction conflict.
func TestCompareAndSwapFileSharedClassKeepsOverlappingExternalSave(t *testing.T) {
	dir := t.TempDir()
	destination := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := writeSwapSourceForTest(t, dir, "product")
	previousTx, previousPlain := swapTransactedRename, swapRenameReplace
	defer func() { swapTransactedRename, swapRenameReplace = previousTx, previousPlain }()
	firstAttempt := make(chan error, 1)
	writerDone := make(chan error, 1)
	var publishing atomic.Bool
	var attemptsDuringPublication atomic.Int64
	transacted, plain := 0, 0
	swapTransactedRename = func(from, to string, flags uint32, tx windows.Handle) error {
		transacted++
		return renameTransacted(from, to, flags, tx)
	}
	swapRenameReplace = func(from, to string, class, flags uint32) error {
		plain++
		go func() {
			deadline := time.Now().Add(swapLockTimeout)
			for attempt := 0; ; attempt++ {
				if publishing.Load() {
					attemptsDuringPublication.Add(1)
				}
				err := os.WriteFile(destination, []byte("administrator"), 0o600)
				if attempt == 0 {
					firstAttempt <- err
				}
				if err == nil || !ordinarySwapWriterBusy(err) || !time.Now().Before(deadline) {
					writerDone <- err
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
		firstErr := <-firstAttempt
		if firstErr == nil || !ordinarySwapWriterBusy(firstErr) {
			return fmt.Errorf("external save before publication: %v", firstErr)
		}
		publishing.Store(true)
		deadline := time.Now().Add(250 * time.Millisecond)
		for attemptsDuringPublication.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		err := renameReplace(from, to, class, flags)
		publishing.Store(false)
		return err
	}
	result, err := CompareAndSwapFile(source, destination,
		SwapExpectation{Exists: true, Data: []byte("old")}, 16, nil, PublishSharedWithExternalWriters)
	if err != nil || !result.Swapped || transacted != 0 || plain != 1 || attemptsDuringPublication.Load() == 0 {
		t.Fatalf("shared publication: result=%+v err=%v transactions=%d plain=%d overlapping_attempts=%d",
			result, err, transacted, plain, attemptsDuringPublication.Load())
	}
	select {
	case writeErr := <-writerDone:
		if writeErr != nil {
			var errno syscall.Errno
			if errors.As(writeErr, &errno) {
				t.Fatalf("external save: Win32 error %d: %v", errno, writeErr)
			}
			t.Fatalf("external save: %v", writeErr)
		}
	case <-time.After(swapLockTimeout):
		t.Fatal("external save did not finish")
	}
	if data, err := os.ReadFile(destination); err != nil || string(data) != "administrator" {
		t.Fatalf("external save = %q, err=%v", data, err)
	}
}

func ordinarySwapWriterBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
