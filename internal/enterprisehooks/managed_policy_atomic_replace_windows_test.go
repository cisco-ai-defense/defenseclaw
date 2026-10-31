// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/safefile/sharedfiletest"
)

// The managed policy writer replaces a file in one rename: a reader that
// opens it meanwhile (Cursor loading the adapter its hooks.json names) finds
// the old bytes or the new ones, never no file. ReplaceFileW moved the old
// file aside while it merged metadata, so a watcher saw hooks.json name a
// missing adapter (GAP-2572, TestWindowsCursorSharedWriterKeepsConcurrent
// AdministratorChanges/publication as LocalSystem). It was still the fallback
// where Windows refuses the POSIX-semantics rename, as on the CI runner of
// GAP-2644 (4476 missing reads in 78998).
func TestWindowsManagedPolicyWriterNeverLeavesTheFileMissing(t *testing.T) {
	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("posix rename refused=%v", refused), func(t *testing.T) {
			if refused {
				t.Cleanup(safefile.RefusePOSIXRenameForTest())
			}
			requireManagedPolicyWriterKeepsTheFile(t)
		})
	}
}

func requireManagedPolicyWriterKeepsTheFile(t *testing.T) {
	paths := withWindowsCursorStandaloneSeamsForTest(t)
	path := paths.Adapter
	if err := writeWindowsManagedFile(path, []byte("version 0\r\n"), true); err != nil {
		t.Fatal(err)
	}
	var reads, missing atomic.Int64
	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 2 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, exists, err := sharedfiletest.ReadShared(path); err == nil {
					reads.Add(1)
					if !exists {
						missing.Add(1)
					}
				}
			}
		}()
	}
	const writes = 400
	var writeErr error
	for i := 1; i <= writes && writeErr == nil; i++ {
		writeErr = writeWindowsManagedFile(path, []byte(fmt.Sprintf("version %d\r\n", i)), true)
	}
	close(stop)
	readers.Wait()
	if writeErr != nil {
		t.Fatal(writeErr)
	}
	if missing.Load() != 0 {
		t.Fatalf("a reader found %s missing %d times in %d reads while it was replaced %d times", path, missing.Load(), reads.Load(), writes)
	}
	if reads.Load() == 0 {
		t.Fatal("fixture: the readers never read the file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("version %d\r\n", writes); string(data) != want {
		t.Fatalf("file = %q, want %q", data, want)
	}
}
