// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func unpackedTestRuntime(t *testing.T, count int) (string, *bytes.Reader, []string) {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	var names []string
	for i := range count {
		name := fmt.Sprintf("python/Lib/m%02d.py", i)
		names = append(names, name)
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte(strings.Repeat("x", 64) + name))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := unpack(buf.Bytes(), dir); err != nil {
		t.Fatal(err)
	}
	return dir, bytes.NewReader(buf.Bytes()), names
}

// rel-1-0-4 GAP-2607: a no-op Setup /ensure spent most of its time in
// prepare, which hashed every unpacked runtime file one at a time. The
// files are hashed by several workers, and every file is still compared.
func TestVerifyRuntimeHashesTheFilesInParallel(t *testing.T) {
	dir, archive, names := unpackedTestRuntime(t, 12)
	previousWorkers, previousHash := verifyRuntimeWorkers, fileSHA256
	t.Cleanup(func() { verifyRuntimeWorkers, fileSHA256 = previousWorkers, previousHash })
	verifyRuntimeWorkers = func() int { return 4 }
	var inFlight, peak atomic.Int64
	var mu sync.Mutex
	hashed := map[string]bool{}
	fileSHA256 = func(path string) ([sha256.Size]byte, error) {
		now := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			seen := peak.Load()
			if now <= seen || peak.CompareAndSwap(seen, now) {
				break
			}
		}
		// Hold the file until a second worker is hashing too (bounded, so
		// a serial implementation fails instead of hanging).
		deadline := time.Now().Add(2 * time.Second)
		for peak.Load() < 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		mu.Lock()
		hashed[path] = true
		mu.Unlock()
		return previousHash(path)
	}
	if err := verifyRuntime(dir, archive, archive.Size(), true, nil); err != nil {
		t.Fatalf("verify an untouched tree: %v", err)
	}
	if peak.Load() < 2 {
		t.Fatalf("the runtime files were hashed one at a time (peak %d workers)", peak.Load())
	}
	if len(hashed) != len(names) {
		t.Fatalf("hashed %d of %d files", len(hashed), len(names))
	}
}

// The error still names the first changed file in archive order, whichever
// worker finds a change first.
func TestVerifyRuntimeNamesTheFirstChangedFileInArchiveOrder(t *testing.T) {
	dir, archive, names := unpackedTestRuntime(t, 24)
	previousWorkers := verifyRuntimeWorkers
	t.Cleanup(func() { verifyRuntimeWorkers = previousWorkers })
	verifyRuntimeWorkers = func() int { return 8 }
	for _, index := range []int{5, 19} {
		path := filepath.Join(dir, filepath.FromSlash(names[index]))
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		body[0] = byte(0x79) // same size, other bytes
		if err := os.WriteFile(path, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for range 50 {
		err := verifyRuntime(dir, archive, archive.Size(), true, nil)
		if err == nil || !strings.Contains(err.Error(), names[5]) {
			t.Fatalf("want the error for %s, got %v", names[5], err)
		}
	}
	// The size-only check (status, verify) is unchanged: it hashes nothing.
	if err := verifyRuntime(dir, archive, archive.Size(), false, nil); err != nil {
		t.Fatalf("the size-only check failed on same-size files: %v", err)
	}
}

// GAP-0044: prepare compares each unpacked file with the entry digest the
// build embedded instead of inflating the entry; an entry the list does not
// name is still inflated and hashed.
func TestVerifyRuntimeUsesTheEmbeddedEntryDigests(t *testing.T) {
	dir, archive, names := unpackedTestRuntime(t, 6)
	digests := map[string][sha256.Size]byte{}
	for _, name := range names[1:] {
		body, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		digests[name] = sha256.Sum256(body)
	}
	if err := verifyRuntime(dir, archive, archive.Size(), true, digests); err != nil {
		t.Fatalf("verify with the embedded digests: %v", err)
	}
	// The listed digest is what is compared: one that names other bytes
	// fails an untouched file the archive itself would pass.
	digests[names[3]] = sha256.Sum256([]byte("other bytes"))
	if err := verifyRuntime(dir, archive, archive.Size(), true, digests); err == nil || !strings.Contains(err.Error(), names[3]) {
		t.Fatalf("a listed digest of other bytes passed: %v", err)
	}
	delete(digests, names[3])
	path := filepath.Join(dir, filepath.FromSlash(names[0]))
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body[0] = byte(0x79)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntime(dir, archive, archive.Size(), true, digests); err == nil || !strings.Contains(err.Error(), names[0]) {
		t.Fatalf("a changed file the list does not name passed: %v", err)
	}
}
