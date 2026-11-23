// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openHashRetryFile writes body and opens it as the skill walk does. The
// hook sleeps past the coarse Linux timestamp tick so a chmod moves ctime.
func openHashRetryFile(t *testing.T, body string, hook func(path string, call int)) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "SKILL.md")
	if err := os.WriteFile(path, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	retry, after := retryMetadataChange, hashOpenedAfterRead
	t.Cleanup(func() { retryMetadataChange, hashOpenedAfterRead = retry, after })
	retryMetadataChange = true // the macOS behaviour, on every platform
	calls := 0
	hashOpenedAfterRead = func(*os.File) {
		calls++
		time.Sleep(25 * time.Millisecond)
		hook(path, calls)
	}
	return file
}

func chmodOrFail(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// GAP-2002: a metadata-only change during a skill file read is read again on
// the same handle, as rel's path reader did on macOS, instead of failing.
func TestGAP2002HashOpenedRetriesMetadataOnlyChange(t *testing.T) {
	const body = "---\nname: s\n---\nbody\n"
	calls := 0
	file := openHashRetryFile(t, body, func(path string, call int) {
		calls = call
		if call == 1 {
			chmodOrFail(t, path, 0o600)
		}
	})
	digest, captured, consumed, err := HashOpenedRegularFileBoundedCapture(file, 1024, 1024)
	if err != nil || digest != sha256.Sum256([]byte(body)) || string(captured) != body || consumed != int64(len(body)) {
		t.Fatalf("hash = %x %q %d, %v; want the content after one retry", digest, captured, consumed, err)
	}
	if calls != 2 {
		t.Fatalf("reads = %d, want 2", calls)
	}
}

func TestGAP2002HashOpenedGivesUpOnMetadataChurn(t *testing.T) {
	calls := 0
	file := openHashRetryFile(t, "body\n", func(path string, call int) {
		calls = call
		chmodOrFail(t, path, os.FileMode(0o600|call%2<<5))
	})
	if _, captured, _, err := HashOpenedRegularFileBoundedCapture(file, 1024, 1024); err == nil || captured != nil {
		t.Fatalf("hash under churn = %q, %v; want a failure", captured, err)
	}
	if calls != readStabilityMetadataRetries {
		t.Fatalf("reads = %d, want %d", calls, readStabilityMetadataRetries)
	}
}

func TestGAP2002HashOpenedContentChangeFailsAtOnce(t *testing.T) {
	calls := 0
	file := openHashRetryFile(t, "body\n", func(path string, call int) {
		calls = call
		if err := os.WriteFile(path, []byte("longer body\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	})
	if _, captured, _, err := HashOpenedRegularFileBoundedCapture(file, 1024, 1024); err == nil || captured != nil {
		t.Fatalf("hash after a content change = %q, %v; want a failure", captured, err)
	}
	if calls != 1 {
		t.Fatalf("reads = %d, want 1 (no retry for a content change)", calls)
	}
}
