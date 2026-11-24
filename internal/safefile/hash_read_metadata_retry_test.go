// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openHashRetryFile writes body and opens it as the skill walk does. The
// hook sleeps past the coarse Linux timestamp tick so a metadata change moves
// the change time.
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

// GAP-2002: a metadata-only change during a skill file read is read again on
// the same handle, as rel's path reader did on macOS, instead of failing.
// moveChangeTimeOnly is per OS (GAP-2033): a chmod on POSIX, the change time
// itself on Windows, where os.Chmod moves no metadata the read checks.
func TestGAP2002HashOpenedRetriesMetadataOnlyChange(t *testing.T) {
	const body = "---\nname: s\n---\nbody\n"
	calls := 0
	file := openHashRetryFile(t, body, func(path string, call int) {
		calls = call
		if call == 1 {
			moveChangeTimeOnly(t, path, call)
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
		moveChangeTimeOnly(t, path, call)
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

// GAP-2033: under the platform's own rule only macOS reads a metadata-only
// change again. Linux and Windows fail that read at once (fail closed).
func TestGAP2033HashOpenedMetadataOnlyChangeFollowsPlatformRule(t *testing.T) {
	const body = "body\n"
	calls := 0
	file := openHashRetryFile(t, body, func(path string, call int) {
		calls = call
		if call == 1 {
			moveChangeTimeOnly(t, path, call)
		}
	})
	retryMetadataChange = readStabilityRetriesMetadataChange
	digest, captured, _, err := HashOpenedRegularFileBoundedCapture(file, 1024, 1024)
	if readStabilityRetriesMetadataChange {
		if err != nil || digest != sha256.Sum256([]byte(body)) || calls != 2 {
			t.Fatalf("hash = %x, %v after %d reads; want the content after one retry", digest, err, calls)
		}
		return
	}
	if err == nil || captured != nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("hash after a metadata-only change = %q, %v; want a changed-while-reading failure", captured, err)
	}
	if calls != 1 {
		t.Fatalf("reads = %d, want 1 (no retry on this platform)", calls)
	}
}

// GAP-2034: a read that gave up under churn leaves nothing behind. Once the
// file stops changing, the next read (the next scan opens the file again)
// succeeds on its first attempt.
func TestGAP2034HashOpenedReadsOkOnceTheChurnStops(t *testing.T) {
	const body = "body\n"
	churn, calls := true, 0
	file := openHashRetryFile(t, body, func(path string, call int) {
		calls++
		if churn {
			moveChangeTimeOnly(t, path, call)
		}
	})
	if _, _, _, err := HashOpenedRegularFileBoundedCapture(file, 1024, 1024); err == nil {
		t.Fatal("hash under churn succeeded; want a failure")
	}
	churn, calls = false, 0
	again, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = again.Close() }()
	digest, captured, _, err := HashOpenedRegularFileBoundedCapture(again, 1024, 1024)
	if err != nil || digest != sha256.Sum256([]byte(body)) || string(captured) != body || calls != 1 {
		t.Fatalf("hash once quiet = %x %q, %v after %d reads; want the content on the first read", digest, captured, err, calls)
	}
}
