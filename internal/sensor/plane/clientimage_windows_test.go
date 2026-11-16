// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package plane

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// R108-COWORK-3: the Security log names no image identity, so the Windows
// reader reads the file at the exec path only if it was not written or
// changed after the exec, keys its cached digest by the file's USN, and fails
// closed on an image with no release version resource.
func TestWindowsClientImageIsBoundToTheExecTime(t *testing.T) {
	image := filepath.Join(t.TempDir(), "claude.exe")
	if err := os.WriteFile(image, []byte("client image fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	written := time.Now()
	file, key, ok := openImageUnchangedSince(image, written.Add(time.Minute))
	if !ok || key.size != int64(len("client image fixture")) || key.changed <= 0 {
		t.Fatalf("image written before the exec: ok=%t key=%+v", ok, key)
	}
	file.Close()
	if err := os.WriteFile(image, []byte("client image fixture2"), 0o700); err != nil {
		t.Fatal(err)
	}
	file, rewritten, ok := openImageUnchangedSince(image, time.Now().Add(time.Minute))
	if !ok || rewritten.changed == key.changed {
		t.Fatalf("a rewritten file kept its cache key: ok=%t key=%+v", ok, rewritten)
	}
	file.Close()
	if file, _, ok := openImageUnchangedSince(image, written.Add(-time.Hour)); ok {
		file.Close()
		t.Fatal("image written after the exec was read as the image that ran")
	}
	if sum, version := windowsClientImage(image, written.Add(time.Minute), ""); sum != "" || version != "" {
		t.Fatalf("image without a release version = %q %q", sum, version)
	}
}
