// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package plane

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// R108-COWORK-3: the macOS source hashes the exec target bound to the stat
// Endpoint Security took at exec time; a file changed after the exec is not
// read as the image that ran.
func TestDarwinClientImageIsBoundToTheExecTimeStat(t *testing.T) {
	image := filepath.Join(t.TempDir(), ".local/share/claude/versions/2.1.317")
	if err := os.MkdirAll(filepath.Dir(image), 0o700); err != nil {
		t.Fatal(err)
	}
	data := []byte("release image fixture")
	if err := os.WriteFile(image, data, 0o700); err != nil {
		t.Fatal(err)
	}
	target := esFile{Path: image}
	info, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	target.Stat.Dev, target.Stat.Ino, target.Stat.Size = int64(stat.Dev), stat.Ino, stat.Size
	target.Stat.Changed = time.Unix(0, stat.Ctimespec.Nano()).UTC().Format(time.RFC3339Nano)
	want := sha256.Sum256(data)
	previous := clientImages
	clientImages = newImageHasher()
	t.Cleanup(func() { clientImages = previous })
	if sum, version := darwinClientImage(target, ""); sum != "" || version != "2.1.317" {
		t.Fatalf("first exec image = %q %q, want the version and no digest yet", sum, version)
	}
	clientImages.idle()
	if sum, version := darwinClientImage(target, ""); sum != hex.EncodeToString(want[:]) || version != "2.1.317" {
		t.Fatalf("exec-time image = %q %q", sum, version)
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(image, []byte("another image fixtur"), 0o700); err != nil {
		t.Fatal(err)
	}
	if sum, _ := darwinClientImage(target, ""); sum != "" {
		t.Fatal("a file changed after the exec was read as its image")
	}
}
