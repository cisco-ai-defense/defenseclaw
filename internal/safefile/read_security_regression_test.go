// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReadRegularFileBoundedRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := ReadRegularFileBounded(link, 1024); err == nil {
		t.Fatal("ReadRegularFileBounded accepted a symlink")
	}
}

func TestReadRegularFileBoundedRejectsOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversize")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 1025)), 0o600); err != nil {
		t.Fatalf("write oversize fixture: %v", err)
	}

	if _, err := ReadRegularFileBounded(path, 1024); err == nil {
		t.Fatal("ReadRegularFileBounded accepted an oversized file")
	}
}

func TestReadRegularFileBoundedRejectsSameObjectOverwrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows denies retained writers with a native share-mode lease")
	}
	path := filepath.Join(t.TempDir(), "mutable")
	original := []byte(strings.Repeat("a", 128*1024))
	replacement := []byte(strings.Repeat("b", len(original)))
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatalf("write mutable fixture: %v", err)
	}

	_, err := readRegularFileBounded(path, int64(len(original)), func() {
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if openErr != nil {
			t.Fatalf("open same object for mutation: %v", openErr)
		}
		if _, writeErr := file.Write(replacement); writeErr != nil {
			_ = file.Close()
			t.Fatalf("overwrite same object: %v", writeErr)
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			t.Fatalf("sync same-object overwrite: %v", syncErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			t.Fatalf("close same-object overwrite: %v", closeErr)
		}
	})
	if err == nil || !strings.Contains(err.Error(), "changed while reading") {
		t.Fatalf("ReadRegularFileBounded same-object overwrite error = %v", err)
	}
}
