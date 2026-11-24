// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2009: RegularChildSize reads, through the held parent, the size of a
// file a writer holds open (the walk's read open, which denies write
// sharing, fails on it), and reports a folder as not regular.
func TestGAP2009RegularChildSizeOfAWriterHeldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.bin")
	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	parent, err := OpenDirectoryNoFollow(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if file, err := OpenRegularChildNoFollow(parent, "data.bin"); err == nil {
		_ = file.Close()
		t.Fatal("the read open succeeded while a writer holds the file")
	}
	if size, regular, err := RegularChildSize(parent, "data.bin"); err != nil || !regular || size != 4096 {
		t.Fatalf("writer-held file: size %d regular %t err %v; want 4096 regular", size, regular, err)
	}
	if _, regular, err := RegularChildSize(parent, "sub"); err != nil || regular {
		t.Fatalf("folder: regular %t err %v; want not regular", regular, err)
	}
}
