//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package posixacl

import (
	"os"
	"path/filepath"
	"testing"
)

// The ACL of a privileged check comes from the kernel, never from a
// getfacl found through the caller's PATH (p0 GAP-1382).
func TestReadIgnoresAGetfaclOnPath(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ran")
	script := "#!/bin/sh\n: > '" + marker + "'\nprintf 'user::rwx\\nuser:4242:rwx\\ngroup::rwx\\nmask::rwx\\nother::rwx\\n'\n"
	if err := os.WriteFile(filepath.Join(bin, "getfacl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	file := filepath.Join(t.TempDir(), "policy")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	view, err := System.Read(file, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("Read started the getfacl found on PATH")
	}
	if found, _ := view.NamedUserAllows(4242, 0o4); found || view.Allows(0, 0, 0o600, 4242, 4242, 0o4) {
		t.Fatalf("Read returned the PATH helper's ACL: %+v", view)
	}
}

// The xattr parser reads the kernel's entry layout.
func TestParseXattrReadsNamedEntries(t *testing.T) {
	data := []byte{2, 0, 0, 0}
	for _, e := range [][3]uint32{{0x01, 6, 0xffffffff}, {0x02, 4, 1001}, {0x04, 4, 0xffffffff}, {0x10, 4, 0xffffffff}, {0x20, 0, 0xffffffff}} {
		data = append(data, byte(e[0]), byte(e[0]>>8), byte(e[1]), byte(e[1]>>8), byte(e[2]), byte(e[2]>>8), byte(e[2]>>16), byte(e[2]>>24))
	}
	view, err := parseXattr(data)
	if err != nil {
		t.Fatal(err)
	}
	if found, allowed := view.NamedUserAllows(1001, 0o4); !found || !allowed || view.Other != 0 || view.Mask != 4 {
		t.Fatalf("parsed %+v", view)
	}
	if _, err := parseXattr(data[:7]); err == nil {
		t.Fatal("a truncated ACL parsed")
	}
}
