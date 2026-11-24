// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// GAP-2008: a link on the way to a folder that leads to a share is refused
// before anything opens the share, so a scan never makes a connection the
// scanned account chose; a link to a local folder still resolves.
func TestGAP2008ResolvedLinkToAShareIsRefusedUnopened(t *testing.T) {
	base := t.TempDir()
	trustAll := func(*os.File, string) bool { return true }
	share := filepath.Join(base, "share")
	if err := os.Symlink(`\\127.0.0.1\c$\Windows`, share); err != nil {
		t.Skipf("symbolic link (needs the privilege or developer mode): %v", err)
	}
	dir, _, err := OpenDirectoryResolved(filepath.Join(share, "System32"), trustAll)
	if dir != nil {
		_ = dir.Close()
	}
	if !errors.Is(err, winpath.ErrPathNotLocal) {
		t.Fatalf("through a link to a share: %v; want ErrPathNotLocal", err)
	}
	real := filepath.Join(base, "real", "sub")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "real"), filepath.Join(base, "local")); err != nil {
		t.Fatal(err)
	}
	dir, resolved, err := OpenDirectoryResolved(filepath.Join(base, "local", "sub"), trustAll)
	if err != nil {
		t.Fatalf("through a link to a local folder: %v", err)
	}
	defer dir.Close()
	want, err := os.Stat(real)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(resolved)
	if err != nil || !os.SameFile(want, got) {
		t.Fatalf("resolved %s (%v); want %s", resolved, err, real)
	}
}
