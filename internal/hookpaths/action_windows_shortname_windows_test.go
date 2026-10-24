// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestR104ActionWindowsExistingShortTarget(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(target, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetShortPathName(name, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Skipf("8.3 aliases unavailable on this volume: %v", err)
	}
	short := windows.UTF16ToString(buf[:n])
	if !strings.Contains(short, "~") {
		t.Skip("8.3 aliases disabled on this volume")
	}
	if got := ActionCommandDecision("cp report.pub "+short, cwd, home); got != "protected-target" {
		t.Fatalf("short target %q decision = %q", short, got)
	}
	throughMissing := filepath.Dir(short) + `\missing\..\` + filepath.Base(short)
	if got := ActionCommandDecision("cp report.pub "+throughMissing, cwd, home); got != "protected-target" {
		t.Fatalf("short target with dot-dot %q decision = %q", throughMissing, got)
	}
}
