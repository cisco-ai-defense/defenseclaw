// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A folder of the compiler's route that is a junction is a link, as a
// symbolic link is, so it is not trusted. filepath.EvalSymlinks left the
// junction unfollowed, so it read as plain (rel-1-0-10:GAP-2185).
func TestGAP2185TrustedDirectoryRefusesAJunction(t *testing.T) {
	base := gap2185Base(t)
	plainDir := filepath.Join(base, "real")
	if err := os.MkdirAll(plainDir, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "Scripts")
	gap2185Junction(t, junction, plainDir)
	if trustedDirectory(junction, base) {
		t.Error("trustedDirectory(junction) = true; want false")
	}
	if !trustedDirectory(plainDir, base) {
		t.Error("trustedDirectory(plain folder) = false; want true")
	}
}

func gap2185Base(t *testing.T) string {
	t.Helper()
	base, err := winpath.EvalLinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return base
}

func gap2185Junction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
}
