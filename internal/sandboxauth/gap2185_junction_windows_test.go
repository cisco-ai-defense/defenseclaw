// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sandboxauth

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The host filesystem of a sandbox view follows a junction, as it follows a
// symbolic link (rel-1-0-10:GAP-2185).
func TestGAP2185OSFSFollowsAJunction(t *testing.T) {
	base := gap2185Base(t)
	target := filepath.Join(base, "masked")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "mount-junction")
	gap2185Junction(t, junction, target)
	if got, err := (OSFS{}).EvalSymlinks(junction); err != nil || !strings.EqualFold(got, target) {
		t.Errorf("OSFS.EvalSymlinks(junction) = %q, %v; want %q", got, err, target)
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
