// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hermesskills

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A Hermes skills root that is a junction is linked: the service scan of a
// profile refuses it, as it refuses a symbolic link. filepath.EvalSymlinks
// left the junction unfollowed, so it read as plain (rel-1-0-10:GAP-2185).
func TestGAP2185HermesSkillsRootThroughAJunctionIsRefused(t *testing.T) {
	base := gap2185Base(t)
	outside := filepath.Join(base, "outside", "skills")
	plain := filepath.Join(base, "plain", "AppData", "Local", "hermes", "skills")
	for _, dir := range []string{outside, plain} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	junction := filepath.Join(base, "user", "AppData", "Local", "hermes", "skills")
	if err := os.MkdirAll(filepath.Dir(junction), 0o700); err != nil {
		t.Fatal(err)
	}
	gap2185Junction(t, junction, outside)
	if canonicalPath(junction) {
		t.Error("canonicalPath(junction root) = true; want false")
	}
	if _, err := DiscoverProfileRoot(junction, DefaultDirectoryLimit); err == nil {
		t.Error("DiscoverProfileRoot(junction root) = nil error; want a linked-root refusal")
	}
	if !canonicalPath(plain) {
		t.Error("canonicalPath(plain root) = false; want true")
	}
	if _, err := DiscoverProfileRoot(plain, DefaultDirectoryLimit); err != nil {
		t.Errorf("DiscoverProfileRoot(plain root) = %v; want nil", err)
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
