// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package skillrootsafe

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// A skill root that is a junction is a linked root, as a symbolic link is:
// Windows refuses every linked root, since the GAP-0905 route check cannot
// run there. filepath.EvalSymlinks left the junction unfollowed, so the root
// read as plain and was admitted (rel-1-0-10:GAP-2185).
func TestGAP2185ResolveRefusesAJunctionSkillRoot(t *testing.T) {
	base := gap2185Base(t)
	outside := filepath.Join(base, "outside", "skills")
	plain := filepath.Join(base, "plain", "skills")
	for _, dir := range []string{outside, plain} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	junction := filepath.Join(base, "home", "skills")
	if err := os.MkdirAll(filepath.Dir(junction), 0o700); err != nil {
		t.Fatal(err)
	}
	gap2185Junction(t, junction, outside)
	if got, err := Resolve(junction, nil); err == nil {
		t.Errorf("Resolve(junction root) = %q, nil; want a linked-root refusal", got)
	}
	if got, _, err := ResolveWithWarnings(junction, nil); err == nil {
		t.Errorf("ResolveWithWarnings(junction root) = %q, nil; want a linked-root refusal", got)
	}
	if got, err := Resolve(plain, nil); err != nil || got != plain {
		t.Errorf("Resolve(plain root) = %q, %v; want %q", got, err, plain)
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
