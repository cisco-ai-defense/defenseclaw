// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-2211: the drive letter respelling names the same file as
// the final path, always. With the drive subst to a folder named with a
// Kelvin sign (U+212A) and a junction on the drive to the k-spelled folder
// beside it, the final path is not below what the drive maps to: NTFS tells
// the two names apart, strings.EqualFold does not. Before the fix EvalLinks
// gave the drive spelling of a place that is not the final one (R:\ for the
// junction, the Kelvin folder itself).
func TestGAP2211DriveRespellingNamesTheFinalFile(t *testing.T) {
	base := t.TempDir()
	kelvin := filepath.Join(base, "\u212Adir")
	plain := filepath.Join(base, "kdir")
	for _, d := range []string{kelvin, plain} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if sameFileAs(t, kelvin, plain) {
		t.Skip("this volume does not tell the Kelvin sign from k")
	}
	for _, f := range []string{filepath.Join(kelvin, "f"), filepath.Join(plain, "f")} {
		if err := os.WriteFile(f, []byte(f), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", filepath.Join(kelvin, "j"), plain).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	letter := freeDriveLetter(t)
	if out, err := exec.Command("subst.exe", letter, kelvin).CombinedOutput(); err != nil {
		t.Fatalf("subst %s %s: %v: %s", letter, kelvin, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("subst.exe", letter, "/d").Run() })
	// The junction itself: its final path is the k-spelled folder, which
	// SameWindowsPath took for what the drive maps to, so EvalLinks gave
	// the drive root, the Kelvin folder.
	if got, err := EvalLinks(letter + `\j`); err != nil || !sameFileAs(t, got, plain) {
		t.Errorf("EvalLinks(%s\\j) = %q, %v, which is not the folder the junction leads to", letter, got, err)
	}
	got, err := EvalLinks(letter + `\j\f`)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFileAs(t, got, filepath.Join(plain, "f")) {
		t.Errorf("EvalLinks(%s\\j\\f) = %q, which is not the file the junction leads to", letter, got)
	}
	if final, err := FinalPath(letter + `\j\f`); err != nil || !sameFileAs(t, final, filepath.Join(plain, "f")) {
		t.Errorf("FinalPath(%s\\j\\f) = %q, %v", letter, final, err)
	}
	// The plain respelling stays: a file below what the drive maps to keeps
	// the drive letter.
	if got, err := EvalLinks(letter + `\f`); err != nil || !SameWindowsPath(got, letter+`\f`) {
		t.Errorf("EvalLinks(%s\\f) = %q, %v; want the drive spelling", letter, got, err)
	}
}
