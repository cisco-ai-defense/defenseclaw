// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The removal reader of the registration set reads an operand through the
// same link-aware walk as the find reader, and a wrapped removal in the
// folder its wrapper names, as a cd there would place it.
//
// rel-1-0-10:GAP-2285: with HOME reached through a directory link, the
// registered hook folder is spelled through the link while the operand is
// compared resolved, so a recursive removal of the folder (by ~, by the
// physical path, or by a relative step) reached nothing while a find of the
// same folder did. rel-1-0-10:GAP-2286: the reader read only a call whose
// own program is the removal, so the removal a wrapper runs (sudo -D DIR,
// env -C DIR, chroot DIR, plain sudo or nice) reached nothing.
func TestGAP2285GAP2286RemovalReachesTheRegisteredFolder(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	for _, name := range []string{".claude/settings.json", "proj/build/out.o"} {
		path := filepath.Join(real, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	linked := filepath.Join(root, "linked")
	if err := os.Symlink(real, linked); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for _, home := range []string{real, linked} {
		folder := filepath.Join(home, ".claude")
		names := []string{folder, filepath.Join(folder, "settings.json")}
		proj := filepath.Join(home, "proj")
		reach := map[string]string{
			"tilde":        "rm -rf ~/.claude",
			"physical":     "rm -rf " + real + "/.claude",
			"spelled":      "rm -rf " + home + "/.claude",
			"relative":     "rm -rf ../.claude",
			"cd":           "cd ~ && rm -rf .claude",
			"sudo-chdir":   "sudo -D " + home + " rm -rf .claude",
			"sudo-chdir=":  "sudo --chdir=" + home + " rm -rf .claude",
			"env-chdir":    "env -C " + home + " rm -rf .claude",
			"env-relative": "env -C .. rm -rf .claude",
			"sudo":         "sudo rm -rf ~/.claude",
			"nice":         "nice rm -rf ~/.claude",
			"sudo-user":    "sudo -u nobody -D " + home + " rm -rf .claude",
			"chroot":       "chroot " + home + " rm -rf .claude",
			"sudo-chroot":  "sudo chroot " + home + " rm -rf .claude",
		}
		for id, command := range reach {
			if got := RegistrationWriteReached(command, proj, home, names); !slices.Contains(got, folder) {
				t.Errorf("%s home %s: reached %d names, want the hook folder", filepath.Base(home), id, len(got))
			}
		}
		benign := map[string]string{
			"build":         "rm -rf build",
			"proj-build":    "rm -rf ~/proj/build",
			"wrapped-build": "sudo -D " + home + " rm -rf proj/build",
			"env-other":     "env -C /tmp rm -rf .claude",
			"sudo-other":    "sudo -D /tmp rm -rf .claude",
			"env-cache":     "env -C " + home + " rm -rf .cache",
			"chroot-other":  "chroot /tmp rm -rf .claude",
			"chroot-rooted": "chroot /tmp rm -rf ~/.claude",
			"wrapped-echo":  "sudo -D " + home + " echo .claude",
		}
		for id, command := range benign {
			if got := RegistrationWriteReached(command, proj, home, names); len(got) != 0 {
				t.Errorf("%s home benign %s: reached %d names, want none", filepath.Base(home), id, len(got))
			}
		}
	}
}
