// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrationWriteReachDestinationRoles pins that an install destination
// that is a folder is reached only through the file name each source takes in
// it, that a perl option word is read option by option (a letter inside a
// module name or after -i is not an in-place edit), and that a loop body
// writes the registered file through every mutation the straight-line
// reader knows.
func TestRegistrationWriteReachDestinationRoles(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	source := filepath.Join(root, "src", "other-tool")
	for _, path := range []string{hook, source, filepath.Join(bin, "other-tool")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{hook, bin}
	owned := filepath.Join(root, "src", "defenseclaw-hook-user")
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"install into the bin folder with a slash", "install -m755 " + source + " " + bin + "/", false},
		{"install into the bin folder", "install -m755 " + source + " " + bin, false},
		{"install with a target folder", "install -m755 -t " + bin + " " + source, false},
		{"copy into the bin folder", "cp " + source + " " + bin + "/", false},
		{"install of a hook-named source into the bin folder", "install -m755 " + owned + " " + bin + "/", true},
		{"install onto the hook file", "install -m755 " + source + " " + hook, true},
		{"perl module option reads the hook", "perl -MFile::Spec -e 'print while <>' " + hook, false},
		{"perl include option reads the hook", "perl -Ilib/inc -ne 'print' " + hook, false},
		{"perl without in-place edit", "perl -ne 'print' " + hook, false},
		{"perl in place edit", "perl -pi -e 's/x/y/' " + hook, true},
		{"perl in place edit with suffix", "perl -pi.bak -e 's/x/y/' " + hook, true},
		{"perl in place option apart from the code option", "perl -i -pe 's/x/y/' " + hook, true},
		{"loop re-modes hooks", "for f in " + bin + "/defenseclaw-hook-*; do chmod 000 \"$f\"; done", true},
		{"one-item loop re-modes the hook", "for f in " + hook + "; do chmod 000 \"$f\"; done", true},
		{"loop overwrites hooks", "for f in " + bin + "/defenseclaw-hook-*; do echo x > \"$f\"; done", true},
		{"one-item loop overwrites the hook", "for f in " + hook + "; do echo x > \"$f\"; done", true},
		{"loop appends to hooks", "for f in " + bin + "/defenseclaw-hook-*; do echo x >> \"$f\"; done", true},
		{"loop truncates hooks", "for f in " + bin + "/defenseclaw-hook-*; do truncate -s 0 \"$f\"; done", true},
		{"loop edits hooks in place", "for f in " + bin + "/defenseclaw-hook-*; do sed -i s/a/b/ \"$f\"; done", true},
		{"loop copies over hooks", "for f in " + bin + "/defenseclaw-hook-*; do cp " + source + " \"$f\"; done", true},
		{"loop removes hooks", "for f in " + bin + "/defenseclaw-hook-*; do rm -f \"$f\"; done", true},
		{"loop re-modes other tools", "for f in " + bin + "/other-*; do chmod 755 \"$f\"; done", false},
		{"loop overwrites other tools", "for f in " + bin + "/other-*; do echo x > \"$f\"; done", false},
		{"loop reads hooks", "for f in " + bin + "/defenseclaw-hook-*; do cat \"$f\"; done", false},
		{"loop copies hooks away", "for f in " + bin + "/defenseclaw-hook-*; do cp \"$f\" " + root + "/backup; done", false},
	} {
		if got := RegistrationWriteReach(tc.command, root, home, names); got != tc.want {
			t.Errorf("%s: %q reached %v, want %v", tc.name, tc.command, got, tc.want)
		}
	}
}
