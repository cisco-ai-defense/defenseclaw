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
		{"parent-preserving copy keeps the source path under the bin folder", "cp --parents " + owned + " " + bin + "/", false},
		{"abbreviated parents option keeps the source path", "cp --par " + owned + " " + bin + "/", false},
		{"parent-preserving copy of a bare hook name lands on the hook", "cp --parents defenseclaw-hook-user " + bin + "/", true},
		{"copy of a hook-named source without the parents option lands on the hook", "cp " + owned + " " + bin + "/", true},
		{"loop parent-preserving copy keeps the source path", "for f in " + owned + "; do cp --parents \"$f\" " + bin + "/; done", false},
		{"loop parent-preserving copy of a bare hook name lands on the hook", "for f in defenseclaw-hook-user; do cp --parents \"$f\" " + bin + "/; done", true},
		{"abbreviated target folder with a parent-preserving copy of a bare hook name", "cp --parents --target-d=" + bin + " defenseclaw-hook-user", true},
		{"abbreviated target folder in the next word with a bare hook name", "cp --parents --target-d " + bin + " defenseclaw-hook-user", true},
		{"loop parent-preserving copy of a bare hook name into an abbreviated target folder", "for f in defenseclaw-hook-user; do cp --parents --target-d=" + bin + " \"$f\"; done", true},
		{"loop parent-preserving copy into an abbreviated target folder in the next word", "for f in defenseclaw-hook-user; do cp --parents --target-d " + bin + " \"$f\"; done", true},
		{"loop parent-preserving copy of a path into an abbreviated target folder", "for f in " + owned + "; do cp --parents --target-d=" + bin + " \"$f\"; done", false},
		{"loop copy of an ordinary source into an abbreviated target folder", "for f in " + source + "; do cp --target-d=" + bin + " \"$f\"; done", false},
		{"loop copy of a hook-named source into an abbreviated target folder", "for f in " + owned + "; do cp --target-d=" + bin + " \"$f\"; done", true},
		{"copy of a hook-named source into an abbreviated target folder", "cp --target-d=" + bin + " " + owned, true},
		{"copy of an ordinary source into an abbreviated target folder", "cp --target-d=" + bin + " " + source, false},
		{"copy of a hook-named source with a short cluster naming the target folder", "cp -rt " + bin + " " + owned, true},
		{"copy of an ordinary source with a short cluster naming the target folder", "cp -rt " + bin + " " + source, false},
		{"install of a hook-named source into an abbreviated target folder", "install --target-d=" + bin + " " + owned, true},
		{"install of an ordinary source into an abbreviated target folder", "install --target-d=" + bin + " " + source, false},
		{"install of a hook-named source with a short cluster naming the target folder", "install -m755 -Dt " + bin + " " + owned, true},
		{"install of an ordinary source with a short cluster naming the target folder", "install -m755 -Dt " + bin + " " + source, false},
		{"loop link of a hook-named source with a short cluster naming the target folder", "for f in " + owned + "; do ln -sft " + bin + " \"$f\"; done", true},
		{"loop link of an ordinary source with a short cluster naming the target folder", "for f in " + source + "; do ln -sft " + bin + " \"$f\"; done", false},
		{"link of a hook-named source into an abbreviated target folder", "ln -f --target-d=" + bin + " " + owned, true},
		{"link of a hook-named source into the full target folder option", "ln -f --target-directory=" + bin + " " + owned, true},
		{"link of a hook-named source with a short cluster naming the target folder", "ln -sft" + bin + " " + owned, true},
		{"link of a hook-named source with a short option naming the target folder", "ln -sf -t " + bin + " " + owned, true},
		{"link of a hook-named source into the bin folder", "ln -sf " + owned + " " + bin + "/", true},
		{"link of an ordinary source into an abbreviated target folder", "ln -f --target-d=" + bin + " " + source, false},
		{"link of an ordinary source with a short cluster naming the target folder", "ln -sft" + bin + " " + source, false},
		{"link of an ordinary source into the bin folder", "ln -sf " + source + " " + bin + "/", false},
		{"link over the hook file", "ln -sf " + source + " " + hook, true},
		{"operand after the end of options is not a long option", "cp -- --target-d=" + bin + " " + source, false},
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
		{"loop copies an ordinary source into the bin folder", "for f in " + source + "; do cp \"$f\" " + bin + "/; done", false},
		{"loop copies into the bin folder without a slash", "for f in " + source + "; do cp \"$f\" " + bin + "; done", false},
		{"loop installs an ordinary source into the bin folder", "for f in " + source + "; do install -m755 \"$f\" " + bin + "/; done", false},
		{"loop installs with a target folder", "for f in " + source + "; do install -m755 -t " + bin + " \"$f\"; done", false},
		{"loop links an ordinary source into the bin folder", "for f in " + source + "; do ln -sf \"$f\" " + bin + "/; done", false},
		{"loop installs a hook-named source into the bin folder", "for f in " + owned + "; do install -m755 \"$f\" " + bin + "/; done", true},
		{"loop copies a hook-named source into the bin folder", "for f in " + owned + "; do cp \"$f\" " + bin + "/; done", true},
		{"loop links over the hook file", "for f in " + source + "; do ln -sf \"$f\" " + hook + "; done", true},
		{"loop installs onto the hook file", "for f in " + source + "; do install -m755 \"$f\" " + hook + "; done", true},
		{"loop perl edits the hook in place", "for f in " + hook + "; do perl -pi -e s/x/y/ \"$f\"; done", true},
		{"loop perl edits the hook in place with a suffix", "for f in " + hook + "; do perl -pi.bak -e s/x/y/ \"$f\"; done", true},
		{"loop perl edits the hook in place apart from the code option", "for f in " + hook + "; do perl -i -pe s/x/y/ \"$f\"; done", true},
		{"loop perl with a module option reads the hook", "for f in " + hook + "; do perl -MFile::Spec -ne print \"$f\"; done", false},
		{"loop perl without in-place edit reads the hook", "for f in " + hook + "; do perl -ne print \"$f\"; done", false},
		{"loop sed prints the hook", "for f in " + hook + "; do sed -n 1p \"$f\"; done", false},
		{"loop perl edits another tool in place", "for f in " + bin + "/other-tool; do perl -pi -e s/x/y/ \"$f\"; done", false},
	} {
		if got := len(RegistrationWriteReached(tc.command, root, home, names)) > 0; got != tc.want {
			t.Errorf("%s: %q reached %v, want %v", tc.name, tc.command, got, tc.want)
		}
	}
	// ln SOURCE links the source under its own name in the working folder.
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"single-operand link of a hook-named source in the bin folder", "ln -f " + owned, true},
		{"single-operand link of an ordinary source in the bin folder", "ln -s " + source, false},
	} {
		if got := len(RegistrationWriteReached(tc.command, bin, home, names)) > 0; got != tc.want {
			t.Errorf("%s: %q reached %v, want %v", tc.name, tc.command, got, tc.want)
		}
	}
}
