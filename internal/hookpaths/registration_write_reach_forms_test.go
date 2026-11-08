// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrationWriteReachSpellings pins that one registered file is reached
// by every spelling of its name that the literal removal is reached by, and
// that the ordinary neighbours of it are not.
func TestRegistrationWriteReachSpellings(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	plugins := filepath.Join(home, ".config", "opencode", "plugins")
	bin := filepath.Join(home, ".local", "bin")
	bridge := filepath.Join(plugins, "defenseclaw.js")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	for _, path := range []string{bridge, hook, filepath.Join(bin, "other-tool")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{bridge, plugins, hook, bin}
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"rm " + hook, true},
		{"rm " + filepath.Join(bin, "defenseclaw-hook-{user,post}"), true},
		{"mv " + hook + "{,.bak}", true},
		{"mv " + plugins + "{,.bak}", true},
		{"rm -rf " + bin, true},
		{"rm -rf " + plugins + "/*", true},
		{"for f in " + bin + "/defenseclaw-hook-*; do rm -f \"$f\"; done", true},
		{"for f in " + plugins + "/*; do mv \"$f\" /tmp/aside; done", true},
		{"find " + plugins + " -delete", true},
		{"find " + home + "/.config -name \"*.js\" -delete", true},
		{"find " + plugins + " -name \"*.js\" -exec rm {} +", true},
		{"rsync -a --delete " + root + "/empty/ " + plugins + "/", true},
		{"install -m755 /bin/true " + hook, true},
		{"install -t " + bin + " " + root + "/build/defenseclaw-hook-user", true},
		{"printf x | dd of=" + hook, true},
		{"install -m755 " + root + "/build/tool " + filepath.Join(bin, "other-tool"), false},
		{"dd if=/dev/zero of=" + root + "/scratch bs=1 count=1", false},
		{"rm " + filepath.Join(bin, "other-tool"), false},
		{"rm " + filepath.Join(bin, "other-{tool,thing}"), false},
		{"mv " + filepath.Join(bin, "other-tool") + "{,.bak}", false},
		{"for f in " + bin + "/other-*; do rm -f \"$f\"; done", false},
		{"find " + plugins + " -name \"*.tmp\" -delete", false},
		{"find " + plugins + " -name \"*.js\"", false},
		{"rsync -a " + root + "/src/ " + plugins + "/", false},
		{"rsync -a --delete " + root + "/src/ " + root + "/dist/", false},
	} {
		if got := RegistrationWriteReach(tc.command, root, home, names); got != tc.want {
			t.Errorf("%q: reached %v, want %v", tc.command, got, tc.want)
		}
	}
}
