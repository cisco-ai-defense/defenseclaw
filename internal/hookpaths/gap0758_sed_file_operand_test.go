// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSedFileOperandIsReadNotScriptGAP0758: sed's w / e reading is of its
// script words only, so a read of the hook whose path has a segment that
// begins with w (a TMPDIR of /var/tmp/x/wr/tmp) stays a read, while a script
// w command, an -e script after the first and an option GNU sed does not
// have (every word may be the script) still reach it (rel-1-0-10:GAP-0758).
func TestSedFileOperandIsReadNotScriptGAP0758(t *testing.T) {
	root := filepath.Join(t.TempDir(), "wr", "tmp")
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"print", "sed -n 1p " + hook + "; echo done", false},
		{"print-expression", "sed -n -e 1p " + hook + "; echo done", false},
		{"print-long-options", "sed --quiet --expression=1p " + hook + "; echo done", false},
		{"print-separate", "sed -s -n 1p /dev/null " + hook + "; echo done", false},
		{"substitute-to-stdout", "sed s/a/b/ " + hook + "; echo done", false},
		{"script-writes", "sed -n 'w " + hook + "' /dev/null; echo done", true},
		{"second-expression-writes", "sed -e 1p -e 'w " + hook + "' /dev/null; echo done", true},
		{"unknown-option-writes", "sed -I '' 'w " + hook + "' /dev/null; echo done", true},
		{"in-place", "sed -i 1d " + hook + "; echo done", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := len(RegistrationWriteReached(row.command, root, home, []string{hook, bin})) > 0; got != row.want {
				t.Errorf("reached %t, want %t for %q", got, row.want, row.command)
			}
		})
	}
}
