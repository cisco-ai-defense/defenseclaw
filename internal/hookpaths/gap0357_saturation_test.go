//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A later gateway layer may also identify these writes. Check the bounded
// value tracker itself so a client decision cannot conceal its regression.
func TestGAP0357SaturationInvalidation(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "names.txt"), []byte("keylink\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(cwd, "keylink")); err != nil {
		t.Fatal(err)
	}
	var capSteps strings.Builder
	for i := 1; i <= 5; i++ {
		fmt.Fprintf(&capSteps, "if [ -n \"$A%d\" ]; then a%d=1; fi; ", i, i)
	}
	capSteps.WriteString(strings.Repeat(":; ", 20))
	rows := []struct{ name, command string }{
		{"eval-dynamic", `g=keylink; f=a.txt; ` + capSteps.String() + `eval f=; echo m >> "$f"`},
		{"andand-after", `f=a.txt; ` + capSteps.String() + `[ -n "$X" ] && f=keylink; echo m >> "$f"`},
		{"group-redirect", `f=a.txt; ` + capSteps.String() + `{ f=keylink; echo m >> "$f"; }`},
		{"while-read", `f=a.txt; ` + capSteps.String() + `while read -r f; do break; done < names.txt; echo m >> "$f"`},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if !actionConcreteProtectedWrite(row.command, cwd, home) {
				t.Errorf("%s: bounded value tracker lost the protected write", row.name)
			}
		})
	}
}
