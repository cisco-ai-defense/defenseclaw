// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// In a folder this process cannot see (the working folder is not there for
// it), the one shell word resolver adds no glob uncertainty: the
// protected-target readers' name fallback decides the call, as on
// rel/1.0.10. A blind gateway (ProtectHome) keeps every such word uncertain,
// the client's evidence deciding it, and a folder the walk sees is read as
// before (rel-1-0-10:GAP-0378).
func TestGAP0378HiddenViewAddsNoGlobUncertainty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX glob walk")
	}
	home := t.TempDir()
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(home, "work", "not-here")
	seen := filepath.Join(home, "work", "here")
	if err := os.MkdirAll(seen, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		command, cwd string
		blind        bool
		uncertain    bool
	}{
		{"rm -f build/*.o", gone, false, false},
		{"chmod 644 */*.md", gone, false, false},
		{"GLOBIGNORE=.keep; rm -f build/*.o", gone, false, false},
		{"rm -f build/*.o", gone, true, true},
		{"GLOBIGNORE=.keep; rm -f build/*.o", gone, true, true},
		{"rm -f build/*.o", seen, false, false},
		{"GLOBIGNORE=.keep; rm -f build/*.o", seen, false, true},
	} {
		got := UncertainGlobWriteReason(row.command, row.cwd, home, nil, row.blind)
		if (got != "") != row.uncertain {
			t.Errorf("%q cwd=%s blind=%v: reason %q, uncertain wanted %v", row.command, filepath.Base(row.cwd), row.blind, got, row.uncertain)
		}
	}
}
