// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// T5 integration (g-hooks-wp class rule, g-hooks-parse inert Python text):
// a write call spelled only in an inert Python string is no unproven write;
// the same text stays unproven when the string can run (a shadowing module
// beside it, or a PYTHONPATH the command sets), and a real write call with a
// computed argument stays unproven.
func TestUnprovenWriteIgnoresInertPythonText(t *testing.T) {
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	clean, shadow := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(shadow, "pathlib.py"), []byte("# local module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const home = "/home/alice"
	inert := `python3 -c 'p = Path.home() / ".ssh" / "authorized_keys"; print(f"p.write_text(42)")'`
	for _, tc := range []struct {
		name, command, cwd string
		unproven           bool
	}{
		{"inert f-string text", inert, clean, false},
		{"inert text beside a pathlib import", `python3 -c 'import pathlib; print("p.write_text(42)")'`, clean, false},
		{"pathlib import shadowed in cwd", `python3 -c 'import pathlib; print("p.write_text(42)")'`, shadow, true},
		{"PYTHONPATH set by the command", "PYTHONPATH=/tmp/mods " + inert, clean, true},
		{"real write with a computed argument", `python3 -c 'p = Path.home() / ".ssh" / "authorized_keys"; p.write_text(str(42))'`, clean, true},
	} {
		if got := hookpaths.UnprovenProtectedWrite(tc.command, tc.cwd, home) != ""; got != tc.unproven {
			t.Errorf("%s: unproven = %v, want %v", tc.name, got, tc.unproven)
		}
	}
}
