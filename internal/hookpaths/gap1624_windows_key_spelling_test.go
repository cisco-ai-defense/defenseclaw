// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10 GAP-1624: on a Windows host the key path of a Windows home is
// spelled with backslashes. In a POSIX reading the one word resolver removes
// them as escapes; the plain value keeps the spelling, so the key named as
// data next to an unbound output keeps the persistence decision, as on
// rel/1.0.10. The fixture makes no link, so it runs for a standard user too
// (TestBalancedActionEffectRolesIndependent needs a symlink and skips there).
// On another host the key path has no backslash and the row holds as well.
func TestGAP1624WindowsKeySpellingKeepsTheMention(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(key, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		`echo marker >> "$out"; printf '%s' ` + key,
		`echo marker >> "$out"; printf '%s' "` + key + `"`,
	} {
		if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, actionfacts.DialectPOSIX, nil); got == "" {
			t.Errorf("%q: no protected-target decision", command)
		}
	}
}
